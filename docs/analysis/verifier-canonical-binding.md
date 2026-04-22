# Canonical Binding Bypass — `ProofBundle::verify`

**Status**: Disclosure PoC
**Branch**: `analysis/verifier-canonical-binding` (on `saroupille/tzel` fork)
**PoC artifacts**:
- `verifier/tests/canonical_binding_bypass.rs` (bundle-level, 2 tests)
- `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs` (end-to-end, 1 test)

## TL;DR

`tzel_verifier::ProofBundle::verify()` pins no canonical `CircuitConfig`: every
field that tells the STARK verifier *which* circuit it is verifying —
`preprocessed_root`, `output_addresses`, `n_blake_gates`,
`preprocessed_column_ids`, and the entire FRI geometry — is rebuilt from
`verify_meta`, which is shipped wire-side with the bundle. An attacker with
access to the public `stwo-circuits` API can prove any custom circuit, package
the proof into a self-consistent bundle, and `bundle.verify()` returns `Ok`.
The rollup kernel's only follow-up check (`validate_stark_circuit`) compares
`output_preimage[2]` against the configured program hash — but
`output_preimage` is also attacker-controlled. End-to-end demo: the kernel
accepts a forged `Unshield`, credits an attacker-chosen recipient with
`fixture.shield.v = 400_000` mutez, and a follow-up `Withdraw` emits a Tezos
L1 outbox `burn` message. Full bridge drain. Verify locally with:

```
cargo +nightly-2025-07-14 test -p tzel-rollup-kernel \
    --test e2e_verifier_binding_bypass -- --nocapture
```

## The vulnerability

### 1. `ProofBundle::verify` takes no canonical-config argument

`verifier/src/bundle.rs:113`:

```rust
pub fn verify(&self) -> Result<()> {
    use circuit_air::verify::{verify_circuit, CircuitConfig, CircuitPublicData};

    let meta = self
        .verify_meta
        .as_ref()
        .ok_or_else(|| anyhow!("proof bundle missing verify_meta"))?;
    ...
```

The method consumes `&self` only. There is no `expected_circuit_config`,
`canonical_program_hash`, or any other caller-supplied pin. `meta` is the
bundle's own `VerifyMeta` (see `verifier/src/bundle.rs:53-80`), deserialized
verbatim from the wire.

### 2. Every circuit-identifying field is rebuilt from `verify_meta`

`verifier/src/bundle.rs:134-186`:

```rust
let proof_config = ProofConfig {
    n_proof_of_work_bits: meta.n_pow_bits,
    n_preprocessed_columns: meta.n_preprocessed_columns,
    n_trace_columns: meta.n_trace_columns,
    n_interaction_columns: meta.n_interaction_columns,
    trace_columns_per_component: meta.trace_columns_per_component.clone(),
    interaction_columns_per_component: meta.interaction_columns_per_component.clone(),
    cumulative_sum_columns: meta.cumulative_sum_columns.clone(),
    n_components: meta.n_components,
    fri: circuits_stark_verifier::fri_proof::FriConfig {
        log_trace_size: meta.fri_log_trace_size,
        log_blowup_factor: meta.fri_log_blowup as usize,
        n_queries: meta.fri_n_queries,
        log_n_last_layer_coefs: meta.fri_log_last_layer as usize,
        fold_step: meta.fri_fold_step as usize,
    },
    interaction_pow_bits: meta.interaction_pow_bits,
};
...
let circuit_config = CircuitConfig {
    config: stwo::core::pcs::PcsConfig { ... /* all from meta */ },
    output_addresses: meta.output_addresses.clone(),
    n_blake_gates: meta.n_blake_gates,
    preprocessed_column_ids: meta.preprocessed_column_ids...collect(),
    preprocessed_root: HashValue(qm31_from(&pr[0..4]), qm31_from(&pr[4..8])),
};
```

Nothing in `ProofBundle::verify` compares any of these values against a tzel
canonical constant. The only cross-check is that `meta.public_output_values`
hashes to `output_preimage` (lines 121-132), which is a self-consistency
check — the attacker controls both sides.

### 3. `DirectProofVerifier::validate` adds only a program-hash equality

`verifier/src/lib.rs:62-71`:

```rust
pub fn validate(&self, proof: &Proof, circuit: CircuitKind) -> Result<(), String> {
    check_proof_shape(proof, self.allow_trust_me_bro, self.verified_mode.is_some())?;
    match (&self.verified_mode, proof) {
        (Some(cfg), Proof::Stark { .. }) => {
            verify_stark_bundle(proof)?;
            validate_stark_circuit(proof, circuit, &cfg.program_hashes)
        }
        _ => Ok(()),
    }
}
```

`verify_stark_bundle` (same file, 142-163) reconstructs a `ProofBundle` and
calls `bundle.verify()` — the same attacker-controllable path described
above. `validate_stark_circuit` (lines 120-140) then calls
`validate_single_task_program_hash` with the configured
`ProgramHashes`. That function lives in `core/src/lib.rs:1276-1289`:

```rust
pub fn validate_single_task_program_hash<'a>(
    output_preimage: &'a [F],
    expected_program_hash: &F,
) -> Result<&'a [F], String> {
    let parsed = parse_single_task_output_preimage(output_preimage)?;
    if parsed.program_hash != expected_program_hash {
        return Err(format!(
            "unexpected circuit program hash: got {}, expected {}",
            hex::encode(parsed.program_hash),
            hex::encode(expected_program_hash),
        ));
    }
    Ok(parsed.public_outputs)
}
```

And `parse_single_task_output_preimage` (`core/src/lib.rs:1232-1272`) reads
the "program hash" from `output_preimage[2]`:

```rust
Ok(BootloaderTaskOutput {
    program_hash: &output_preimage[2],
    public_outputs: &output_preimage[3..],
})
```

This is the *declared* program hash sitting inside the preimage bytes —
not a value cryptographically bound to the circuit that produced the
bundle. An attacker who picks `output_preimage[2] =
<canonical_unshield_hash>` passes this check trivially.

### 4. `CircuitStatement::verify_preprocessed_root` is self-consistency, not pinning

`circuit_air::statement::CircuitStatement::verify_preprocessed_root`
(`circuit_air/src/statement.rs:126-137`):

```rust
fn verify_preprocessed_root(
    &self,
    context: &mut Context<Value>,
    preprocessed_root: HashValue<Var>,
) {
    let expected_preprocessed_root = HashValue(
        context.constant(self.preprocessed_root.0),
        context.constant(self.preprocessed_root.1),
    );
    eq_op(context, preprocessed_root.0, expected_preprocessed_root.0);
    eq_op(context, preprocessed_root.1, expected_preprocessed_root.1);
}
```

`self.preprocessed_root` is whatever was passed to
`CircuitStatement::new` by the caller — in our path, whatever the bundle's
`VerifyMeta` declared. The constraint says "the prover's declared root
matches the verifier's declared root", which is vacuous when both are
chosen by the attacker.

### 5. `verify_circuit` is shape-agnostic

`circuit_air::verify::verify_circuit` (`circuit_air/src/verify.rs:51-64`):

```rust
pub fn verify_circuit(
    circuit_config: CircuitConfig,
    proof: Proof<QM31>,
    public_data: CircuitPublicData,
) -> Result<Context<QM31>, String> {
    let context = build_verification_circuit(circuit_config, proof, public_data)?;
    #[cfg(test)]
    context.check_vars_used();

    if !context.is_circuit_valid() {
        return Err("Verification failed".to_string());
    }
    Ok(context)
}
```

This is a generic STARK verifier. It has no notion of "tzel's shield
circuit" vs "tzel's transfer circuit" vs "attacker's 2-output fibonacci
circuit": all three are just `CircuitConfig` inputs it accepts at face value.

## Why the privacy bootloader doesn't help

The canonical proving pipeline (`services/reprover::prove` in
`services/reprover/src/lib.rs:32-40`) wraps each Cairo program in tzel's
**privacy bootloader** (`get_privacy_bootloader_program`,
`services/reprover/src/lib.rs:21`). The bootloader commits to the program
hash cryptographically: the first task slot in its `output_preimage` is
the Cairo program hash of whatever executable was loaded. Under the
canonical pipeline, a Shield bundle really does prove "I ran the Shield
Cairo executable".

This is a property of the **proving path**, not the **verification path**.
`ProofBundle::verify()` never enforces "this bundle went through the
privacy bootloader at all". An attacker who bypasses `custom_recursive_prove`
(defined at `services/reprover/src/custom_circuit.rs:411`) and calls
`circuit_prover::prove_circuit_assignment` directly on a hand-crafted
`Context` never touches the bootloader. The resulting proof still
verifies under `verify_circuit` because `verify_circuit` doesn't care
about the bootloader — it only checks that the proof bytes are consistent
with the `CircuitConfig` + `CircuitPublicData` it was handed.

The PoC does exactly this. `build_attacker_context` (in
`verifier/tests/canonical_binding_bypass.rs:151-194`) builds a fibonacci-
style `Context` with two hand-placed output gates. The proof is produced
via `prove_circuit_assignment` (`verifier/tests/canonical_binding_bypass.rs:395-399`)
— the public stwo-circuits prover API, not `reprover::prove`. No
bootloader. `output_preimage[2]` is then chosen to be the *canonical*
unshield/transfer/shield program hash (`verifier/tests/canonical_binding_bypass.rs:266-267`
for the value copied from `testdata/verified_bridge_flow.json`), which
satisfies `validate_single_task_program_hash` downstream.

## Attack chain

1. **Attacker picks a target circuit kind** — `Unshield`, `Transfer`, or
   `Shield` — and copies the corresponding canonical program hash from
   the deployed verifier's configuration. These are public in
   `tezos/rollup-kernel/testdata/verified_bridge_flow.json` and whatever
   `ConfigureVerifier` message the operator has submitted on L1.

2. **Attacker constructs an attack payload** — for Unshield, a
   14-felt `output_preimage` shaped exactly as `apply_unshield`
   expects (`core/src/lib.rs:2016-2061`): `[n_tasks=1,
   task_output_size=13, program_hash, filler, auth_domain, root,
   nullifier, v_pub, fee, hash(recipient), cm_change=0,
   memo_hash_change=0, cm_fee, memo_hash_fee]`. See
   `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs:730-745`.

3. **Attacker chooses application-layer values freely**: the nullifier
   is a fresh felt nobody has ever spent (so the freshness check at
   `core/src/lib.rs:1996-2000` passes); the root is any historical root
   already in `valid_roots` (observable from the rollup's durable
   storage RPC); `v_pub` is the amount to mint out of thin air
   (`apply_unshield` never cross-checks `v_pub` against any deposit
   balance or note value); `recipient` is any string (the kernel indexes
   balances by string, see `core/src/lib.rs:1713` `apply_shield` for the
   symmetric pattern).

4. **Attacker computes the Blake2 hash** `H = Blake2Felt252(preimage)`
   through the bundle's own recipe (`verifier/src/bundle.rs:41-51`).
   The output is 8 M31 words, i.e. 2 `QM31`s; these are the exact
   target values the attacker's circuit must emit.

5. **Attacker builds a custom circuit** whose first two `output` gates
   emit exactly those two `QM31`s. A 1030-round Fibonacci-shape chain
   with `(x - x) + target` folding suffices (see
   `verifier/tests/canonical_binding_bypass.rs:151-194` for the exact
   construction, including why the `(x - x)` trick is needed to keep
   the stwo-circuits logup-sum balanced).

6. **Attacker proves the circuit** with `prove_circuit_assignment`
   (public API in `circuit-prover`, pulled in as a dev-dep but
   equivalently usable by any consumer). The resulting
   `stark_proof.proof.commitments[0]` is the attacker's preprocessed
   Merkle root. Snapshot it.

7. **Attacker packages the bundle** with a `VerifyMeta` materialized
   entirely from the attacker's own `ProofConfig` + `CircuitConfig` —
   same `preprocessed_root`, same `output_addresses`, same FRI
   parameters (see `verifier/tests/canonical_binding_bypass.rs:210-259`).
   Everything is internally self-consistent.

8. **Attacker submits the bundle through the normal inbox path**.
   `KernelInboxMessage::Unshield` is encoded via
   `encode_kernel_inbox_message` and wrapped in an
   `ExternalMessageFrame::Targetted` for the rollup's
   `SmartRollupAddress` (see
   `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs:225-239`).
   Anyone who can pay for a Tezos `Smart_rollup_add_messages` operation
   can do this — no operator bearer token required.

9. **The kernel runs `validate_transition_proof`** (`tezos/rollup-kernel/src/lib.rs:1000`),
   which goes through `DirectProofVerifier::validate_kernel` →
   `verify_stark_bundle` (`bundle.verify()` returns `Ok`) →
   `validate_stark_circuit` (passes because `output_preimage[2]` equals
   the canonical unshield hash). Then it runs
   `apply_unshield` (`core/src/lib.rs:1965`), which cross-checks the
   preimage tail against the request fields (`core/src/lib.rs:2016-2061`) —
   but since the attacker built the preimage *from* the request fields,
   every check passes.

10. **The kernel credits `attacker_recipient` with `drained_amount`
    mutez** and appends the producer-fee note to the tree. A follow-up
    `KernelInboxMessage::Withdraw` (already a known auth gap — see the
    prior disclosure) drains those mutez through the Tezos outbox as a
    standard ticket-burn message. L1 funds are now exiting the bridge.

**Footnote on the felt byte trick.** The Stark field is ~2^252 and felts
are 32 bytes, so a byte-vector with all 32 bytes set can land outside
the field. Keeping `output_preimage[31] == 0x00` (top byte zero) makes
the felt fit and survives the round-trip through `Felt::from_bytes_le`
/ `to_bytes_le` that the kernel uses to reconstruct the preimage. The
PoC builds its fresh `nullifier` and `cm_fee` via
`(i, byte) in n.iter_mut().enumerate().take(31)` — the `.take(31)`
leaves byte [31] at zero (see
`tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs:824-837`).

## Impact

- **What the attacker gains**: any amount of rollup-side balance
  they choose. Once that balance is public, the existing `Withdraw`
  path (or a chained `Transfer`) moves it to a Tezos L1 address
  they control. The e2e test concretely drains
  `fixture.shield.v = 400_000` mutez through the real outbox.
  Nothing in `apply_unshield` binds `v_pub` to any specific deposit
  or note commitment — the only guard is that the nullifier be
  fresh, which it is by construction.

- **Prerequisites for the attacker**: ability to pay for a Tezos
  `Smart_rollup_add_messages` operation targeted at the rollup's
  address. That is every L1 account holder. No bearer token, no
  operator cooperation, no off-chain coordination required. The
  kernel reads messages from the inbox directly
  (`tezos/rollup-kernel/src/lib.rs`, inbox path).

- **Relationship to commit `8983481` (`Bind shield deposits to
  secret-derived keys`)**: that commit ties `Shield` deposit balances
  to secret-derived keys, so a third party can no longer shield
  someone else's deposit by knowing only the deposit ID. This
  closes one authentication gap at the `apply_shield` layer. It does
  **not** close the bypass documented here: the attacker in this
  disclosure does not need to touch any deposit balance at all. They
  mint `v_pub` directly via a forged Unshield, because the proof
  acceptance predicate is broken upstream of `apply_shield`'s new
  secret-binding. Independently: if the canonical-binding gap is
  closed, the secret-binding remains useful as defense in depth.

- **Surface across circuit kinds**: the primitive (prove a custom
  circuit that emits the preimage-hash QM31s) is circuit-agnostic.
  The e2e demo chose Unshield because it leads most directly to
  L1-observable funds movement. A symmetric forgery works for Shield
  (mint a commitment tied to any receiver, bypassing the new
  secret-binding because the verifier accepts the forged proof
  before `apply_shield` runs) and Transfer (spend any historical
  commitment). The same `VerifyMeta` / preimage-shape trick applies;
  only the preimage layout changes per
  `apply_shield`/`apply_transfer`/`apply_unshield`.

- **Bridge-drain upper bound**: the rollup can only pay out what is
  held in the ticketer's balance on L1 (the `burn` entrypoint rejects
  over-balance withdrawals at the Michelson layer). So the attacker's
  ceiling is "whatever the bridge holds at the moment of exit". With
  a live rollup, that is every user's deposited mutez.

## Reproduction

### Prerequisites

Same toolchain the canonical tzel test suite uses — `nightly-2025-07-14`
is required because `circuit-prover` pulls unstable features:

```bash
rustup toolchain install nightly-2025-07-14
rustup component add rust-src --toolchain nightly-2025-07-14
```

### Bundle-level PoC (2 tests, no kernel)

```bash
git checkout analysis/verifier-canonical-binding

cargo +nightly-2025-07-14 test -p tzel-verifier \
    --test canonical_binding_bypass --release -- --nocapture
```

Expected output (trimmed):

```
running 2 tests
[PoC] preimage_hash_target_qm31s = [ ... ]
[PoC] circuit: trace_log_size=..., n_blake_gates=..., ...
[PoC] bundle.verify() -> Ok — canonical-binding bypass demonstrated
test proof_bundle_verify_accepts_bundle_from_attacker_pipeline ... ok

[PoC] bundle.verify() -> Ok — canonical-binding bypass demonstrated
test proof_bundle_verify_accepts_transfer_shaped_bundle ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The first test demonstrates a shape-agnostic bypass with a random
13-felt preimage. The second uses a transfer-shaped preimage carrying
the canonical transfer program hash from `verified_bridge_flow.json`.

### End-to-end kernel PoC (1 test, full inbox → outbox)

Debug mode (matches CI invocation for `bridge_flow`; the kernel's
admin-key helpers fall back to dev keys under `cfg(debug_assertions)`):

```bash
cargo +nightly-2025-07-14 test -p tzel-rollup-kernel \
    --test e2e_verifier_binding_bypass -- --nocapture
```

Release mode (faster; needs the dev admin-key env vars spelled out
because `cfg(debug_assertions)` is off):

```bash
TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX=ce29748d82bfaea9bc847a797798a7216c07548cc5b3cdb9d7a321250e6ae905 \
TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX=df8140bb21671e80e79edda81bb4094a849213cac0094ac2614eaf29d6bed005 \
TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX=42d92056ee6ca0b3ee4ffc522657b9981244545de8f6879b7f08a5f7ee41ef02 \
  cargo +nightly-2025-07-14 test -p tzel-rollup-kernel \
    --test e2e_verifier_binding_bypass --release -- --nocapture
```

(The env-var values are the outputs of `dev_config_admin_ask()` =
`hash(b"tzel-dev-rollup-config-admin")` and its derived admin leaves.)

Expected output (trimmed):

```
running 1 test
[E2E PoC] kernel accepted forged Unshield: Unshield(...)
[E2E PoC] kernel issued L1 withdrawal #0 for the forged funds
[E2E PoC] full impact chain complete: forged Unshield → credited balance → L1 withdrawal via outbox.
  drained_amount = 400000 (attacker-chosen — apply_unshield does not bind v_pub to any deposit/note)
  attacker_recipient = "attacker-drain-account"
  attacker_nullifier = 0xa0a1...
  l1_withdrawal_recipient = tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
  outbox message emitted = true
test kernel_accepts_forged_unshield_and_applies_state_mutations ... ok
```

### Non-regression

```bash
cargo +nightly-2025-07-14 test -p tzel-rollup-kernel --test bridge_flow
```

All 12 existing `bridge_flow` tests continue to pass on this branch.

## Proposed mitigations

The fix surface is `ProofBundle::verify` (and whatever calls it). Four
options, in rough order of increasing invasiveness:

### Option 1 — `ProofBundle::verify` accepts a pinned `CircuitConfig`

Smallest API change:

```rust
impl ProofBundle {
    pub fn verify(&self, expected: &CircuitConfig) -> Result<()> {
        // ... existing self-consistency checks ...
        let derived = /* reconstruct CircuitConfig from verify_meta */;
        if derived != *expected { return Err(anyhow!("non-canonical circuit config")); }
        // ... call verify_circuit with `expected` ...
    }
}
```

Callers (`DirectProofVerifier::validate`, any offline verification
tools) must supply the canonical config for the circuit they expect.
The rollup kernel holds exactly one canonical config per circuit kind
— currently baked into the compiled executables' preprocessed roots —
so this is a natural fit.

**Pros**: surgical, preserves the `VerifyMeta` wire format, easy to
review. **Cons**: callers still must know the canonical config; if
any call site forgets to pin, the gap reopens.

### Option 2 — Drop circuit-describing fields from `VerifyMeta`

Remove from `VerifyMeta` every field that the canonical
`CircuitConfig` already determines: `output_addresses`,
`n_blake_gates`, `preprocessed_column_ids`, `preprocessed_root`,
and the FRI geometry. Keep only what actually varies per-proof
(`public_output_values` and the subset of `ProofConfig` that is
proof-specific rather than circuit-specific). `ProofBundle::verify`
then *constructs* `CircuitConfig` from its pinned canonical source
(e.g. a precomputed `OnceLock<CircuitConfig>` per `CircuitKind`) and
rejects any proof whose shape doesn't match.

**Pros**: removes the ability to ship attacker-chosen circuit params
at all. Makes the invariant "every bundle is verified against the
canonical circuit" structural rather than checked. **Cons**: bigger
code change; affects the wire format of `VerifyMeta`; requires the
verifier to be aware of all three `CircuitKind`s at build time
(already true in `verified` mode via `ProgramHashes`).

### Option 3 — Rollup kernel pins a `CircuitConfig` per circuit kind

Same spirit as Option 1, but the pin lives at the call site:
`validate_transition_proof` (`tezos/rollup-kernel/src/lib.rs:1267-1287`)
passes a canonical `CircuitConfig` alongside the existing
`program_hash`. `DirectProofVerifier::validate_kernel` gains a
`&CircuitConfig` argument. Canonical configs are loaded from
`ConfigureVerifier` — extended to carry the full
`CircuitConfig`, not just `verified_program_hashes`.

**Pros**: keeps `verifier` as a pure STARK library; makes the rollup
kernel the sole trust anchor for what "canonical" means. **Cons**:
`ConfigureVerifier` grows by ~kilobytes (the `preprocessed_column_ids`
alone are dozens of strings); config-admin signatures need to cover
the new bytes; backward-incompat for deployed verifiers.

### Option 4 — Defense in depth: operator-signed manifest

Complement Option 2 or 3 with an operator-signed manifest of
canonical circuit configs (analogous to
`KernelSignedVerifierConfig`), distributed out-of-band and pinned in
the operator's repo. `ConfigureVerifier` messages would carry the
full `CircuitConfig` (not just program hashes), signed by the
config admin WOTS key. This adds no new cryptographic primitive
over what already exists for `ConfigureVerifier`; it just widens the
payload.

**Pros**: matches the existing trust architecture (WOTS-signed
admin messages), gives a single on-chain source of truth,
auditable. **Cons**: does not by itself close the gap —
`ProofBundle::verify` still needs to *consume* the canonical
config; without Option 1/2/3 as the enforcement layer, a signed
manifest is merely a policy document.

### Preference

**The reviewer's preference is Option 2**, because it converts
"verifier must be called correctly" (a contract the caller can
forget) into "verifier is structurally unable to accept a
non-canonical bundle" (an invariant the compiler enforces). Option 1
is a reasonable backstop if the `VerifyMeta` wire-format change is
too invasive for the current release window. Options 3 and 4 are
orthogonal (per-kernel pinning, operator-signed manifest) and can
layer on top of either 1 or 2 as defense in depth.

## Scope of this disclosure

- **What is tested**: the bundle-level bypass (2 tests) and an
  end-to-end Unshield forgery that drains funds through the real
  outbox path (1 test). The bundle-level tests include a
  shape-agnostic case (arbitrary preimage) and a transfer-shaped
  case (preimage carries the canonical transfer program hash from
  `verified_bridge_flow.json`).
- **What is not tested**: Shield and Transfer forgeries. Both are
  functionally equivalent to Unshield under this primitive — the
  same `VerifyMeta` reconstruction accepts any `CircuitConfig`,
  and the downstream `apply_shield` / `apply_transfer` tail checks
  are satisfied by construction once the preimage is laid out to
  match their respective tail layouts (`core/src/lib.rs:1713` for
  Shield, `core/src/lib.rs:1854` for Transfer). We omit them
  because adding them does not add evidence; one broken acceptance
  predicate is a single bug.
- **What is not modified**: no tzel production code was touched on
  this branch. Only test files were added
  (`verifier/tests/canonical_binding_bypass.rs`,
  `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs`) and
  two dev-dependencies were added to `verifier/Cargo.toml` (both
  already in the tzel dependency graph as regular deps).
- **Non-regression**: all 12 existing `bridge_flow.rs` tests still
  pass. The disclosure artifact does not perturb the verified
  bridge path.

## Related prior disclosures

- `docs/analysis/withdraw-auth-gap.md` (same repo, prior branch).
  That disclosure documented the absence of sender authentication
  on `KernelInboxMessage::Withdraw` — a structurally similar
  "kernel trusts a wire field without cryptographic binding" issue,
  but at the *application* layer (Withdraw takes no signature and
  the kernel doesn't bind `sender` to any L1 identity).
- This disclosure is the same *shape* of issue one layer down: the
  kernel trusts `ProofBundle`'s wire-provided `VerifyMeta` without
  binding it to any canonical circuit configuration. Together, the
  two findings suggest the tzel verification chain has recurrent
  canonical-trust gaps that would benefit from an audit pass
  checking "which wire field is taken at face value that should
  instead be pinned to an on-chain or build-time constant".

## Appendix A — Code citations

| File:line | What it proves |
| --- | --- |
| `verifier/src/bundle.rs:113` | `verify(&self)` signature — no `expected_circuit_config` argument |
| `verifier/src/bundle.rs:134-186` | `CircuitConfig` + `ProofConfig` fully rebuilt from `verify_meta` |
| `verifier/src/bundle.rs:53-80` | `VerifyMeta` struct shape — all attacker-controllable fields |
| `verifier/src/bundle.rs:121-132` | Only non-meta check is `output_preimage` hashes to `public_output_values` (self-consistency) |
| `verifier/src/lib.rs:62-71` | `DirectProofVerifier::validate` = `verify_stark_bundle` + `validate_stark_circuit` |
| `verifier/src/lib.rs:120-140` | `validate_stark_circuit` compares `output_preimage[2]` to configured `program_hash` |
| `verifier/src/lib.rs:142-163` | `verify_stark_bundle` reconstructs a `ProofBundle` and calls `bundle.verify()` |
| `core/src/lib.rs:1232-1272` | `parse_single_task_output_preimage` reads `program_hash` from `output_preimage[2]` |
| `core/src/lib.rs:1276-1289` | `validate_single_task_program_hash` compares the parsed hash to the expected one |
| `core/src/lib.rs:1965-2062` | `apply_unshield` tail-parse check — every field cross-referenced against `req.*`, not any canonical constant |
| `core/src/lib.rs:1854` | `apply_transfer` entry (same pattern, different tail layout) |
| `core/src/lib.rs:1713` | `apply_shield` entry (same pattern, different tail layout) |
| `tezos/rollup-kernel/src/lib.rs:999-1003` | Kernel entry for Unshield → `validate_transition_proof` → `apply_unshield` |
| `tezos/rollup-kernel/src/lib.rs:1267-1287` | `validate_transition_proof` calls `DirectProofVerifier::validate_kernel` with no canonical-config pin |
| `circuit_air/src/verify.rs:51-64` | `verify_circuit` is generic — no tzel-specific invariant |
| `circuit_air/src/statement.rs:126-137` | `verify_preprocessed_root` is self-consistency (compares in-context constants from the same caller) |
| `services/reprover/src/lib.rs:21` | Canonical prover uses `get_privacy_bootloader_program` — attacker's path does not go through this |
| `services/reprover/src/custom_circuit.rs:411` | `custom_recursive_prove` is the canonical entry point; attacker replaces it with `prove_circuit_assignment` |
| `verifier/tests/canonical_binding_bypass.rs:151-194` | Attacker circuit construction (fibonacci chain + target fold) |
| `verifier/tests/canonical_binding_bypass.rs:335-497` | Full bundle-bypass PoC driver |
| `verifier/tests/canonical_binding_bypass.rs:526-551` | Transfer-shaped preimage test using canonical program hash |
| `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs:721-771` | Forged-Unshield request builder |
| `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs:777-968` | End-to-end kernel impact (forged Unshield + follow-up Withdraw + outbox assertions) |
| `tezos/rollup-kernel/testdata/verified_bridge_flow.json` | Source of the canonical program hashes and `auth_domain` used by the PoC |

## Appendix B — For AI agents

Machine-parseable claims. Each is a single self-contained statement
with a file:line verification anchor and the observation an agent
should make when reading those lines.

- **Claim**: `ProofBundle::verify` takes no canonical-config argument.
  - Verify at: `verifier/src/bundle.rs:113`
  - What to see: method signature is `pub fn verify(&self) -> Result<()>`; no `expected_*` parameter.

- **Claim**: Every `CircuitConfig` field is reconstructed from `verify_meta` (attacker-controlled).
  - Verify at: `verifier/src/bundle.rs:162-186`
  - What to see: `CircuitConfig { output_addresses: meta.output_addresses.clone(), n_blake_gates: meta.n_blake_gates, preprocessed_column_ids: meta..., preprocessed_root: HashValue(qm31_from(&pr[0..4]), qm31_from(&pr[4..8])) }` — every field sources from `meta`.

- **Claim**: Every `ProofConfig` field (including full FRI geometry) is reconstructed from `verify_meta`.
  - Verify at: `verifier/src/bundle.rs:134-151`
  - What to see: `ProofConfig { n_proof_of_work_bits: meta.n_pow_bits, ..., fri: FriConfig { log_trace_size: meta.fri_log_trace_size, ... } }`.

- **Claim**: `VerifyMeta` is wire-deserializable (i.e. ships alongside the proof bytes on the inbox).
  - Verify at: `verifier/src/bundle.rs:53-80` and `core/src/lib.rs:1207-1222`
  - What to see: `#[derive(..., serde::Deserialize)] pub struct VerifyMeta { ... }` and `Proof::Stark { ..., verify_meta: Option<Vec<u8>> }`.

- **Claim**: The only cross-check in `verify()` is output-preimage-to-public-output hash consistency, not circuit identity.
  - Verify at: `verifier/src/bundle.rs:121-132`
  - What to see: a single `if meta.public_output_values[..n] != expected_output_hash_values { Err(...) }`, nothing else.

- **Claim**: `validate_stark_circuit` only compares `output_preimage[2]` to the expected program hash — but `output_preimage` is also attacker-supplied.
  - Verify at: `verifier/src/lib.rs:120-140` and `core/src/lib.rs:1268-1270`
  - What to see: `validate_single_task_program_hash(output_preimage, expected)` where `parse_single_task_output_preimage` reads `program_hash: &output_preimage[2]`.

- **Claim**: `CircuitStatement::verify_preprocessed_root` is a self-consistency check, not a pin.
  - Verify at: `circuit_air/src/statement.rs:126-137`
  - What to see: `expected_preprocessed_root` is built from `self.preprocessed_root` (passed in by caller), then `eq_op` checks that the proof's declared root equals it.

- **Claim**: `verify_circuit` is a generic STARK verifier with no tzel-specific knowledge.
  - Verify at: `circuit_air/src/verify.rs:51-64`
  - What to see: no references to `ShieldCircuit`, `TransferCircuit`, tzel program hashes, or any canonical constant; only a generic `CircuitConfig`.

- **Claim**: Canonical prover path goes through the privacy bootloader; attacker path does not.
  - Verify at: `services/reprover/src/lib.rs:21-40` (canonical) vs `verifier/tests/canonical_binding_bypass.rs:395-399` (attacker)
  - What to see: canonical uses `get_privacy_bootloader_program` and `run_privacy_bootloader`; attacker uses `prove_circuit_assignment` on a hand-built `Context`.

- **Claim**: Kernel `validate_transition_proof` calls `DirectProofVerifier::validate_kernel` with no canonical-config argument.
  - Verify at: `tezos/rollup-kernel/src/lib.rs:1267-1287`
  - What to see: signature `fn validate_transition_proof<H: Host>(host: &H, proof: &KernelStarkProof, circuit: CircuitKind) -> Result<(), String>` — no `CircuitConfig`.

- **Claim**: `apply_unshield`'s tail-parse compares the preimage to `req.*` fields, not to any canonical source.
  - Verify at: `core/src/lib.rs:2016-2061`
  - What to see: every `if tail[i] != <derived from req>` — all checks reference the `UnshieldReq` the attacker constructed.

- **Claim**: The e2e PoC produces a Tezos L1 outbox `burn` message for the forged funds.
  - Verify at: `tezos/rollup-kernel/tests/e2e_verifier_binding_bypass.rs:901-968`
  - What to see: follow-up `KernelInboxMessage::Withdraw` → `KernelResult::Withdraw`, `host.outputs.len() == outbox_before + 1`, `final_ledger.withdrawals[0].amount == drained_amount`.
