//! wrapping of mpt-circuit

use crate::chips::execution_chip_v2::lookup_table::poseidon_table::PoseidonTable;
use crate::chips::execution_chip_v2::utils::to_field::ToField;
use crate::utils::challenges::Challenges;
use crate::{CircuitConfigV2, SubCircuit, SubCircuitConfig};
use aptos_move_witnesses::exec_state::ExecutionState;
use aptos_move_witnesses::static_info::{EntryInfo, Footprints, StaticInfo};

use aptos_move_witnesses::witness_preprocessor::WitnessPreProcessor;
use field_exts::U256;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error},
};
use itertools::Itertools;
use move_package::compilation::compiled_package::CompiledPackage;
pub use poseidon_circuit::hash::Hashable;
use poseidon_circuit::hash::{PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};
use std::cmp::max;
use types::Field;

/// re-wrapping for mpt circuit
#[derive(Default, Clone, Debug)]
pub struct PoseidonCircuit<F: Field>(pub(crate) PoseidonHashTable<F>, usize);

/// Circuit configuration argument ts
pub struct PoseidonCircuitConfigArgs {
    /// PoseidonTable
    pub poseidon_table: PoseidonTable,
}

/// re-wrapping for poseidon config
#[derive(Debug, Clone)]
pub struct PoseidonCircuitConfig<F: Field>(pub(crate) PoseidonHashConfig<F>);

const HASH_BYTES_IN_FIELD: usize = 16;
/// How many bytes a poseidon round can consume.
pub const HASH_STEP_SIZE: usize = HASH_BYTES_IN_FIELD * PoseidonTable::INPUT_WIDTH;

impl<F: Field + Hashable> SubCircuitConfig<F> for PoseidonCircuitConfig<F> {
    type ConfigArgs = PoseidonCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { poseidon_table }: Self::ConfigArgs,
    ) -> Self {
        let poseidon_table = (
            poseidon_table.q_enable,
            [
                poseidon_table.hash_id,
                poseidon_table.input0,
                poseidon_table.input1,
                poseidon_table.control,
                poseidon_table.domain_spec,
                poseidon_table.heading_mark,
            ],
        );
        let conf = PoseidonHashConfig::configure_sub(meta, poseidon_table, HASH_STEP_SIZE);
        Self(conf)
    }
}

impl<F: Field + Hashable> SubCircuit<F> for PoseidonCircuit<F> {
    type Config = PoseidonCircuitConfig<F>;

    fn new(
        package: &CompiledPackage,
        traces: &Footprints,
        pubs_indices: &[usize],
        config: CircuitConfigV2,
    ) -> Self {
        let entry = traces.entry().expect("entry should be set in traces");
        let static_info = StaticInfo::generate(entry, package, pubs_indices)
            .expect("static info should be generated");
        let preprocessor = WitnessPreProcessor::default();
        let states = preprocessor.pre_process(&traces.0, &static_info);

        let max_hashes = config.max_poseidon_rows / F::hash_block_size();
        let mut poseidon_table_data: PoseidonHashTable<F> = PoseidonHashTable::default();
        let poseidon_hash_data = states
            .iter()
            .flat_map(|opcode| {
                opcode
                    .step_states
                    .iter()
                    .filter(|s| s.step_state.exec_state == ExecutionState::NativePoseidonHash)
                    .map(|v| {
                        let rhs: F = v
                            .memory_ops
                            .first()
                            .as_ref()
                            .unwrap()
                            .0
                            .as_ref()
                            .unwrap()
                            .value
                            .to_field();
                        let lhs: F = v
                            .memory_ops
                            .get(1)
                            .and_then(|op| op.0.as_ref())
                            .unwrap()
                            .value
                            .to_field();
                        let inputs = [lhs, rhs];
                        let domain_spec = F::from(1u64);
                        let checks = Hashable::hash_with_domain([lhs, rhs], domain_spec);

                        (inputs, domain_spec, Some(checks))
                    })
            })
            .collect::<Vec<_>>();

        poseidon_table_data.fixed_inputs(poseidon_hash_data.iter());
        Self(poseidon_table_data, max_hashes)
    }
    fn new_with_empty_state(
        package: &CompiledPackage,
        entry: EntryInfo,
        pubs_indices: &[usize],
        circuit_config: CircuitConfigV2,
    ) -> Self {
        let max_hashes = circuit_config.max_poseidon_rows / F::hash_block_size();
        let poseidon_table_data: PoseidonHashTable<F> = PoseidonHashTable::default();
        Self(poseidon_table_data, max_hashes)
    }
    //
    // fn new_from_block(block: &witness::Block) -> Self {
    //     let max_hashes = block.circuits_params.max_poseidon_rows / F::hash_block_size();
    //     #[allow(unused_mut)]
    //     let mut poseidon_table_data: PoseidonHashTable<F> = PoseidonHashTable::default();
    //     // without any feature we just synthesis an empty poseidon circuit
    //     #[cfg(feature = "zktrie")]
    //     {
    //         let mpt_hashes = get_storage_poseidon_witness(block);
    //         if mpt_hashes.len() > max_hashes {
    //             log::error!(
    //                 "poseidon max_hashes: {:?} not enough. {:?} needed by zktrie proof",
    //                 max_hashes,
    //                 mpt_hashes.len()
    //             );
    //         }
    //         poseidon_table_data.fixed_inputs(&mpt_hashes);
    //     }
    //     #[cfg(feature = "poseidon-codehash")]
    //     {
    //         use crate::bytecode_circuit::bytecode_unroller::unroll_to_hash_input_default;
    //         for bytecode in block.bytecodes.values() {
    //             // must skip empty bytecode
    //             if !bytecode.bytes.is_empty() {
    //                 let unrolled_inputs =
    //                     unroll_to_hash_input_default::<F>(bytecode.bytes.iter().copied());
    //                 poseidon_table_data.stream_inputs(
    //                     &unrolled_inputs,
    //                     bytecode.bytes.len() as u64,
    //                     HASH_BLOCK_STEP_SIZE,
    //                 );
    //             }
    //         }
    //     }
    //
    //     Self(poseidon_table_data, max_hashes)
    // }
    //
    // fn min_num_rows_block(block: &witness::Block) -> (usize, usize) {
    //     let mut path_hash_counter: std::collections::HashMap<[u8; 32], usize> = Default::default();
    //     let mut account_counter: std::collections::HashMap<[u8; 32], usize> = Default::default();
    //     let mut storage_counter: std::collections::HashMap<[u8; 32], usize> = Default::default();
    //     let mut key_counter: std::collections::HashMap<[u8; 32], usize> = Default::default();
    //     let insert = |map: &mut std::collections::HashMap<[u8; 32], usize>, k| {
    //         *map.entry(k).or_insert(0) += 1;
    //     };
    //     for smt_trace in &block.mpt_updates.smt_traces {
    //         // for a smt trace there are multiple sources for hashes:
    //         // + account path, each layer (include the root) cost 1 hashes
    //         insert(&mut path_hash_counter, smt_trace.account_path[0].root.0);
    //         for node in &smt_trace.account_path[0].path {
    //             insert(&mut path_hash_counter, node.value.0);
    //         }
    //         for node in &smt_trace.account_path[1].path {
    //             insert(&mut path_hash_counter, node.value.0);
    //         }
    //
    //         // + the hashes required for leaf is dynamic and depended
    //         // on the type of mpt updates, here we suppose to count
    //         // all of the 4 hashes once
    //         if let Some(node) = smt_trace.account_path[0].leaf {
    //             insert(&mut account_counter, node.value.0);
    //         }
    //         if let Some(node) = smt_trace.account_path[1].leaf {
    //             insert(&mut account_counter, node.value.0);
    //         }
    //
    //         // + and the address key
    //         insert(&mut key_counter, smt_trace.account_key.0);
    //
    //         // + state path, like account path
    //         if let Some(path) = &smt_trace.state_path[0] {
    //             for node in &path.path {
    //                 insert(&mut path_hash_counter, node.value.0);
    //             }
    //         }
    //
    //         if let Some(path) = &smt_trace.state_path[1] {
    //             for node in &path.path {
    //                 insert(&mut path_hash_counter, node.value.0);
    //             }
    //         }
    //
    //         // + state leaf
    //         if let Some(node) = smt_trace.state_path[0].as_ref().and_then(|pt| pt.leaf) {
    //             insert(&mut storage_counter, node.value.0);
    //         }
    //         if let Some(node) = smt_trace.state_path[1].as_ref().and_then(|pt| pt.leaf) {
    //             insert(&mut storage_counter, node.value.0);
    //         }
    //
    //         // + the storage key
    //         if let Some(hash) = smt_trace.state_key {
    //             insert(&mut key_counter, hash.0);
    //         }
    //     }
    //     let sum_count = |h: &std::collections::HashMap<[u8; 32], usize>| h.values().sum::<usize>();
    //     let prev_dedup_size = sum_count(&path_hash_counter)
    //         + sum_count(&key_counter)
    //         + sum_count(&account_counter) * 4
    //         + sum_count(&storage_counter);
    //     let after_dedup_size = path_hash_counter.len()
    //         + key_counter.len()
    //         + account_counter.len() * 4
    //         + storage_counter.len();
    //     log::debug!("poseidon circuit row num: dedup mpt from {prev_dedup_size} to {after_dedup_size}, mpt update len {}, smt trace len {}",
    //     block.mpt_updates.len(), block.mpt_updates.smt_traces.len());
    //     let mpt_row_num = after_dedup_size * F::hash_block_size();
    //     let byte_row_num = block
    //         .bytecodes
    //         .values()
    //         .map(|bytecode| bytecode.bytes.len() / HASH_BLOCK_STEP_SIZE + 1)
    //         .sum::<usize>()
    //         * F::hash_block_size();
    //     let total_row_num = mpt_row_num + byte_row_num;
    //     log::debug!("poseidon circuit row num: {mpt_row_num}(mpt) + {byte_row_num}(bytecode) = {total_row_num}");
    //     let avg_trie_depth = after_dedup_size / block.mpt_updates.len();
    //     log::debug!(
    //         "avg_trie_depth {avg_trie_depth}, hash num {after_dedup_size}, mpt update num {}",
    //         block.mpt_updates.len()
    //     );
    //     (
    //         total_row_num,
    //         block.circuits_params.max_poseidon_rows.max(total_row_num),
    //     )
    // }

    /// Make the assignments to the MptCircuit, notice it fill mpt table
    /// but not fill hash table
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip =
            PoseidonHashChip::<_, HASH_STEP_SIZE>::construct(config.0.clone(), &self.0, self.1);

        chip.load(layouter)
    }
}

#[cfg(any(feature = "test-circuits", test))]
impl<F: Field + Hashable> halo2_proofs::plonk::Circuit<F> for PoseidonCircuit<F> {
    type Config = (PoseidonCircuitConfig<F>, Challenges);
    type FloorPlanner = halo2_proofs::circuit::SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(Default::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let poseidon_table = PoseidonTable::construct(meta);

        let config =
            { PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table }) };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

/// Get unrolled hash inputs as inputs to hash circuit
pub fn unroll_to_hash_input<F: Field, const BYTES_IN_FIELD: usize, const INPUT_LEN: usize>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[F; INPUT_LEN]> {
    let fl_cnt = code.len() / BYTES_IN_FIELD;
    let fl_cnt = if code.len() % BYTES_IN_FIELD != 0 {
        fl_cnt + 1
    } else {
        fl_cnt
    };

    let (msgs, _) = code
        .chain(std::iter::repeat(0))
        .take(fl_cnt * BYTES_IN_FIELD)
        .fold((Vec::new(), Vec::new()), |(mut msgs, mut cache), bt| {
            cache.push(bt);
            if cache.len() == BYTES_IN_FIELD {
                let mut buf: [u8; 64] = [0; 64];
                U256::from_big_endian(&cache).to_little_endian(&mut buf[0..32]);
                msgs.push(F::from_uniform_bytes(&buf));
                cache.clear();
            }
            (msgs, cache)
        });

    let input_cnt = msgs.len() / INPUT_LEN;
    let input_cnt = if msgs.len() % INPUT_LEN != 0 {
        input_cnt + 1
    } else {
        input_cnt
    };
    if input_cnt == 0 {
        return Vec::new();
    }
    let inputs = msgs
        .into_iter()
        .chain(std::iter::repeat(F::zero()))
        .chunks(2)
        .into_iter()
        .take(input_cnt)
        .map(|chunk| {
            let mut arr = [F::zero(); INPUT_LEN];
            for (i, v) in chunk.enumerate() {
                if i < INPUT_LEN {
                    arr[i] = v;
                }
            }
            arr
        })
        .collect::<Vec<_>>();
    inputs
}

/// Apply default constants in mod
pub fn unroll_to_hash_input_default<F: Field>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[F; PoseidonTable::INPUT_WIDTH]> {
    unroll_to_hash_input::<F, HASH_BYTES_IN_FIELD, { PoseidonTable::INPUT_WIDTH }>(code)
}

#[cfg(test)]
mod test {
    use crate::chips::execution_chip_v2::utils::pow_of_two;
    use field_exts::U256;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::halo2curves::ff::PrimeField;
    use types::Field;

    #[test]
    fn test_hash_result() {
        let f1 = Fr::from(123);
        let f2 = Fr::from(45u64);
        let hash = poseidon_base::hash::Hashable::hash_with_domain([f1, f2], Fr::one());
        println!(
            "hash result: h({:?}, {:?}) = {:?}",
            f1.get_lower_128(),
            f2.get_lower_128(),
            U256::from_little_endian(hash.to_repr().as_ref())
        );
        let result = U256::from_little_endian(hash.to_repr().as_ref());
        let (hi, lo) = result.div_mod(U256::pow(U256::from(2), 128.into()));
        let expected =
            Fr::from_u128(hi.as_u128()) * pow_of_two::<Fr>(128) + Fr::from_u128(lo.as_u128());
        assert_eq!(hash, expected, "Hash result mismatch");
    }
}
