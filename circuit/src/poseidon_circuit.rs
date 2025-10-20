//! wrapping of mpt-circuit

use crate::execution_circuit::lookup_table::poseidon_table::PoseidonTable;
use crate::utils::challenges::Challenges;
use crate::utils::to_field::ToField;
use crate::vm_circuit::{CircuitConfigArgs, SubCircuit, SubCircuitConfig};
use witnesses::static_info::{EntryInfo, Footprints, StaticInfo};
use witnesses::step_state::ExecutionState;

use field_exts::U256;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, ErrorFront as Error},
};
use itertools::Itertools;
use move_package::compilation::compiled_package::CompiledPackage;
pub use poseidon_circuit::hash::Hashable;
use poseidon_circuit::hash::{PoseidonHashChip, PoseidonHashConfig, PoseidonHashTable};
use types::Field;
use witnesses::preprocessor::WitnessPreProcessor;

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
        circuit_config_args: CircuitConfigArgs,
    ) -> Self {
        let entry = traces.entry().expect("entry should be set in traces");
        let static_info = StaticInfo::generate(entry, package, pubs_indices)
            .expect("static info should be generated");
        let preprocessor = WitnessPreProcessor::default();
        let states = preprocessor.process(&traces.0, &static_info);

        let max_hashes = circuit_config_args.max_poseidon_rows / F::hash_block_size();
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
        _package: &CompiledPackage,
        _entry: EntryInfo,
        _pubs_indices: &[usize],
        circuit_config_args: CircuitConfigArgs,
    ) -> Self {
        let max_hashes = circuit_config_args.max_poseidon_rows / F::hash_block_size();
        let poseidon_table_data: PoseidonHashTable<F> = PoseidonHashTable::default();
        Self(poseidon_table_data, max_hashes)
    }

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
    use crate::utils::pow_of_two;
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
