/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{circuit::*, pasta::Fp, plonk::*};
use std::marker::PhantomData;

#[derive(Debug, Clone)]

struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    inputs: Vec<Column<Advice>>,
    pow5_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

struct PoseidonChip<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
{
    config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox.try_into().unwrap(),
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            inputs: state.clone().try_into().unwrap(),
            pow5_config: pow5_config,
        }
    }

    fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        words: [&AssignedCell<Fp, Fp>; L],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        layouter.assign_region(
            || "load words",
            |mut region| {
                for i in 0..L {
                    words[i].copy_advice(
                        || format!("word {}", i),
                        region,
                        self.config.inputs[i],
                        0,
                    )?;
                }
            },
        );
        let word_cells = layouter.assign_region(
            || "load words",
            |mut region| -> Result<[AssignedCell<Fp, Fp>; L], Error> {
                let result = words
                    .iter()
                    .enumerate()
                    .map(|(i, word)| {
                        let value = word.value().map(|x| x.to_owned());
                        region.assign_advice(
                            || format!("load word {}", i),
                            self.config.inputs[i],
                            0,
                            || value,
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), word_cells)
    }
}

struct PoseidonCircuit<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    message: Value<[Fp; L]>,
    output: Value<Fp>,
    _spec: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for PoseidonCircuit<S, WIDTH, RATE, L>
{
    type Config = PoseidonConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        PoseidonChip::<S, WIDTH, RATE, L>::configure(&mut meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<WIDTH, RATE, L>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(config);
        Ok(())
    }
}

mod tests {
    use super::PoseidonChip;
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    fn test() {
        let leaf = 99u64;
        let elements = vec![1u64, 5u64, 6u64, 9u64, 9u64];
        let indices = vec![0u64, 0u64, 0u64, 0u64, 0u64];
        let digest: u64 = leaf + elements.iter().sum::<u64>();

        let leaf_fp = Value::known(Fp::from(leaf));
        let elements_fp: Vec<Value<Fp>> = elements
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();
        let indices_fp: Vec<Value<Fp>> = indices
            .iter()
            .map(|x| Value::known(Fp::from(x.to_owned())))
            .collect();

        let circuit = MerkleTreeV2Circuit {
            leaf: leaf_fp,
            elements: elements_fp,
            indices: indices_fp,
        };

        let public_input = vec![Fp::from(leaf), Fp::from(digest)];
        let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}
