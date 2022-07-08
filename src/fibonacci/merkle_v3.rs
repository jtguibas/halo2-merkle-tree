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
    instance: Column<Instance>,
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
        let instance = meta.instance_column();
        for i in 0..WIDTH {
            meta.enable_equality(state[i]);
        }
        meta.enable_equality(instance);
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
            instance,
            pow5_config: pow5_config,
        }
    }

    pub fn load_private_inputs(
        &self,
        mut layouter: impl Layouter<Fp>,
        inputs: [Value<Fp>; L],
    ) -> Result<[AssignedCell<Fp, Fp>; L], Error> {
        layouter.assign_region(
            || "load private inputs",
            |mut region| -> Result<[AssignedCell<Fp, Fp>; L], Error> {
                let result = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "private input",
                            self.config.inputs[i],
                            0,
                            || x.to_owned(),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }

    fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        words: &[AssignedCell<Fp, Fp>; L],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        let word_cells = layouter.assign_region(
            || "load words",
            |mut region| -> Result<[AssignedCell<Fp, Fp>; L], Error> {
                let result = words
                    .iter()
                    .enumerate()
                    .map(|(i, word)| {
                        word.copy_advice(
                            || format!("word {}", i),
                            &mut region,
                            self.config.inputs[i],
                            0,
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
    message: [Value<Fp>; L],
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
            message: (0..L)
                .map(|i| Value::unknown())
                .collect::<Vec<Value<Fp>>>()
                .try_into()
                .unwrap(),
            output: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        PoseidonChip::<S, WIDTH, RATE, L>::configure(meta)
    }

    fn synthesize(
        &self,
        config: PoseidonConfig<WIDTH, RATE, L>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let poseidon_chip = PoseidonChip::<S, WIDTH, RATE, L>::construct(config);
        let message_cells = poseidon_chip
            .load_private_inputs(layouter.namespace(|| "load private inputs"), self.message)?;
        let result = poseidon_chip.hash(layouter.namespace(|| "poseidon chip"), &message_cells)?;
        poseidon_chip.expose_public(layouter.namespace(|| "expose result"), &result, 0)?;
        Ok(())
    }
}

mod tests {
    use std::marker::PhantomData;

    use super::PoseidonCircuit;
    use halo2_gadgets::poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    };
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    fn test() {
        let input = 99u64;
        let message = [Fp::from(input), Fp::from(input)];
        let output =
            poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);

        let circuit = PoseidonCircuit::<OrchardNullifier, 3, 2, 2> {
            message: message.map(|x| Value::known(x)),
            output: Value::known(output),
            _spec: PhantomData,
        };
        let public_input = vec![output];
        let prover = MockProver::run(10, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}
