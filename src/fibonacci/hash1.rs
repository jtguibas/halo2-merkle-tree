// MockHash: https://github.com/DrPeterVanNostrand/halo2-merkle/blob/main/src/main.rs
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
struct Hash1Config {
    pub advice: [Column<Advice>; 2],
    pub instance: Column<Instance>,
    pub hash_selector: Selector,
}

#[derive(Debug, Clone)]
struct Hash1Chip<F: FieldExt> {
    config: Hash1Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Hash1Chip<F> {
    pub fn construct(config: Hash1Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
    ) -> Hash1Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let hash_selector = meta.selector();
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(instance);

        // Enforces our dummy hash function 2 * a = b.
        meta.create_gate("hash", |meta| {
            let s = meta.query_selector(hash_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            vec![s * (Expression::Constant(F::from(2)) * a - b)]
        });

        Hash1Config {
            advice: [col_a, col_b],
            instance,
            hash_selector,
        }
    }

    pub fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        input: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(|| "private input", self.config.advice[0], 0, || input)
            },
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "load constant",
            |mut region| {
                region.assign_advice_from_constant(
                    || "constant value",
                    self.config.advice[0],
                    0,
                    constant,
                )
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        assigned_cell: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(assigned_cell.cell(), self.config.instance, row)
    }

    pub fn hash1(
        &self,
        mut layouter: impl Layouter<F>,
        input: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "hash1",
            |mut region| {
                input.copy_advice(|| "input", &mut region, self.config.advice[0], 0)?;
                let output_cell = region.assign_advice(
                    || "output",
                    self.config.advice[1],
                    0,
                    || input.value().map(|x| x.to_owned()) * Value::known(F::from(2)),
                )?;
                self.config.hash_selector.enable(&mut region, 0)?;
                Ok(output_cell)
            },
        )
    }
}

#[derive(Default)]
struct Hash1Circuit<F> {
    pub a: Value<F>,
}

impl<F: FieldExt> Circuit<F> for Hash1Circuit<F> {
    type Config = Hash1Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let instance = meta.instance_column();
        Hash1Chip::configure(meta, [col_a, col_b], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = Hash1Chip::construct(config);
        let a = chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = chip.hash1(layouter.namespace(|| "Hash1"), a)?;
        chip.expose_public(layouter.namespace(|| "hi"), b, 0)
    }
}

mod tests {
    use super::Hash1Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    fn test() {
        let k = 4;
        let a = Value::known(Fp::from(2));
        let public_inputs = vec![Fp::from(4)];
        let circuit = Hash1Circuit { a };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
