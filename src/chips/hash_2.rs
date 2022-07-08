// MockHash: https://github.com/DrPeterVanNostrand/halo2-merkle/blob/main/src/main.rs
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct Hash2Config {
    pub advice: [Column<Advice>; 3],
    pub instance: Column<Instance>,
    pub hash_selector: Selector,
}

#[derive(Debug, Clone)]
pub struct Hash2Chip<F: FieldExt> {
    config: Hash2Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Hash2Chip<F> {
    pub fn construct(config: Hash2Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> Hash2Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let hash_selector = meta.selector();
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // Enforces our dummy hash function 2 * a = b.
        meta.create_gate("hash", |meta| {
            let s = meta.query_selector(hash_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a + b - c)]
        });

        Hash2Config {
            advice: [col_a, col_b, col_c],
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

    pub fn load_constant(
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

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        assigned_cell: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(assigned_cell.cell(), self.config.instance, row)
    }

    pub fn hash2(
        &self,
        mut layouter: impl Layouter<F>,
        input_a: AssignedCell<F, F>,
        input_b: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "hash2",
            |mut region| {
                input_a.copy_advice(|| "input_a", &mut region, self.config.advice[0], 0)?;
                input_b.copy_advice(|| "input_b", &mut region, self.config.advice[1], 0)?;
                let output_cell = region.assign_advice(
                    || "output",
                    self.config.advice[2],
                    0,
                    || {
                        input_a.value().map(|x| x.to_owned())
                            + input_b.value().map(|x| x.to_owned())
                    },
                )?;
                self.config.hash_selector.enable(&mut region, 0)?;
                Ok(output_cell)
            },
        )
    }
}
