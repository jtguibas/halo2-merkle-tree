use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct MerkleTreeV1Config {
    pub advice: [Column<Advice>; 3],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub hash_selector: Selector,
    pub instance: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct MerkleTreeV1Chip<F: FieldExt> {
    config: MerkleTreeV1Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MerkleTreeV1Chip<F> {
    pub fn construct(config: MerkleTreeV1Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> MerkleTreeV1Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let hash_selector = meta.selector();
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // Enforces that c is either a 0 or 1.
        meta.create_gate("bool", |meta| {
            let s = meta.query_selector(bool_selector);
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * c.clone() * (Expression::Constant(F::from(1)) - c.clone())]
        });

        // Enforces that if the swap bit is on, l=b and r=a. Otherwise, l=a and r=b.
        meta.create_gate("swap", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let l = meta.query_advice(col_a, Rotation::next());
            let r = meta.query_advice(col_b, Rotation::next());
            vec![
                s * (c * Expression::Constant(F::from(2)) * (b.clone() - a.clone())
                    - (l - a.clone())
                    - (b.clone() - r)),
            ]
        });

        // Enforces our dummy hash function a + b = c.
        meta.create_gate("hash", |meta| {
            let s = meta.query_selector(hash_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a + b - c)]
        });

        MerkleTreeV1Config {
            advice: [col_a, col_b, col_c],
            bool_selector,
            swap_selector,
            hash_selector,
            instance,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: Value<F>,
        path: Value<F>,
        bit: Value<F>,
        prev_digest: Option<&AssignedCell<F, F>>,
        layer_idx: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || format!("layer {}", layer_idx),
            |mut region| {
                // Row 0: | Leaf | Path | Bit |
                // Enabled Selectors: Bool, Swap
                if layer_idx == 0 {
                    region.assign_advice(|| "leaf", self.config.advice[0], 0, || leaf)?;
                } else {
                    prev_digest.unwrap().copy_advice(
                        || "leaf_cell",
                        &mut region,
                        self.config.advice[0],
                        0,
                    )?;
                }
                region.assign_advice(|| "path", self.config.advice[1], 0, || path)?;
                region.assign_advice(|| "bit", self.config.advice[2], 0, || bit)?;
                self.config.bool_selector.enable(&mut region, 0)?;
                self.config.swap_selector.enable(&mut region, 0)?;

                // Row 1: | InputLeft | InputRight | Digest |
                // Enabled Selectors: Hash
                let new: Value<F>;
                if layer_idx == 0 {
                    new = leaf
                } else {
                    new = prev_digest.unwrap().value().map(|x| x.to_owned())
                };
                let mut input_l = new;
                let mut input_r = path;
                bit.map(|bit| {
                    if bit != F::zero() {
                        (input_l, input_r) = (path, new);
                    }
                });
                region.assign_advice(|| "input_l", self.config.advice[0], 1, || input_l)?;
                region.assign_advice(|| "input_r", self.config.advice[1], 1, || input_r)?;
                let digest_cell = region.assign_advice(
                    || "digest",
                    self.config.advice[2],
                    1,
                    || input_l + input_r,
                )?;
                self.config.hash_selector.enable(&mut region, 1)?;
                Ok(digest_cell)
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
