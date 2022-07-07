// MockMerkleTreeV2: https://github.com/DrPeterVanNostrand/halo2-merkle/blob/main/src/main.rs
use super::hash_2::{self, Hash2Chip, Hash2Config};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::*,
    plonk::*,
    poly::Rotation,
};
use std::{marker::PhantomData, path};

#[derive(Debug, Clone)]
struct MerkleTreeV2Config {
    pub advice: [Column<Advice>; 3],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub instance: Column<Instance>,
    pub hash2_config: Hash2Config,
}

#[derive(Debug, Clone)]
struct MerkleTreeV2Chip<F: FieldExt> {
    config: MerkleTreeV2Config,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> MerkleTreeV2Chip<F> {
    pub fn construct(config: MerkleTreeV2Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 3],
        instance: Column<Instance>,
    ) -> MerkleTreeV2Config {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
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

        MerkleTreeV2Config {
            advice: [col_a, col_b, col_c],
            bool_selector: bool_selector,
            swap_selector: swap_selector,
            instance: instance,
            hash2_config: Hash2Chip::configure(meta, [col_a, col_b, col_c], instance),
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

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }

    fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        digest: &AssignedCell<F, F>,
        element: Value<F>,
        index: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (left, right) = layouter.assign_region(
            || "merkle_prove_leaf",
            |mut region| {
                // Row 0
                digest.copy_advice(|| "digest", &mut region, self.config.advice[0], 0)?;
                region.assign_advice(|| "element", self.config.advice[1], 0, || element)?;
                region.assign_advice(|| "index", self.config.advice[2], 0, || index)?;
                self.config.bool_selector.enable(&mut region, 0)?;
                self.config.swap_selector.enable(&mut region, 0)?;

                // Row 1
                let digest_value = digest.value().map(|x| x.to_owned());
                let (mut l, mut r) = (digest_value, element);
                index.map(|x| {
                    (l, r) = if x == F::zero() { (l, r) } else { (r, l) };
                });
                let left = region.assign_advice(|| "left", self.config.advice[0], 1, || l)?;
                let right = region.assign_advice(|| "right", self.config.advice[1], 1, || r)?;

                Ok((left, right))
            },
        )?;

        let hash2_chip = Hash2Chip::construct(self.config.hash2_config.clone());
        let digest = hash2_chip.hash2(layouter.namespace(|| "hash2"), left, right)?;
        Ok(digest)
    }

    pub fn merkle_prove(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: &AssignedCell<F, F>,
        elements: &Vec<Value<F>>,
        indices: &Vec<Value<F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let layers = elements.len();
        let mut leaf_or_digest = self.merkle_prove_layer(
            layouter.namespace(|| "merkle_prove_layer_0"),
            leaf,
            elements[0],
            indices[0],
        )?;
        for i in 1..layers {
            leaf_or_digest = self.merkle_prove_layer(
                layouter.namespace(|| format!("merkle_prove_layer_{}", i)),
                &leaf_or_digest,
                elements[i],
                indices[i],
            )?;
        }
        Ok(leaf_or_digest)
    }
}

#[derive(Default)]
struct MerkleTreeV2Circuit<F> {
    pub leaf: Value<F>,
    pub elements: Vec<Value<F>>,
    pub indices: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for MerkleTreeV2Circuit<F> {
    type Config = MerkleTreeV2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        MerkleTreeV2Chip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = MerkleTreeV2Chip::construct(config);
        let leaf_cell = chip.load_private(layouter.namespace(|| "load leaf"), self.leaf)?;
        chip.expose_public(layouter.namespace(|| "public leaf"), &leaf_cell, 0);
        let digest = chip.merkle_prove(
            layouter.namespace(|| "merkle_prove"),
            &leaf_cell,
            &self.elements,
            &self.indices,
        )?;
        chip.expose_public(layouter.namespace(|| "public root"), &digest, 1)?;
        Ok(())
    }
}

mod tests {
    use super::MerkleTreeV2Circuit;
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
