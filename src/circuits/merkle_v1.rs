use super::super::chips::merkle_v1::{MerkleTreeV1Chip, MerkleTreeV1Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

#[derive(Default)]
struct MerkleTreeV1Circuit<F> {
    pub leaf: Value<F>,
    pub path_elements: Vec<Value<F>>,
    pub path_indices: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for MerkleTreeV1Circuit<F> {
    type Config = MerkleTreeV1Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        MerkleTreeV1Chip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = MerkleTreeV1Chip::construct(config);
        let mut digest = chip.assign(
            layouter.namespace(|| "first row"),
            self.leaf,
            self.path_elements[0],
            self.path_indices[0],
            None,
            0,
        )?;

        for i in 1..self.path_elements.len() {
            digest = chip.assign(
                layouter.namespace(|| "next row"),
                self.leaf,
                self.path_elements[i],
                self.path_indices[i],
                Some(&digest),
                i as usize,
            )?;
        }

        chip.expose_public(layouter.namespace(|| "root"), &digest, 0)?;

        Ok(())
    }
}

mod tests {
    use super::MerkleTreeV1Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    fn test() {
        let leaf = Value::known(Fp::from(99));
        let path_elements = vec![Value::known(Fp::from(1)), Value::known(Fp::from(1))];
        let path_indices = vec![Value::known(Fp::from(0)), Value::known(Fp::from(0))];
        let digest = Fp::from(101);

        let circuit = MerkleTreeV1Circuit {
            leaf: leaf,
            path_elements: path_elements,
            path_indices: path_indices,
        };

        let public_input = vec![digest];
        let prover = MockProver::run(4, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}
