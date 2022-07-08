// MockHash: https://github.com/DrPeterVanNostrand/halo2-merkle/blob/main/src/main.rs
use super::super::chips::hash_1::{Hash1Chip, Hash1Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};

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
