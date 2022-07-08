use super::super::chips::hash_2::{Hash2Chip, Hash2Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

#[derive(Default)]
struct Hash2Circuit<F> {
    pub a: Value<F>,
    pub b: Value<F>,
}

impl<F: FieldExt> Circuit<F> for Hash2Circuit<F> {
    type Config = Hash2Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c: Column<Advice> = meta.advice_column();
        let instance = meta.instance_column();
        Hash2Chip::configure(meta, [col_a, col_b, col_c], instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = Hash2Chip::construct(config);
        let a = chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = chip.load_private(layouter.namespace(|| "load b"), self.b)?;
        let b = chip.hash2(layouter.namespace(|| "Hash2"), a, b)?;
        chip.expose_public(layouter.namespace(|| "hi"), b, 0)
    }
}

mod tests {
    use super::Hash2Circuit;
    use halo2_proofs::{circuit::Value, dev::MockProver, pasta::Fp};

    #[test]
    fn test() {
        let k = 4;
        let a = Value::known(Fp::from(2));
        let b = Value::known(Fp::from(7));
        let public_inputs = vec![Fp::from(9)];
        let circuit = Hash2Circuit { a, b };
        let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
