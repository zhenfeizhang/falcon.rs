use super::{DualPolyVar, PolyVar};
use ark_ff::PrimeField;
use falcon_rust::{DualPolynomial, MODULUS};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit},
    errors::PlonkError,
};
use std::marker::PhantomData;

impl<F: PrimeField> DualPolyVar<F> {
    // allocate variables for a give ntt_polynomial
    pub fn alloc_vars(cs: &mut PlonkCircuit<F>, poly: &DualPolynomial) -> Result<Self, PlonkError> {
        let mut pos = vec![];
        for &e in poly.pos.coeff() {
            pos.push(cs.create_variable(F::from(e))?);
        }
        let mut neg = vec![];
        for &e in poly.neg.coeff() {
            neg.push(cs.create_variable(F::from(e))?);
        }

        // for each coefficient i, either pos[i] = 0 or neg[i] = 0
        for (&p, &n) in pos.iter().zip(neg.iter()) {
            let prod = cs.mul(p, n)?;
            cs.equal_gate(prod, cs.zero())?;
        }

        Ok(Self {
            pos: PolyVar {
                coeff: pos,
                phantom: PhantomData::default(),
            },

            neg: PolyVar {
                coeff: neg,
                phantom: PhantomData::default(),
            },
        })
    }

    pub fn to_poly_var(&self, cs: &mut PlonkCircuit<F>) -> Result<PolyVar<F>, PlonkError> {
        let mut res = vec![];

        for (&p, &n) in self.pos.coeff.iter().zip(self.neg.coeff.iter()) {
            let wires = [p, cs.one(), n, cs.zero()];
            let coeffs = [F::one(), F::from(MODULUS), -F::one(), F::zero()];

            let c = cs.lc(&wires, &coeffs)?;
            res.push(c)
        }

        Ok(PolyVar {
            coeff: res,
            phantom: PhantomData::default(),
        })
    }
}
