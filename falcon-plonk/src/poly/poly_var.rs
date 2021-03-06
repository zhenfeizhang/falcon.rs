use super::PolyVar;
use ark_ff::PrimeField;
use falcon_rust::Polynomial;
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use std::marker::PhantomData;

impl<F: PrimeField> PolyVar<F> {
    /// create a PolyVar from variables
    pub fn new(coeff: Vec<Variable>) -> Self {
        Self {
            coeff,
            phantom: PhantomData::default(),
        }
    }

    /// allocate variables for a private polynomial
    pub fn alloc_vars(cs: &mut PlonkCircuit<F>, poly: &Polynomial) -> Result<Self, PlonkError> {
        let mut res = vec![];
        for &e in poly.coeff() {
            res.push(cs.create_variable(F::from(e))?);
        }

        Ok(Self {
            coeff: res,
            phantom: PhantomData::default(),
        })
    }

    /// allocate variables for a public polynomial
    pub fn alloc_public_vars(
        cs: &mut PlonkCircuit<F>,
        poly: &Polynomial,
    ) -> Result<Self, PlonkError> {
        let mut res = vec![];
        for &e in poly.coeff() {
            res.push(cs.create_public_variable(F::from(e))?);
        }

        Ok(Self {
            coeff: res,
            phantom: PhantomData::default(),
        })
    }

    /// Access the coefficients
    pub fn coeff(&self) -> &[Variable] {
        &self.coeff
    }

    /// Compute multiplication between two polynomials, defer the mod q reduction.
    pub fn mul_defer_mod_q_circuit(
        cs: &mut PlonkCircuit<F>,
        a: &Self,
        b: &Self,
    ) -> Result<Self, PlonkError> {
        let mut res = Vec::new();
        for (&ai, &bi) in a.coeff().iter().zip(b.coeff().iter()) {
            res.push(cs.mul(ai, bi)?);
        }
        Ok(Self::new(res))
    }
}
