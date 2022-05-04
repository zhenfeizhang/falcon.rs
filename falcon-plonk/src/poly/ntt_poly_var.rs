use super::{mod_q, NTTPolyVar, PolyVar};
use ark_ff::PrimeField;
use falcon_rust::{Polynomial, LOG_N, N};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use std::marker::PhantomData;

impl<F: PrimeField> NTTPolyVar<F> {
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

    /// The circuit to convert a poly into its NTT form
    /// Cost 15360 constraints.
    /// Inputs:
    /// - cs: constraint system
    /// - input: the wires of the input polynomial
    /// - const_vars: the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
    /// - param: the forward NTT table in wire format
    pub fn ntt_circuit(
        cs: &mut PlonkCircuit<F>,
        input: &PolyVar<F>,
        const_vars: &[Variable],
        param: &[Variable],
    ) -> Result<Self, PlonkError> {
        if input.coeff().len() != N {
            panic!("input length {} is not N", input.coeff().len())
        }
        let mut output = input.coeff().to_vec();

        let mut t = N;
        for l in 0..LOG_N {
            let m = 1 << l;
            let ht = t / 2;
            let mut i = 0;
            let mut j1 = 0;
            while i < m {
                let s = param[m + i].clone();
                let j2 = j1 + ht;
                let mut j = j1;
                while j < j2 {
                    // for the l-th loop, we know that all the output's
                    // coefficients are less than q^{l+1}
                    // therefore we have
                    //  u < 2^l * q^{l+1}
                    //  v < 2^l * q^{l+2}
                    // and we have
                    //  neg_v = q^{l+2} - v
                    // note that this works when q^10 < F::Modulus
                    // so all operations here becomes native field operations
                    let u = output[j].clone();
                    let v = &output[j + ht] * &s;
                    let neg_v = &const_vars[l + 1] - &v;

                    // output[j] and output[j+ht]
                    // are between 0 and 2^{l+1} * q^{l+2}
                    output[j] = &u + &v;
                    output[j + ht] = &u + &neg_v;
                    j += 1;
                }
                i += 1;
                j1 += t
            }
            t = ht;
        }

        // perform a final mod reduction to make the
        // output into the right range
        // this is the only place that we need non-native circuits
        for e in output.iter_mut() {
            *e = mod_q(cs, e, &const_vars[0])?;
        }

        Ok(NTTPolyVar {
            coeff: output.to_vec(),
            phantom: PhantomData::default(),
        })
    }
}
