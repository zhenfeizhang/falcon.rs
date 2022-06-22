use crate::mod_q;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, Result as ArkResult, SynthesisError};
use falcon_rust::{NTTPolynomial, Polynomial, LOG_N, N};
use std::ops::{Add, Mul};

#[derive(Debug, Clone)]
pub struct NTTPolyVar<F: PrimeField>(pub Vec<FpVar<F>>);

#[derive(Debug, Clone)]
pub struct PolyVar<F: PrimeField>(pub Vec<FpVar<F>>);

impl<F: PrimeField> Add for NTTPolyVar<F> {
    type Output = Self;

    /// generate the variables for a + b without mod reduction
    fn add(self, other: Self) -> <Self as Add<Self>>::Output {
        let mut res = Vec::new();
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            res.push(a.clone() + b.clone())
        }
        Self(res)
    }
}

impl<F: PrimeField> Mul for NTTPolyVar<F> {
    type Output = Self;

    /// generate the variables for a * b without mod reduction
    fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
        let mut res = Vec::new();
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            res.push(a.clone() * b.clone())
        }
        Self(res)
    }
}

impl<F: PrimeField> NTTPolyVar<F> {
    /// build a new instances from inputs
    pub fn new(coeff: Vec<FpVar<F>>) -> Self {
        Self(coeff)
    }

    // allocate variables for a give ntt_polynomial
    pub fn alloc_vars(
        cs: impl Into<Namespace<F>>,
        poly: &NTTPolynomial,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let mut vec = Vec::new();
        for &value in poly.coeff().iter() {
            vec.push(FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(value)),
                mode,
            )?);
        }
        Ok(Self(vec))
    }

    /// generate constraints proving that c = a * b without mod reduction
    pub fn enforce_product(a: &Self, b: &Self, c: &Self) -> ArkResult<()> {
        for (ai, (bi, ci)) in a.0.iter().zip(b.0.iter().zip(c.0.iter())) {
            let tmp = ai * bi;
            tmp.enforce_equal(ci)?;
        }
        Ok(())
    }

    /// generate constraints proving that c = a + b without mod reduction
    pub fn enforce_sum(a: &Self, b: &Self, c: &Self) -> ArkResult<()> {
        for (ai, (bi, ci)) in a.0.iter().zip(b.0.iter().zip(c.0.iter())) {
            let tmp = ai + bi;
            tmp.enforce_equal(ci)?;
        }
        Ok(())
    }

    pub fn mod_q(&self, cs: ConstraintSystemRef<F>, modulus_var: &FpVar<F>) -> Self {
        let res: Vec<FpVar<F>> = self
            .0
            .iter()
            .map(|x| mod_q(cs.clone(), x, modulus_var).unwrap())
            .collect();
        Self(res)
    }

    /// Access the coefficients
    pub fn coeff(&self) -> &[FpVar<F>] {
        &self.0
    }

    /// The circuit to convert a poly into its NTT form
    /// Cost 15360 constraints.
    /// Inputs:
    /// - cs: constraint system
    /// - input: the wires of the input polynomial
    /// - const_vars: the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
    /// - param: the forward NTT table in wire format
    pub fn ntt_circuit(
        cs: ConstraintSystemRef<F>,
        input: &PolyVar<F>,
        const_vars: &[FpVar<F>],
        param: &[FpVar<F>],
    ) -> Result<Self, SynthesisError> {
        let mut output = Self::ntt_circuit_defer_range_check(input, const_vars, param)?;

        // perform a final mod reduction to make the
        // output into the right range
        // this is the only place that we need non-native circuits
        for e in output.0.iter_mut() {
            *e = mod_q(cs.clone(), e, &const_vars[0])?;
        }

        Ok(output)
    }

    /// The circuit to convert a poly into its NTT form
    /// Inputs:
    /// - input: the wires of the input polynomial
    /// - const_vars: the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
    /// - param: the forward NTT table in wire format
    pub fn ntt_circuit_defer_range_check(
        input: &PolyVar<F>,
        const_vars: &[FpVar<F>],
        param: &[FpVar<F>],
    ) -> Result<Self, SynthesisError> {
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

        Ok(NTTPolyVar(output.to_vec()))
    }
}

impl<F: PrimeField> Add for PolyVar<F> {
    type Output = Self;

    /// generate the variables for a + b without mod reduction
    fn add(self, other: Self) -> <Self as Add<Self>>::Output {
        let mut res = Vec::new();
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            res.push(a.clone() + b.clone())
        }
        Self(res)
    }
}

impl<F: PrimeField> Mul for PolyVar<F> {
    type Output = Self;

    /// generate the variables for a * b without mod reduction
    fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
        let mut res = Vec::new();
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            res.push(a.clone() * b.clone())
        }
        Self(res)
    }
}

impl<F: PrimeField> PolyVar<F> {
    /// build a new instances from inputs
    pub fn new(coeff: Vec<FpVar<F>>) -> Self {
        Self(coeff)
    }

    // allocate variables for a give polynomial
    pub fn alloc_vars(
        cs: impl Into<Namespace<F>>,
        poly: &Polynomial,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let mut vec = Vec::new();
        for &value in poly.coeff().iter() {
            vec.push(FpVar::new_variable(
                cs.clone(),
                || Ok(F::from(value)),
                mode,
            )?);
        }
        Ok(Self(vec))
    }

    /// generate constraints proving that c = a * b without mod reduction
    pub fn enforce_product(a: &Self, b: &Self, c: &Self) -> ArkResult<()> {
        for (ai, (bi, ci)) in a.0.iter().zip(b.0.iter().zip(c.0.iter())) {
            let tmp = ai * bi;
            tmp.enforce_equal(ci)?;
        }
        Ok(())
    }

    /// generate constraints proving that c = a + b without mod reduction
    pub fn enforce_sum(a: &Self, b: &Self, c: &Self) -> ArkResult<()> {
        for (ai, (bi, ci)) in a.0.iter().zip(b.0.iter().zip(c.0.iter())) {
            let tmp = ai + bi;
            tmp.enforce_equal(ci)?;
        }
        Ok(())
    }

    /// Access the coefficients
    pub fn coeff(&self) -> &[FpVar<F>] {
        &self.0
    }
}

// TODO: more tests for the functions

#[cfg(test)]
mod tests {
    use crate::ntt_param_var;

    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_ff::Field;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use falcon_rust::{NTTPolynomial, Polynomial, MODULUS};

    #[test]
    fn test_ntt_mul_circuit() {
        let mut rng = test_rng();

        for _ in 0..10 {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let param_vars = ntt_param_var(cs.clone()).unwrap();
            // the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
            let const_power_q_vars: Vec<FpVar<Fq>> = (1..LOG_N + 2)
                .map(|x| {
                    FpVar::<Fq>::new_constant(
                        cs.clone(),
                        Fq::from(1 << (x - 1)) * Fq::from(MODULUS).pow(&[x as u64]),
                    )
                    .unwrap()
                })
                .collect();
            let poly = Polynomial::rand(&mut rng);
            let poly_var = PolyVar::<Fq>::alloc_vars(
                cs.clone(),
                &poly,
                ark_r1cs_std::alloc::AllocationMode::Witness,
            )
            .unwrap();

            let output = NTTPolynomial::from(&poly);

            // let num_instance_variables = cs.num_instance_variables();
            // let num_witness_variables = cs.num_witness_variables();
            // let num_constraints = cs.num_constraints();

            let output_var =
                NTTPolyVar::ntt_circuit(cs.clone(), &poly_var, &const_power_q_vars, &param_vars)
                    .unwrap();
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables() - num_instance_variables,
            //     cs.num_witness_variables() - num_witness_variables,
            //     cs.num_constraints() - num_constraints,
            // );

            for i in 0..N {
                assert_eq!(
                    Fq::from(output.coeff()[i]),
                    output_var.coeff()[i].value().unwrap()
                )
            }
        }

        // assert!(false)
    }
}
