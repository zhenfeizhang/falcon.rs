use super::{mod_q, NTTPolyVar, PolyVar};
use ark_ff::PrimeField;
use falcon_rust::{NTTPolynomial, LOG_N, MODULUS, N, NTT_TABLE};
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
    pub fn alloc_vars(cs: &mut PlonkCircuit<F>, poly: &NTTPolynomial) -> Result<Self, PlonkError> {
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
        poly: &NTTPolynomial,
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
    /// Cost 11266 constraints.
    /// Inputs:
    /// - cs: constraint system
    /// - input: the wires of the input polynomial
    /// - power_of_q_s: the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
    /// - param: the forward NTT table in wire format
    pub fn ntt_circuit(
        cs: &mut PlonkCircuit<F>,
        input: &PolyVar<F>,
        power_of_q_s: &[F],
        // param: &[Variable],
    ) -> Result<Self, PlonkError> {
        #[cfg(feature = "print-trace")]
        let cs_count = cs.num_gates();

        if input.coeff().len() != N {
            panic!("input length {} is not N", input.coeff().len())
        }
        let mut output = input.coeff().to_vec();

        let param: Vec<F> = NTT_TABLE.iter().take(N).map(|&x| F::from(x)).collect();

        let mut t = N;
        for l in 0..LOG_N {
            let m = 1 << l;
            let ht = t / 2;
            let mut i = 0;
            let mut j1 = 0;
            while i < m {
                let s = param[m + i];
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
                    let u = output[j];
                    let v = output[j + ht];

                    // output[j] = u + v * s
                    let wires_in = [u, v, cs.zero(), cs.zero()];
                    let coeffs = [F::one(), s, F::zero(), F::zero()];
                    output[j] = cs.lc(&wires_in, &coeffs)?;

                    // output[j+ht] = u + 2^{l+1} * q^{l+2} - v
                    // this is guaranteed to be positive since v is between 0 and 2^{l+1} * q^{l+2}
                    let wires_in = [u, v, cs.one(), cs.zero()];
                    let coeffs = [F::one(), -s, power_of_q_s[l + 1], F::zero()];
                    output[j + ht] = cs.lc(&wires_in, &coeffs)?;

                    j += 1;
                }
                i += 1;
                j1 += t
            }
            t = ht;
        }

        // perform a final mod reduction
        // Defer the range check of the output to caller
        for e in output.iter_mut() {
            *e = mod_q(cs, e, MODULUS)?;
        }

        #[cfg(feature = "print-trace")]
        println!(
            "NTT {}  total {}",
            cs.num_gates() - cs_count,
            cs.num_gates()
        );
        Ok(NTTPolyVar {
            coeff: output.to_vec(),
            phantom: PhantomData::default(),
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_ff::Field;
    use ark_std::test_rng;
    use falcon_rust::{NTTPolynomial, Polynomial, MODULUS};
    const REPEAT: usize = 100;
    #[test]
    fn test_ntt_mul_circuit() -> Result<(), PlonkError> {
        let mut rng = test_rng();

        for _ in 0..REPEAT {
            let mut cs = PlonkCircuit::new_ultra_plonk(8);
            // the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
            let const_power_q: Vec<Fq> = (1..LOG_N + 2)
                .map(|x| Fq::from((1 << (x - 1)) as u64) * Fq::from(MODULUS).pow(&[x as u64]))
                .collect();
            let poly = Polynomial::rand(&mut rng);
            let poly_var = PolyVar::<Fq>::alloc_vars(&mut cs, &poly)?;

            let output = NTTPolynomial::from(&poly);

            let output_var = NTTPolyVar::ntt_circuit(&mut cs, &poly_var, &const_power_q)?;

            for i in 0..N {
                assert_eq!(
                    Fq::from(output.coeff()[i]),
                    cs.witness(output_var.coeff()[i])?
                )
            }
            assert!(cs.check_circuit_satisfiability(&[]).is_ok());
        }
        Ok(())
    }
}
