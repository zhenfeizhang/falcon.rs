use crate::gadgets::*;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result};
use falcon_rust::*;

#[derive(Clone, Debug)]
pub struct FalconSchoolBookVerificationCircuit {
    pk: PublicKey,
    msg: Vec<u8>,
    sig: Signature,
}

impl FalconSchoolBookVerificationCircuit {
    pub fn build_circuit(pk: PublicKey, msg: Vec<u8>, sig: Signature) -> Self {
        Self { pk, msg, sig }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for FalconSchoolBookVerificationCircuit {
    /// generate a circuit proving that for a given tuple: pk, msg, sig
    /// the following statement holds
    /// - hm = hash_message(message, nonce)     <- done in public
    /// - v = hm - sig * pk
    /// - l2_norm(sig, v) < SIG_L2_BOUND = 34034726
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
        let sig_poly: Polynomial = (&self.sig).into();
        let pk_poly: Polynomial = (&self.pk).into();

        let const_q_var = FpVar::<F>::new_constant(cs.clone(), F::from(MODULUS))?;

        // ========================================
        // compute related data in the clear
        // ========================================
        let hm = Polynomial::from_hash_of_message(self.msg.as_ref(), self.sig.nonce());

        // compute v = hm - uh and lift it to positives
        let uh = sig_poly * pk_poly;
        let v = hm - uh;

        // ========================================
        // allocate the variables with range checks
        // ========================================
        // signature
        let mut sig_poly_vars = Vec::new();
        for e in sig_poly.coeff() {
            let tmp = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*e)))?;

            // ensure all the sig inputs are smaller than MODULUS
            // Note that this step is not necessary: we will be checking
            // the l2-norm of \|sig | v\| < 34034726. If any
            // coefficient of sig is greater than MODULUS, we will have
            // a l2-norm that is at least > MODULUS^2 which is greater
            // than 34034726 and cause the circuit to be unsatisfied.
            //
            // enforce_less_than_q(cs.clone(), &tmp)?;
            sig_poly_vars.push(tmp);
        }

        // pk
        //
        // here we use a buffer = [-pk[0], -pk[1], ..., -pk[511], pk[0], pk[1], ...,
        // pk[511]] where the buffer[i+1..i+513].reverse() will be used for the i-th
        // column in inner-product calculation
        let mut pk_poly_vars = Vec::new();
        let mut neg_pk_poly_vars = Vec::new();
        for e in pk_poly.coeff() {
            // do not need to ensure the pk inputs are smaller than MODULUS
            // pk is public input, so the verifier can check in the clear
            let tmp = FpVar::<F>::new_input(cs.clone(), || Ok(F::from(*e)))?;
            // It is implied that all the neg_pk inputs are smaller than MODULUS
            neg_pk_poly_vars.push(&const_q_var - &tmp);
            pk_poly_vars.push(tmp);
        }

        // hash of message
        let mut hm_vars = Vec::new();
        for e in hm.coeff() {
            // do not need to ensure the hm inputs are smaller than MODULUS
            // hm is public input, does not need to keep secret
            hm_vars.push(FpVar::<F>::new_input(cs.clone(), || Ok(F::from(*e)))?);
        }

        // v with positive coefficients
        let mut v_pos_vars = Vec::new();
        for e in v.coeff() {
            // ensure all the v inputs are smaller than MODULUS
            // v will need to be kept secret
            let tmp = FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(*e)))?;
            enforce_less_than_q(cs.clone(), &tmp)?;
            v_pos_vars.push(tmp);
        }

        // ========================================
        // proving v = hm + sig * pk mod MODULUS
        // ========================================
        // we are proving the polynomial congruence via
        // a school-bool vector-matrix multiplication.
        //
        //
        // build buffer = [-pk[0], -pk[1], ..., -pk[N-1], pk[0], pk[1], ..., pk[N]]
        let mut buf_poly_poly_vars = [neg_pk_poly_vars, pk_poly_vars].concat();
        buf_poly_poly_vars.reverse();

        for i in 0..N {
            // current_col = sig * pk[i] mod q
            let current_col = inner_product_mod(
                cs.clone(),
                sig_poly_vars.as_ref(),
                buf_poly_poly_vars[N - 1 - i..N * 2 - 1 - i].as_ref(),
                &const_q_var,
            )?;

            // rhs = hm + q - sig * pk[i] mod q
            let rhs = &hm_vars[i] + &const_q_var - &current_col;

            // v = rhs mod MODULUS
            (((&rhs).is_eq(&v_pos_vars[i])?)
                .or(&(&rhs).is_eq(&(&v_pos_vars[i] + &const_q_var))?)?)
            .enforce_equal(&Boolean::TRUE)?;
        }

        // ========================================
        // proving l2_norm(v | sig) < 34034726
        // ========================================
        let l2_norm_var = l2_norm_var(
            cs.clone(),
            &[v_pos_vars, sig_poly_vars].concat(),
            &const_q_var,
        )?;
        enforce_less_than_norm_bound(cs, &l2_norm_var)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_relations::r1cs::ConstraintSystem;
    #[test]
    fn test_schoolbook_verification_r1cs() {
        let keypair = KeyPair::keygen();
        let message = "testing message".as_bytes();
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());

        assert!(keypair.public_key.verify(message.as_ref(), &sig));
        assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));

        let cs = ConstraintSystem::<Fq>::new_ref();

        let falcon_circuit = FalconSchoolBookVerificationCircuit {
            pk: keypair.public_key,
            msg: message.to_vec(),
            sig,
        };

        falcon_circuit.generate_constraints(cs.clone()).unwrap();
        // println!(
        //     "number of variables {} {} and constraints {}\n",
        //     cs.num_instance_variables(),
        //     cs.num_witness_variables(),
        //     cs.num_constraints(),
        // );

        assert!(cs.is_satisfied().unwrap());
    }
}
