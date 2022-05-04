use crate::gadgets::*;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result};
use falcon_rust::*;

#[derive(Clone, Debug)]
pub struct FalconNTTVerificationCircuit {
    pk: PublicKey,
    msg: Vec<u8>,
    sig: Signature,
}

impl FalconNTTVerificationCircuit {
    pub fn build_circuit(pk: PublicKey, msg: Vec<u8>, sig: Signature) -> Self {
        Self { pk, msg, sig }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for FalconNTTVerificationCircuit {
    /// generate a circuit proving that for a given tuple: pk, msg, sig
    /// the following statement holds
    /// - hm = hash_message(message, nonce)     <- done in public
    /// - v = hm - sig * pk
    /// - l2_norm(sig, v) < SIG_L2_BOUND = 34034726
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()> {
        let sig_poly: Polynomial = (&self.sig).into();
        let pk_poly: Polynomial = (&self.pk).into();

        // the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
        let const_q_power_vars: Vec<FpVar<F>> = (1..LOG_N + 2)
            .map(|x| {
                FpVar::<F>::new_constant(
                    cs.clone(),
                    F::from(1u32 << (x - 1)) * F::from(MODULUS).pow(&[x as u64]),
                )
                .unwrap()
            })
            .collect();
        let param_vars = ntt_param_var(cs.clone()).unwrap();
        // ========================================
        // compute related data in the clear
        // ========================================
        let hm = Polynomial::from_hash_of_message(self.msg.as_ref(), self.sig.nonce());
        let hm_ntt = NTTPolynomial::from(&hm);

        // compute v = hm - uh and lift it to positives
        let uh = sig_poly * pk_poly;
        let v = hm - uh;

        let pk_ntt = NTTPolynomial::from(&pk_poly);

        // ========================================
        // allocate the variables with range checks
        // ========================================
        // signature, over Z
        //  a private input to the circuit; a range proof will be done later
        let sig_poly_vars =
            PolyVar::<F>::alloc_vars(cs.clone(), &sig_poly, AllocationMode::Witness)?;

        // pk, in NTT domain
        //  a public input to the circuit; do not need range proof
        let pk_ntt_vars = NTTPolyVar::<F>::alloc_vars(cs.clone(), &pk_ntt, AllocationMode::Input)?;

        // hash of message, in NTT domain
        //  also a public input; do not need range proof
        let hm_ntt_vars = NTTPolyVar::<F>::alloc_vars(cs.clone(), &hm_ntt, AllocationMode::Input)?;

        // v := hm - sig * pk, over Z
        //  a private input to the circuit; require a range proof
        let v_vars = PolyVar::<F>::alloc_vars(cs.clone(), &v, AllocationMode::Witness)?;

        for e in v_vars.coeff() {
            // ensure all the v inputs are smaller than MODULUS
            // v will need to be kept secret
            enforce_less_than_q(cs.clone(), &e)?;
        }
        // ========================================
        // proving v = hm + sig * pk mod MODULUS
        // ========================================
        // we are proving the polynomial congruence via NTT.
        //

        // first, prove that the circuit variable are indeed the
        // NTT representation of the polynomial
        //  sig_ntt_vars = ntt_circuit(sig_vars)
        //  v_ntt_vars = ntt_circuit(v_vars)
        let sig_ntt_vars =
            NTTPolyVar::ntt_circuit(cs.clone(), &sig_poly_vars, &const_q_power_vars, &param_vars)?;
        let v_ntt_vars =
            NTTPolyVar::ntt_circuit(cs.clone(), &v_vars, &const_q_power_vars, &param_vars)?;

        // second, prove the equation holds in the ntt domain
        for i in 0..N {
            // hm[i] = v[i] + sig[i] * pk[i] % MODULUS

            // println!(
            //     "{:?} {:?} {:?} {:?}",
            //     v_ntt_vars[i].value()?.into_repr(),
            //     hm_ntt_vars[i].value()?.into_repr(),
            //     sig_ntt_vars[i].value()?.into_repr(),
            //     pk_ntt_vars[i].value()?.into_repr(),
            // );

            hm_ntt_vars.coeff()[i].enforce_equal(&add_mod(
                cs.clone(),
                &v_ntt_vars.coeff()[i],
                &(&sig_ntt_vars.coeff()[i] * &pk_ntt_vars.coeff()[i]),
                &const_q_power_vars[0],
            )?)?;
        }

        // ========================================
        // proving l2_norm(v | sig) < 34034726
        // ========================================
        let l2_norm_var = l2_norm_var(
            cs.clone(),
            &[v_vars.coeff(), sig_poly_vars.coeff()].concat(),
            &const_q_power_vars[0],
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
    fn test_ntt_verification_r1cs() {
        let keypair = KeyPair::keygen();
        let message = "testing message".as_bytes();
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());

        assert!(keypair.public_key.verify(message.as_ref(), &sig));
        assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));

        let cs = ConstraintSystem::<Fq>::new_ref();

        let falcon_circuit = FalconNTTVerificationCircuit {
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
