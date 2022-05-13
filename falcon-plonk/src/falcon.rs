use ark_ff::PrimeField;
use falcon_rust::{NTTPolynomial, Polynomial, PublicKey, Signature, LOG_N, MODULUS, N};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit},
    errors::PlonkError,
};

use crate::poly::{
    enforce_less_than_norm_bound, enforce_less_than_q, l2_norm_var, mod_q, NTTPolyVar, PolyVar,
};

#[derive(Clone, Debug)]
pub struct FalconNTTVerificationWitness {
    pk: PublicKey,
    msg: Vec<u8>,
    sig: Signature,
}

impl FalconNTTVerificationWitness {
    pub fn build_witness(pk: PublicKey, msg: Vec<u8>, sig: Signature) -> Self {
        Self { pk, msg, sig }
    }

    pub fn verification_circuit<F: PrimeField>(
        &self,
        cs: &mut PlonkCircuit<F>,
    ) -> Result<(), PlonkError> {
        #[cfg(feature = "print-trace")]
        let cs_count = cs.num_gates();

        let sig_poly: Polynomial = (&self.sig).into();
        let pk_poly: Polynomial = (&self.pk).into();

        // the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
        let const_q_power: Vec<F> = (1..LOG_N + 2)
            .map(|x| F::from(1u32 << (x - 1)) * F::from(MODULUS).pow(&[x as u64]))
            .collect();

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
        let sig_poly_vars = PolyVar::<F>::alloc_vars(cs, &sig_poly)?;

        // pk, in NTT domain
        //  a public input to the circuit; do not need range proof
        let pk_ntt_vars = NTTPolyVar::<F>::alloc_public_vars(cs, &pk_ntt)?;

        // hash of message, in NTT domain
        //  also a public input; do not need range proof
        let hm_ntt_vars = NTTPolyVar::<F>::alloc_public_vars(cs, &hm_ntt)?;

        // v := hm - sig * pk, over Z
        //  a private input to the circuit; require a range proof
        let v_vars = PolyVar::alloc_vars(cs, &v)?;

        for e in v_vars.coeff() {
            // ensure all the v inputs are smaller than MODULUS
            // v will need to be kept secret
            enforce_less_than_q(cs, &e)?;
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
        let sig_ntt_vars = NTTPolyVar::ntt_circuit(cs, &sig_poly_vars, &const_q_power)?;
        let v_ntt_vars = NTTPolyVar::ntt_circuit(cs, &v_vars, &const_q_power)?;

        // second, prove the equation holds in the ntt domain
        for i in 0..N {
            // if i < 5 {
            //     println!("{} {}", i, cs.num_gates());
            //     println!(
            //         "{:?} {:?} {:?} {:?}",
            //         cs.witness(v_ntt_vars.coeff()[i])?.into_repr(),
            //         cs.witness(hm_ntt_vars.coeff()[i])?.into_repr(),
            //         cs.witness(sig_ntt_vars.coeff()[i])?.into_repr(),
            //         cs.witness(pk_ntt_vars.coeff()[i])?.into_repr(),
            //     );
            // }

            // hm[i] = v[i] + sig[i] * pk[i] % MODULUS
            let wires = [
                sig_ntt_vars.coeff()[i],
                pk_ntt_vars.coeff()[i],
                v_ntt_vars.coeff()[i],
                cs.one(),
            ];
            let coeffs = [F::one(), F::one()];
            let right = cs.mul_add(&wires, &coeffs)?;
            let right = mod_q(cs, &right, MODULUS)?;
            cs.equal_gate(hm_ntt_vars.coeff()[i], right)?;
        }

        // ========================================
        // proving l2_norm(v | sig) < 34034726
        // ========================================
        let l2_norm_var = l2_norm_var(cs, &[v_vars.coeff(), sig_poly_vars.coeff()].concat())?;

        enforce_less_than_norm_bound(cs, &l2_norm_var)?;

        #[cfg(feature = "print-trace")]
        println!(
            "falcon verification circuit {};  total {}",
            cs.num_gates() - cs_count,
            cs.num_gates()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use falcon_rust::KeyPair;

    const REPEAT: usize = 10;

    #[test]
    fn test_ntt_verification_r1cs() -> Result<(), PlonkError> {
        for _ in 0..REPEAT {
            let keypair = KeyPair::keygen();
            let message = "testing message".as_bytes();
            let sig = keypair
                .secret_key
                .sign_with_seed("test seed".as_ref(), message.as_ref());

            assert!(keypair.public_key.verify(message.as_ref(), &sig));
            assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));

            let mut cs = PlonkCircuit::<Fq>::new_ultra_plonk(8);

            let falcon_witness = FalconNTTVerificationWitness {
                pk: keypair.public_key,
                msg: message.to_vec(),
                sig,
            };

            falcon_witness.verification_circuit(&mut cs)?;
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );

            // build the public inputs
            let mut public_inputs = vec![];
            // pk
            let pk_poly: Polynomial = (&keypair.public_key).into();
            let pk_ntt = NTTPolynomial::from(&pk_poly);
            for &e in pk_ntt.coeff() {
                public_inputs.push(Fq::from(e));
            }
            // hm
            let hm = Polynomial::from_hash_of_message(message.as_ref(), sig.nonce());
            let hm_ntt = NTTPolynomial::from(&hm);
            for &e in hm_ntt.coeff() {
                public_inputs.push(Fq::from(e));
            }

            assert!(cs.check_circuit_satisfiability(&public_inputs).is_ok());
        }
        Ok(())
    }
}
