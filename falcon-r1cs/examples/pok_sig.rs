//! This example generates a proof of knowledge of the secret key

use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{create_random_proof, verify_proof, Groth16, PreparedVerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use falcon_r1cs::FalconNTTVerificationCircuit;
use falcon_rust::{KeyPair, NTTPolynomial, Polynomial};
use rand_chacha::ChaCha20Rng;

fn main() {
    // generate the public key, message and the signature
    let mut rng = ChaCha20Rng::from_seed([0; 32]);

    let keypair = KeyPair::keygen();

    let msg = "testing message";
    let sig = keypair
        .secret_key
        .sign_with_seed("test seed".as_ref(), msg.as_ref());
    assert!(keypair.public_key.verify(msg.as_ref(), &sig));

    // build the circuit
    let cs_input = FalconNTTVerificationCircuit::build_circuit(
        keypair.public_key,
        msg.as_bytes().to_vec(),
        sig,
    );

    let (pp, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(cs_input.clone(), &mut rng).unwrap();
    let proof = create_random_proof(cs_input, &pp, &mut rng).unwrap();
    let pk = Polynomial::from(&(keypair.public_key));
    let pk_ntt = NTTPolynomial::from(&pk);
    let hm = Polynomial::from_hash_of_message(msg.as_ref(), sig.nonce());
    let hm_ntt = NTTPolynomial::from(&hm);

    let mut public_inputs = Vec::new();
    for e in pk_ntt.coeff() {
        public_inputs.push(Fr::from(*e))
    }
    for e in hm_ntt.coeff() {
        public_inputs.push(Fr::from(*e))
    }
    let pvk = PreparedVerifyingKey::from(vk.clone());

    assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap())
}
