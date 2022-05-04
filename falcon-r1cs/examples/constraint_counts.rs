use ark_ed_on_bls12_381::fq::Fq;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, Field};
use ark_std::test_rng;
use falcon_r1cs::*;
use falcon_rust::*;

fn main() {
    println!("                  # instance variables |      # witness |      #constraints |");
    count_ntt_conversion_constraints();
    count_verify_with_ntt_constraints();
    count_verify_with_dual_ntt_constraints();
    count_verify_with_schoolbook_constraints();
}

fn count_verify_with_schoolbook_constraints() {
    let keypair = KeyPair::keygen();
    let message = "testing message".as_bytes();
    let sig = keypair
        .secret_key
        .sign_with_seed("test seed".as_ref(), message.as_ref());

    assert!(keypair.public_key.verify(message.as_ref(), &sig));
    assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));

    let cs = ConstraintSystem::<Fq>::new_ref();

    let falcon_circuit = FalconSchoolBookVerificationCircuit::build_circuit(
        keypair.public_key,
        message.to_vec(),
        sig,
    );

    falcon_circuit.generate_constraints(cs.clone()).unwrap();
    println!(
        "verify with schoolbook:       {:8} |       {:8} |          {:8} |",
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
}

fn count_verify_with_ntt_constraints() {
    let keypair = KeyPair::keygen();
    let message = "testing message".as_bytes();
    let sig = keypair
        .secret_key
        .sign_with_seed("test seed".as_ref(), message.as_ref());

    assert!(keypair.public_key.verify(message.as_ref(), &sig));
    assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));

    let cs = ConstraintSystem::<Fq>::new_ref();

    let falcon_circuit =
        FalconNTTVerificationCircuit::build_circuit(keypair.public_key, message.to_vec(), sig);
    falcon_circuit.generate_constraints(cs.clone()).unwrap();
    println!(
        "verify with ntt:              {:8} |       {:8} |          {:8} |",
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
}

fn count_ntt_conversion_constraints() {
    let mut rng = test_rng();

    let cs = ConstraintSystem::<Fq>::new_ref();
    let param_var = ntt_param_var(cs.clone()).unwrap();
    let poly = Polynomial::rand(&mut rng);
    let poly_var = PolyVar::<Fq>::alloc_vars(cs.clone(), &poly, AllocationMode::Witness).unwrap();

    // the [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10] constant wires
    let const_mod_q_vars: Vec<FpVar<Fq>> = (1..LOG_N + 2)
        .map(|x| {
            FpVar::<Fq>::new_constant(
                cs.clone(),
                Fq::from(1 << (x - 1)) * Fq::from(MODULUS).pow(&[x as u64]),
            )
            .unwrap()
        })
        .collect();
    let output = NTTPolynomial::from(&poly);

    let num_instance_variables = cs.num_instance_variables();
    let num_witness_variables = cs.num_witness_variables();
    let num_constraints = cs.num_constraints();

    let output_var =
        NTTPolyVar::ntt_circuit(cs.clone(), &poly_var, &const_mod_q_vars, &param_var).unwrap();
    println!(
        "ntt conversion:               {:8} |       {:8} |          {:8} |",
        cs.num_instance_variables() - num_instance_variables,
        cs.num_witness_variables() - num_witness_variables,
        cs.num_constraints() - num_constraints,
    );

    for i in 0..N {
        assert_eq!(
            Fq::from(output.coeff()[i]),
            output_var.coeff()[i].value().unwrap()
        )
    }
}

fn count_verify_with_dual_ntt_constraints() {
    let keypair = KeyPair::keygen();
    let message = "testing message".as_bytes();
    let sig = keypair
        .secret_key
        .sign_with_seed("test seed".as_ref(), message.as_ref());

    assert!(keypair.public_key.verify(message.as_ref(), &sig));
    assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));

    let cs = ConstraintSystem::<Fq>::new_ref();

    let falcon_circuit =
        FalconDualNTTVerificationCircuit::build_circuit(keypair.public_key, message.to_vec(), sig);
    falcon_circuit.generate_constraints(cs.clone()).unwrap();
    println!(
        "verify with dual ntt:         {:8} |       {:8} |          {:8} |",
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    );

    assert!(cs.is_satisfied().unwrap());
}
