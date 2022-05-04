use ark_ff::PrimeField;
use falcon_rust::MODULUS;
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use num_bigint::BigUint;

use super::enforce_less_than_q;

/// Generate the variable b = a mod 12289;
pub fn mod_q<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
    modulus_var: &Variable,
) -> Result<Variable, PlonkError> {
    // we want to prove that `b = a mod 12289`
    // that is
    // (1) a - t * 12289 = b
    // for some unknown t, with
    // (2) b < 12289
    //
    // Note that this implementation assumes the
    // native field's order is greater than 12289^2
    // so we do not have any overflows

    // rebuild the field elements
    let a_val = cs.witness(*a)?;

    let a_int: BigUint = a_val.into();

    let modulus_int: BigUint = F::from(MODULUS).into();
    let t_int = &a_int / &modulus_int;
    let b_int = &a_int % &modulus_int;

    let t_val = F::from(t_int);
    let b_val = F::from(b_int);

    // cast the variables
    let t_var = cs.create_variable(t_val)?;
    let b_var = cs.create_variable(b_val)?;

    // (1) a - t * 12289 = c
    let t_12289 = t_var * modulus_var;
    let left = a - t_12289;
    cs.equal_gate(left, b_var)?;

    // (2) c < 12289
    enforce_less_than_q(cs, &b_var)?;

    Ok(b_var)
}
