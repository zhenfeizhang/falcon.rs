use ark_ff::PrimeField;
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};
use num_bigint::BigUint;

use super::enforce_less_than_q;

/// Generate the variable b = a mod 12289;
/// Cost: 76 constraints
pub fn mod_q<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
    modulus: u16,
) -> Result<Variable, PlonkError> {
    #[cfg(feature = "print-trace")]
    let cs_count = cs.num_gates();

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

    let modulus_int: BigUint = F::from(modulus).into();
    let t_int = &a_int / &modulus_int;
    let b_int = &a_int % &modulus_int;

    let t_val = F::from(t_int);
    let b_val = F::from(b_int);

    // cast the variables
    let t_var = cs.create_variable(t_val)?;
    let b_var = cs.create_variable(b_val)?;

    // (1) a - t * 12289 = c
    let wires = [*a, t_var, 0, 0, b_var];
    let coeffs = [F::one(), -F::from(modulus), F::zero(), F::zero()];
    cs.lc_gate(&wires, &coeffs)?;

    // (2) c < 12289
    enforce_less_than_q(cs, &b_var)?;

    #[cfg(feature = "print-trace")]
    println!(
        "mod q {};  total {}",
        cs.num_gates() - cs_count,
        cs.num_gates()
    );
    Ok(b_var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_std::{rand::Rng, test_rng};
    use falcon_rust::MODULUS;
    const REPEAT: usize = 100;

    macro_rules! test_mod_q {
        ($a:expr, $b:expr, $satisfied:expr) => {
            let mut cs = PlonkCircuit::new_ultra_plonk(8);
            let a = Fq::from($a);
            let b = Fq::from($b);

            let a_var = cs.create_variable(a)?;
            let b_var = mod_q(&mut cs, &a_var, MODULUS)?;
            let b_var2 = cs.create_variable(b)?;
            cs.equal_gate(b_var, b_var2)?;
            if $satisfied {
                assert!(cs.check_circuit_satisfiability(&[]).is_ok());
            } else {
                assert!(cs.check_circuit_satisfiability(&[]).is_err());
            }

            assert_eq!(cs.witness(b_var)? == b, $satisfied);
        };
    }

    #[test]
    fn test_mod_q() -> Result<(), PlonkError> {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_mod_q!(42, 42, true);

        // edge case: 0
        test_mod_q!(0, 0, true);
        test_mod_q!(MODULUS, 0, true);

        // edge case: wraparound
        test_mod_q!(MODULUS + 1, 1, true);

        // =======================
        // bad path
        // =======================
        // wrong value
        test_mod_q!(6, 7, false);
        test_mod_q!(5, MODULUS - 1, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..REPEAT {
            let t = rng.gen_range(0..1 << 30);

            test_mod_q!(t, t % MODULUS as u32, true);
            test_mod_q!(t, (t + 1) % MODULUS as u32, false);
        }
        Ok(())
    }
}
