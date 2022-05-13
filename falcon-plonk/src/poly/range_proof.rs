use ark_ff::PrimeField;
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};

/// Constraint that the witness of a is smaller than 12289
/// Cost: 75 constraints.
pub fn enforce_less_than_q<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
) -> Result<(), PlonkError> {
    #[cfg(feature = "print-trace")]
    let cs_count = cs.num_gates();
    // we want to decompose a input a into the following format
    // a = a_13*2^13 + a_12*2^12 + a_11*2^11 + ... + a_0 *2^0
    // where
    //  - a_0 ... a_13 are binary

    // a_bit_vars is the least 14 bits of a
    // (we only care for the first 14 bits of a_bits)
    let a_bit_vars = cs.unpack(*a, 14)?;

    // argue that a < MODULUS = 2^13 + 2^12 + 1 via enforcing one of the following
    // branch 1: a[13]
    // if a[13] == 0, terminate
    let branch_1_pos = cs.check_equal(a_bit_vars[13], cs.zero())?;
    // if a[13] != 0, branch 2: a[12]
    // if a[12] == 0, terminate
    let branch_2_pos = cs.check_equal(a_bit_vars[12], cs.zero())?;
    // if a[12] != 0, branch 3: a[1-11] == 0
    let mut tmp = vec![];
    for i in 0..12 {
        tmp.push(cs.check_equal(a_bit_vars[i], cs.zero())?);
    }
    let branch_3_pos = cs.logic_and_all(tmp.as_ref())?;
    let res = cs.logic_or(branch_1_pos, branch_2_pos)?;
    let res = cs.logic_or(res, branch_3_pos)?;
    cs.enforce_true(res)?;

    #[cfg(feature = "print-trace")]
    println!(
        "enforce less than q {}  total {}",
        cs.num_gates() - cs_count,
        cs.num_gates()
    );

    Ok(())
}

/// Constraint that the witness of a is smaller than 765
/// Cost: 4 constraints.
pub fn enforce_leq_765<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
) -> Result<(), PlonkError> {
    #[cfg(feature = "print-trace")]
    let cs_count = cs.num_gates();

    if cs.range_bit_len()? != 8 {
        return Err(PlonkError::InvalidParameters(format!(
            "range bit len {} is not 8",
            cs.range_bit_len()?
        )));
    }

    // decompose a = a1 + a2 + a3 ensure a1, a2, a3 <= 255
    let a_val = cs.witness(*a)?;
    let a_int: F::BigInt = a_val.into();
    let a_u64 = a_int.as_ref()[0];
    let (a1, a2, a3) = {
        if a_u64 > 510 {
            (255, 255, a_u64 - 510)
        } else if a_u64 > 255 {
            (255, a_u64 - 255, 0)
        } else {
            (a_u64, 0, 0)
        }
    };
    let a1_var = cs.create_variable(F::from(a1))?;
    let a2_var = cs.create_variable(F::from(a2))?;
    let a3_var = cs.create_variable(F::from(a3))?;

    // ensure a1, a2, a3 <= 256
    cs.range_gate(a1_var, 8)?;
    cs.range_gate(a2_var, 8)?;
    cs.range_gate(a3_var, 8)?;

    // ensure a = a1 + a2 + a3
    let wires = [a1_var, a2_var, a3_var, cs.zero(), *a];
    let coeffs = [F::one(); 4];
    let res = cs.lc_gate(&wires, &coeffs);

    #[cfg(feature = "print-trace")]
    println!(
        "enforce leq 765 {};  total {}",
        cs.num_gates() - cs_count,
        cs.num_gates()
    );
    res
}

// compute the l2 norm of polynomial a where a's coefficients
// are positive between [0, 12289).
// We need to firstly lift it to [-6144, 6144) and then
// compute the norm.
pub fn l2_norm_var<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &[Variable],
) -> Result<Variable, PlonkError> {
    // let mut res = FpVar::<F>::conditionally_select(
    //     &is_less_than_6144(cs.clone(), &input[0])?,
    //     &input[0],
    //     &(modulus_var - &input[0]),
    // )?;
    // res = &res * &res;
    // for e in input.iter().skip(1) {
    //     let tmp = FpVar::<F>::conditionally_select(
    //         &is_less_than_6144(cs.clone(), e)?,
    //         e,
    //         &(modulus_var - e),
    //     )?;
    //     res += &tmp * &tmp
    // }
    todo!()
    // Ok(res)
}

pub fn enforce_less_than_norm_bound<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
) -> Result<(), PlonkError> {
    #[cfg(feature = "falcon-512")]
    enforce_less_than_norm_bound_512(cs, a)?;
    #[cfg(feature = "falcon-1024")]
    enforce_less_than_norm_bound_1024(cs, a)?;

    Ok(())
}

/// Constraint that the witness of a is smaller than 34034726
/// Cost: XX constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)    
#[cfg(feature = "falcon-1024")]
fn enforce_less_than_norm_bound_1024<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
) -> Result<(), PlonkError> {
    // 34034726 = 2 * (2^8)^3 + 7 * (2^8)^2 + 84 * 2^8 + 38

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_std::{rand::Rng, test_rng};
    use falcon_rust::MODULUS;

    const REPEAT: usize = 100;

    macro_rules! enforce_leq_765 {
        ($value: expr, $satisfied: expr) => {
            let mut cs = PlonkCircuit::new_ultra_plonk(8);
            let a = Fq::from($value);
            let a_var = cs.create_variable(a)?;

            enforce_leq_765(&mut cs, &a_var).unwrap();
            if $satisfied {
                assert!(cs.check_circuit_satisfiability(&[]).is_ok());
            } else {
                assert!(cs.check_circuit_satisfiability(&[]).is_err());
            }

            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );
        };
    }
    #[test]
    fn test_enforce_leq_765() -> Result<(), PlonkError> {
        // =======================
        // good path
        // =======================
        // the meaning of life
        enforce_leq_765!(42, true);

        // edge case: 0
        enforce_leq_765!(0, true);

        // edge case: 764
        enforce_leq_765!(764, true);

        // edge case: 765
        enforce_leq_765!(765, true);

        // =======================
        // bad path
        // =======================
        // edge case: 766
        enforce_leq_765!(766, false);

        // edge case: 767
        enforce_leq_765!(767, false);

        // edge case: 12289
        enforce_leq_765!(MODULUS, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..REPEAT {
            let t = rng.gen_range(0..2048) as u64;
            enforce_leq_765!(t, t <= 765);
        }
        Ok(())
    }

    macro_rules! enforce_less_than_q {
        ($value: expr, $satisfied: expr) => {
            let mut cs = PlonkCircuit::new_ultra_plonk(8);
            let a = Fq::from($value);
            let a_var = cs.create_variable(a)?;

            enforce_less_than_q(&mut cs, &a_var).unwrap();
            if $satisfied {
                assert!(cs.check_circuit_satisfiability(&[]).is_ok());
            } else {
                assert!(cs.check_circuit_satisfiability(&[]).is_err());
            }

            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );
        };
    }
    #[test]
    fn test_enforce_less_than_q() -> Result<(), PlonkError> {
        // =======================
        // good path
        // =======================
        // the meaning of life
        enforce_less_than_q!(42, true);

        // edge case: 0
        enforce_less_than_q!(0, true);

        // edge case: 12287
        enforce_less_than_q!(12287, true);

        // edge case: 12288
        enforce_less_than_q!(12288, true);

        // =======================
        // bad path
        // =======================
        // edge case: 12289
        enforce_less_than_q!(12289, false);

        // edge case: 12290
        enforce_less_than_q!(12290, false);

        // edge case: 12289
        enforce_less_than_q!(MODULUS, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..REPEAT {
            let t = rng.gen_range(0..1 << 14) as u64;
            enforce_less_than_q!(t, t < MODULUS as u64);
        }
        Ok(())
    }
}
