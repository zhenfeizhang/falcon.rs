use ark_ff::PrimeField;
use falcon_rust::N;
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};

use super::DualPolyVar;

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

    // ensure a1, a2, a3 < 256
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

// /// Return a boolean variable indicating if a < 1020
// pub fn is_less_than_1020<F: PrimeField>(
//     cs: &mut PlonkCircuit<F>,
//     a: &Variable,
// ) -> Result<Variable, PlonkError> {
//     #[cfg(feature = "print-trace")]
//     let cs_count = cs.num_gates();

//     if cs.range_bit_len()? != 8 {
//         return Err(PlonkError::InvalidParameters(format!(
//             "range bit len {} is not 8",
//             cs.range_bit_len()?
//         )));
//     }

//     // decompose a = a1 + a2 + a3 + a4
//     // ensure a1, a2, a3, a4 <= 255
//     let a_val = cs.witness(*a)?;
//     let a_int: F::BigInt = a_val.into();
//     let a_u64 = a_int.as_ref()[0];
//     let (a1, a2, a3, a4) = {
//         if a_u64 > 765 {
//             (255, 255, 255, a_u64 - 765)
//         } else if a_u64 > 510 {
//             (255, 255, a_u64 - 510, 0)
//         } else if a_u64 > 255 {
//             (255, a_u64 - 255, 0, 0)
//         } else {
//             (a_u64, 0, 0, 0)
//         }
//     };
//     let a1_var = cs.create_variable(F::from(a1))?;
//     let a2_var = cs.create_variable(F::from(a2))?;
//     let a3_var = cs.create_variable(F::from(a3))?;
//     let a4_var = cs.create_variable(F::from(a4))?;

//     // // check a1, a2, a3, a4 < 256
//     let a1_check = cs.check_in_range(a1_var, 8)?;
//     // let a2_check = cs.check_in_range(a2_var, 8)?;
//     // let a3_check = cs.check_in_range(a3_var, 8)?;
//     // let a4_check = cs.check_in_range(a4_var, 8)?;

//     // check a = a1 + a2 + a3 + a4
//     let wires = [a1_var, a2_var, a3_var, a4_var];
//     let coeffs = [F::one(); 4];
//     let a_rec = cs.lc(&wires, &coeffs)?;
//     let eq_check = cs.check_equal(*a, a_rec)?;

//     // // return a1_check and a2_check ... and eq_check
//     // let res = cs.logic_and_all([a1_check, a2_check, a3_check, a4_check,
// eq_check].as_ref())?;     let res = eq_check;

//     #[cfg(feature = "print-trace")]
//     println!(
//         "is less then 1024: {};  total {}",
//         cs.num_gates() - cs_count,
//         cs.num_gates()
//     );
//     Ok(res)
// }

// compute the l2 norm of polynomial a where a's coefficients
// are positive between [0, 12289).
// This is applied over the `DualPolynomial` so we don't really
// need to care for the signs.
pub fn l2_norm_var<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    u: &DualPolyVar<F>,
    v: &DualPolyVar<F>,
) -> Result<Variable, PlonkError> {
    let mut t = vec![];
    for i in 0..N / 2 {
        let coeffs = [F::one(), F::one()];

        // t1 = u.pos[2i]^2 + u.pos[2i+1]^2
        {
            let wires = [
                u.pos.coeff()[2 * i],
                u.pos.coeff()[2 * i],
                u.pos.coeff()[2 * i + 1],
                u.pos.coeff()[2 * i + 1],
            ];
            let t1 = cs.mul_add(&wires, &coeffs)?;
            t.push(t1);
        }

        // t2 = u.neg[2i]^2 + u.neg[2i+1]^2
        {
            let wires = [
                u.neg.coeff()[2 * i],
                u.neg.coeff()[2 * i],
                u.neg.coeff()[2 * i + 1],
                u.neg.coeff()[2 * i + 1],
            ];
            let t2 = cs.mul_add(&wires, &coeffs)?;
            t.push(t2);
        }

        // t3 = v.pos[2i]^2 + v.pos[2i+1]^2
        {
            let wires = [
                v.pos.coeff()[2 * i],
                v.pos.coeff()[2 * i],
                v.pos.coeff()[2 * i + 1],
                v.pos.coeff()[2 * i + 1],
            ];
            let t3 = cs.mul_add(&wires, &coeffs)?;
            t.push(t3);
        }

        // t4 = v.neg[2i]^2 + v.neg[2i+1]^2
        {
            let wires = [
                v.neg.coeff()[2 * i],
                v.neg.coeff()[2 * i],
                v.neg.coeff()[2 * i + 1],
                v.neg.coeff()[2 * i + 1],
            ];
            let t4 = cs.mul_add(&wires, &coeffs)?;
            t.push(t4);
        }
    }

    let wires = [t[0], t[1], t[2], t[3]];
    let coeffs = [F::one(), F::one(), F::one(), F::one()];
    let mut res = cs.lc(&wires, &coeffs)?;

    for e in t[4..].chunks(3) {
        let wires = if e.len() == 3 {
            [res, e[0], e[1], e[2]]
        } else {
            [res, e[0], cs.zero(), cs.zero()]
        };

        res = cs.lc(&wires, &coeffs)?;
    }

    Ok(res)
}

// pub fn enforce_less_than_norm_bound<F: PrimeField>(
//     cs: &mut PlonkCircuit<F>,
//     a: &Variable,
// ) -> Result<(), PlonkError> {
//     #[cfg(feature = "falcon-512")]
//     enforce_less_than_norm_bound_512(cs, a)?;
//     #[cfg(feature = "falcon-1024")]
//     enforce_less_than_norm_bound_1024(cs, a)?;

//     Ok(())
// }

// /// Constraint that the witness of a is smaller than 34034726
// /// Cost: XX constraints.
// /// (This improves the range proof of 1264 constraints as in Arkworks.)
// #[cfg(feature = "falcon-1024")]
// fn enforce_less_than_norm_bound_1024<F: PrimeField>(
//     cs: &mut PlonkCircuit<F>,
//     a: &Variable,
// ) -> Result<(), PlonkError> {
//     // 34034726 = 2 * (2^8)^3 + 7 * (2^8)^2 + 84 * 2^8 + 38

//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_ff::Zero;
    use ark_std::{rand::Rng, test_rng};
    use falcon_rust::{DualPolynomial, Polynomial, MODULUS};

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

    // macro_rules! is_leq_1020 {
    //     ($value: expr, $satisfied: expr) => {
    //         let mut cs = PlonkCircuit::new_ultra_plonk(8);
    //         let a = Fq::from($value);
    //         let a_var = cs.create_variable(a)?;

    //         let res = is_less_than_1020(&mut cs, &a_var).unwrap();
    //         assert_eq!(cs.witness(res)?, Fq::from($satisfied as u64));

    //         // println!(
    //         //     "number of variables {} {} and constraints {}\n",
    //         //     cs.num_instance_variables(),
    //         //     cs.num_witness_variables(),
    //         //     cs.num_constraints(),
    //         // );
    //     };
    // }
    // #[test]
    // fn test_is_leq_1020() -> Result<(), PlonkError> {
    //     // =======================
    //     // good path
    //     // =======================
    //     // the meaning of life
    //     is_leq_1020!(42, true);

    //     // edge case: 0
    //     is_leq_1020!(0, true);

    //     // edge case: 1019
    //     is_leq_1020!(1019, true);

    //     // edge case: 1020
    //     is_leq_1020!(1020, true);

    //     // =======================
    //     // bad path
    //     // =======================
    //     // edge case: 1021
    //     is_leq_1020!(1021, false);

    //     // edge case: 1022
    //     is_leq_1020!(1022, false);

    //     // edge case: 12289
    //     is_leq_1020!(MODULUS, false);

    //     // =======================
    //     // random path
    //     // =======================
    //     let mut rng = test_rng();
    //     for _ in 0..REPEAT {
    //         let t = rng.gen_range(0..2048) as u64;
    //         is_leq_1020!(t, t <= 1020);
    //     }
    //     Ok(())
    // }

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

    #[test]
    fn test_l2_norm() -> Result<(), PlonkError> {
        let mut rng = test_rng();

        let mut cs = PlonkCircuit::<Fq>::new_ultra_plonk(8);

        let u = Polynomial::rand(&mut rng);
        let v = Polynomial::rand(&mut rng);

        let dual_u = DualPolynomial::from(&u);
        let dual_v = DualPolynomial::from(&v);

        let u_var = DualPolyVar::alloc_vars(&mut cs, &dual_u)?;
        let v_var = DualPolyVar::alloc_vars(&mut cs, &dual_v)?;

        let norm_var = l2_norm_var(&mut cs, &u_var, &v_var)?;
        let norm = cs.witness(norm_var)?;

        let mut norm_clear = Fq::zero();
        for &e in dual_u.pos.coeff().iter() {
            let tmp = Fq::from(e);
            norm_clear += tmp * tmp
        }
        for &e in dual_u.neg.coeff().iter() {
            let tmp = Fq::from(e);
            norm_clear += tmp * tmp
        }
        for &e in dual_v.pos.coeff().iter() {
            let tmp = Fq::from(e);
            norm_clear += tmp * tmp
        }
        for &e in dual_v.neg.coeff().iter() {
            let tmp = Fq::from(e);
            norm_clear += tmp * tmp
        }

        assert_eq!(norm, norm_clear);

        Ok(())
    }
}
