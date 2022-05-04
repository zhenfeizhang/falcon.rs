use super::*;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
#[cfg(not(test))]
use falcon_rust::MODULUS;
#[cfg(not(test))]
use falcon_rust::SIG_L2_BOUND;

/// Enforce the input is less than 1024 or not
/// Cost: 15 constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)
pub fn enforce_less_than_1024<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    // Note that the function returns a boolean and
    // the input a is allowed to be larger than 768

    let a_bits = a_val.into_repr().to_bits_le();
    // a_bit_vars is the least 10 bits of a
    // (we only care for the first 10 bits of a_bits)
    let a_bit_vars = a_bits
        .iter()
        .take(10)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    // ensure that a_bits are the bit decomposition of a
    enforce_decompose(a, a_bit_vars.as_ref())
}

/// Constraint that the witness of a is smaller than 12289
/// Cost: 28 constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)
pub(crate) fn enforce_less_than_q<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // if !cs.is_in_setup_mode(){
    // println!("< norm 12289 satisfied? {:?}", cs.is_satisfied());
    // }
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    // suppressing this check so that unit test can test
    // bad paths
    #[cfg(not(test))]
    if a_val >= F::from(MODULUS) {
        panic!("Invalid input: {}", a_val);
    }

    let a_bits = a_val.into_repr().to_bits_le();
    // a_bit_vars is the least 14 bits of a
    // (we only care for the first 14 bits of a_bits)
    let a_bit_vars = a_bits
        .iter()
        .take(14)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    // ensure that a_bits are the bit decomposition of a
    enforce_decompose(a, a_bit_vars.as_ref())?;

    // argue that a < MODULUS = 2^13 + 2^12 + 1 via enforcing one of the following
    // - either a[13] == 0, or
    // - a[13] == 1 and
    //      - either a[12] == 0
    //      - or a[12] == 1 and a[11] && a[10] && ... && a[0] == 0

    // a[13] == 0
    (a_bit_vars[13].is_eq(&Boolean::FALSE)?)
        .or(
            // a[12] == 0
            &a_bit_vars[12].is_eq(&Boolean::FALSE)?.or(
                // a[11] && ... && a[0] == 0
                &Boolean::kary_or(a_bit_vars[0..12].as_ref())?.is_eq(&Boolean::FALSE)?,
            )?,
        )?
        .enforce_equal(&Boolean::TRUE)?;
    // if !cs.is_in_setup_mode(){
    // println!("< norm 12289 satisfied? {:?}", cs.is_satisfied());
    // }
    Ok(())
}

/// Constraint that the witness of a is smaller than 34034726
/// Cost: 47 constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)    
#[cfg(feature = "falcon-512")]
fn enforce_less_than_norm_bound_512<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // the norm bound is 0b10000001110101010000100110 which is 26 bits, i.e.,
    // 2^25 + 2^18 + 2^17 + 2^16 + 2^14 + 2^ 12 + 2^10 + 2^5 + 2^2 + 2
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    // suppressing this check so that unit test can test
    // bad paths
    #[cfg(not(test))]
    if a_val >= F::from(SIG_L2_BOUND) {
        panic!("Invalid input: {}", a_val);
    }

    let a_bits = a_val.into_repr().to_bits_le();
    // a_bit_vars is the least 26 bits of a
    // (we only care for the first 26 bits of a_bits)
    let a_bit_vars = a_bits
        .iter()
        .take(26)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    // ensure that a_bits are the bit decomposition of a
    enforce_decompose(a, a_bit_vars.as_ref())?;

    // argue that a < 0b10000001110101010000100110  via the following:
    // - a[25] == 0 or
    // - a[25] == 1 and a[19..24] == 0 and
    //    - either one of a[16..18] == 0
    //    - or a[16..18] == 1 and a[15] == 0 and
    //      - either a[14] == 0
    //      - or a[14] == 1 and a[13] == 0 and
    //          - either a[12] == 0
    //          - or a[12] == 1 and a[11] == 0 and
    //              - either a[10] == 0
    //              - or a[10] == 1 and a[6-9] == 0 and
    //                  - either a[5] == 0
    //                  - or a[5] == 1 and a[3] = a [4] == 0 and
    //                      - one of a[1] or a[2] == 0

    #[rustfmt::skip]
    // a[25] == 0
    (a_bit_vars[25].is_eq(&Boolean::FALSE)?).or(
        // a[25] == 1 and a[19..24] == 0 and
        &Boolean::kary_or(a_bit_vars[19..25].as_ref())?.is_eq(&Boolean::FALSE)?.and(
            // - either one of a[16..18] == 0
            &Boolean::kary_and(a_bit_vars[16..19].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                // - or a[16..18] == 1 and a[15] == 0 and
                &a_bit_vars[15].is_eq(&Boolean::FALSE)?.and(
                    // - either a[14] == 0
                        &a_bit_vars[14].is_eq(&Boolean::FALSE)?.or(
                        // - or a[14] == 1 and a[13] == 0 and
                            &a_bit_vars[13].is_eq(&Boolean::FALSE)?.and(
                            // - either a[12] == 0
                                &a_bit_vars[12].is_eq(&Boolean::FALSE)?.or(
                                // - or a[12] == 1 and a[11] == 0 and   
                                    &a_bit_vars[11].is_eq(&Boolean::FALSE)?.and(
                                        // - either a[10] == 0
                                        &a_bit_vars[10].is_eq(&Boolean::FALSE)?.or(
                                            // - or a[10] == 1 and a[6-9] == 0 and
                                            &Boolean::kary_or(a_bit_vars[6..10].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                                // either a[5] == 0
                                                &a_bit_vars[5].is_eq(&Boolean::FALSE)?.or(
                                                    // - or a[5] == 1 and a[3] = a [4] == 0 and
                                                    &Boolean::kary_or(a_bit_vars[3..5].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                                        // - one of a[1] or a[2] == 0
                                                        &Boolean::kary_and(a_bit_vars[1..3].as_ref())?.is_eq(&Boolean::FALSE)?
                                                    )?
                                                )?
                                            )?
                                        )?
                                    )?
                                )?
                            )?
                        )?
                    )? 
                )?,
            )?,
        )?.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}

/// Constraint that the witness of a is smaller than 34034726
/// Cost: 54 constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)    
#[cfg(feature = "falcon-1024")]
fn enforce_less_than_norm_bound_1024<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    // the norm bound is 0b100001100000010100110011010 which is 26 bits, i.e.,
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    // suppressing this check so that unit test can test
    // bad paths
    #[cfg(not(test))]
    if a_val >= F::from(SIG_L2_BOUND) {
        panic!("Invalid input: {}", a_val);
    }

    let a_bits = a_val.into_repr().to_bits_le();
    // a_bit_vars is the least 26 bits of a
    // (we only care for the first 26 bits of a_bits)
    let a_bit_vars = a_bits
        .iter()
        .take(27)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    // ensure that a_bits are the bit decomposition of a
    enforce_decompose(a, a_bit_vars.as_ref())?;

    // argue that a < 0b100001100000010100110011010  via the following:
    // - a[26] == 0 or
    // - a[26] == 1 and a[22..25] == 0 and
    //    - either one of a[20..21] == 0
    //    - or a[20..21] == 1 and a[14..19] == 0 and
    //      - either a[13] == 0
    //      - or a[13] == 1 and a[12] == 0 and
    //          - either a[11] == 0
    //          - or a[11] == 1 and a[9..10] == 0 and
    //              - either one of a[7] or a[8] == 0
    //              - or, a[7] == a[8] == 1 and a[5] == a[6] == 0 and
    //                  - either a[4] or a[3] == 0 or
    //                  - or a[4] == a[3] == 1 and a[2] == a[1] == 0
    #[rustfmt::skip]
    // a[26] == 0
    (a_bit_vars[26].is_eq(&Boolean::FALSE)?).or(
        // a[26] == 1 and a[22..25] == 0 and
        &Boolean::kary_or(a_bit_vars[22..26].as_ref())?.is_eq(&Boolean::FALSE)?.and(
            // - either one of a[20..21] == 0
            &Boolean::kary_and(a_bit_vars[20..22].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                // - or a[20..21] == 0 and a[14..19] == 0
                &Boolean::kary_or(a_bit_vars[14..20].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                    // - either a[13] == 0
                    &a_bit_vars[13].is_eq(&Boolean::FALSE)?.or(
                        // - or a[13] == 1 and a[12] == 0 and
                        &a_bit_vars[12].is_eq(&Boolean::FALSE)?.and(
                            // - either a[11] == 0
                            &a_bit_vars[11].is_eq(&Boolean::FALSE)?.or(
                                // - or a[11] == 1 and a[9..10] == 0 and
                                &Boolean::kary_or(a_bit_vars[9..11].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                    // - either one of a[7] or a[8] == 0
                                    &Boolean::kary_and(a_bit_vars[7..9].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                                        // - or, a[7] == a[8] == 1 and a[5] == a[6] == 0 and
                                        &Boolean::kary_or(a_bit_vars[5..7].as_ref())?.is_eq(&Boolean::FALSE)?.and(
                                            // - either a[4] or a[3] == 0
                                            &Boolean::kary_and(a_bit_vars[3..5].as_ref())?.is_eq(&Boolean::FALSE)?.or(
                                                // and a[2] == a[1] == 0
                                                &Boolean::kary_or(a_bit_vars[1..3].as_ref())?.is_eq(&Boolean::FALSE)?
                                            )?
                                        )?
                                    )?
                                )?
                            )?
                        )?
                    )?
                )?
            )?,
        )?
    )?.enforce_equal(&Boolean::TRUE)?;
    Ok(())
}

pub fn enforce_less_than_norm_bound<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<(), SynthesisError> {
    #[cfg(feature = "falcon-512")]
    enforce_less_than_norm_bound_512(cs, a)?;
    #[cfg(feature = "falcon-1024")]
    enforce_less_than_norm_bound_1024(cs, a)?;

    Ok(())
}

/// Return a variable indicating if the input is less than 6144 or not
/// Cost: 18 constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)
pub(crate) fn is_less_than_6144<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    // println!("< norm 6144 satisfied? {:?}", cs.is_satisfied());

    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    // Note that the function returns a boolean and
    // the input a is allowed to be larger than 6144

    let a_bits = a_val.into_repr().to_bits_le();
    // a_bit_vars is the least 14 bits of a
    // (we only care for the first 14 bits of a_bits)
    let a_bit_vars = a_bits
        .iter()
        .take(14)
        .map(|x| Boolean::new_witness(cs.clone(), || Ok(x)))
        .collect::<Result<Vec<_>, _>>()?;

    // ensure that a_bits are the bit decomposition of a
    enforce_decompose(a, a_bit_vars.as_ref())?;

    // argue that a < 6144 = 2^12 + 2^11 via the following:
    // - a[13] == 0 and
    // - either a[12] == 0 or a[11] == 0

    // a[13] == 0
    let res = (a_bit_vars[13].is_eq(&Boolean::FALSE)?)
        // a[12] == 0
        .and(&a_bit_vars[12].is_eq(&Boolean::FALSE)?
            // a[11] == 0
        .   or(&a_bit_vars[11].is_eq(&Boolean::FALSE)?
            )?
        )?
        .is_eq(&Boolean::TRUE);
    //     if !cs.is_in_setup_mode(){
    // println!("< norm 6144 satisfied? {:?}", cs.is_satisfied());
    //     }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{rand::Rng, test_rng};
    use falcon_rust::{MODULUS, SIG_L2_BOUND};

    macro_rules! test_range_proof_mod_q {
        ($value: expr, $satisfied: expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($value);
            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();

            enforce_less_than_q(cs.clone(), &a_var).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );
        };
    }
    #[test]
    fn test_range_proof_mod_q() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_range_proof_mod_q!(42, true);

        // edge case: 0
        test_range_proof_mod_q!(0, true);

        // edge case: 2^12
        test_range_proof_mod_q!(1 << 12, true);

        // edge case: 2^13
        test_range_proof_mod_q!(1 << 13, true);

        // edge case: 12288
        test_range_proof_mod_q!(MODULUS - 1, true);

        // =======================
        // bad path
        // =======================
        // edge case: 12289
        test_range_proof_mod_q!(MODULUS, false);

        // edge case: 12290
        test_range_proof_mod_q!(MODULUS + 1, false);

        // edge case: 122890000
        test_range_proof_mod_q!(MODULUS as u32 * 10000, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..1000 {
            let t = rng.gen_range(0..1 << 15);
            test_range_proof_mod_q!(t, t < MODULUS);
        }

        // the following code prints out the
        // cost for arkworks native range proof
        // {
        //     let cs = ConstraintSystem::<Fq>::new_ref();
        //     let a = Fq::from(42u64);
        //     let a_var = FpVar::<Fq>::new_witness(cs.clone(), ||
        // Ok(a)).unwrap();     let b_var =
        // FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();
        //     a_var.enforce_cmp(&b_var, Ordering::Less, false).unwrap();
        //     println!(
        //         "number of variables {} {} and constraints {}\n",
        //         cs.num_instance_variables(),
        //         cs.num_witness_variables(),
        //         cs.num_constraints(),
        //     );
        // }

        // assert!(false)
    }

    macro_rules! test_range_proof_norm_bound {
        ($value: expr, $satisfied: expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($value);
            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();

            enforce_less_than_norm_bound(cs.clone(), &a_var).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied, "{}", $value);
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );
        };
    }
    #[test]
    fn test_range_proof_norm_bound() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_range_proof_norm_bound!(42, true);

        // edge case: 0
        test_range_proof_norm_bound!(0, true);

        // edge case: 2^25
        test_range_proof_norm_bound!(1 << 25, true);

        // edge case: 2^24
        test_range_proof_norm_bound!(1 << 24, true);

        #[cfg(feature = "falcon-1024")]
        // edge case: 2^26
        test_range_proof_norm_bound!(1 << 26, true);

        // edge case: 34034725
        test_range_proof_norm_bound!(SIG_L2_BOUND - 1, true);

        // =======================
        // bad path
        // =======================
        // edge case: 34034726
        test_range_proof_norm_bound!(SIG_L2_BOUND, false);

        // edge case: 34034727
        test_range_proof_norm_bound!(SIG_L2_BOUND + 1, false);

        #[cfg(feature = "falcon-512")]
        // edge case: 2^26
        test_range_proof_norm_bound!(1 << 26, false);

        // edge case: 2^27
        test_range_proof_norm_bound!(1 << 27, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..1000 {
            let t = rng.gen_range(0..1 << 27);
            test_range_proof_norm_bound!(t, t < SIG_L2_BOUND);
        }

        // the following code prints out the
        // cost for arkworks native range proof
        // {
        //     let cs = ConstraintSystem::<Fq>::new_ref();
        //     let a = Fq::from(42);
        //     let a_var = FpVar::<Fq>::new_witness(cs.clone(), ||
        // Ok(a)).unwrap();     let b_var =
        // FpVar::<Fq>::new_constant(cs.clone(), Fq::from(12289)).unwrap();
        //     a_var
        //         .enforce_cmp(&b_var, std::cmp::Ordering::Less, false)
        //         .unwrap();
        //     println!(
        //         "number of variables {} {} and constraints {}\n",
        //         cs.num_instance_variables(),
        //         cs.num_witness_variables(),
        //         cs.num_constraints(),
        //     );
        // }
        // assert!(false)
    }

    macro_rules! test_range_proof_half_q {
        ($value: expr, $satisfied: expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($value);
            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();

            let is_less = is_less_than_6144(cs.clone(), &a_var).unwrap();
            is_less.enforce_equal(&Boolean::TRUE).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );
        };
    }
    #[test]
    fn test_range_proof_half_q() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_range_proof_half_q!(42, true);

        // edge case: 0
        test_range_proof_half_q!(0, true);

        // edge case: 6143
        test_range_proof_half_q!(6143, true);

        // =======================
        // bad path
        // =======================
        // edge case: 6144
        test_range_proof_half_q!(6144, false);

        // edge case: 6145
        test_range_proof_half_q!(6145, false);

        // edge case: 12289
        test_range_proof_half_q!(MODULUS, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..1000 {
            let t = rng.gen_range(0..1 << 15);
            test_range_proof_half_q!(t, t < 6144);
        }

        // the following code prints out the
        // cost for arkworks native range proof
        // {
        //     let cs = ConstraintSystem::<Fq>::new_ref();
        //     let a = Fq::from(42);
        //     let a_var = FpVar::<Fq>::new_witness(cs.clone(), ||
        // Ok(a)).unwrap();     let b_var =
        // FpVar::<Fq>::new_constant(cs.clone(), Fq::from(12289)).unwrap();
        //     a_var
        //         .enforce_cmp(&b_var, std::cmp::Ordering::Less, false)
        //         .unwrap();
        //     println!(
        //         "number of variables {} {} and constraints {}\n",
        //         cs.num_instance_variables(),
        //         cs.num_witness_variables(),
        //         cs.num_constraints(),
        //     );
        // }
        // assert!(false)
    }

    macro_rules! enforce_less_than_1024 {
        ($value: expr, $satisfied: expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($value);
            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();

            enforce_less_than_1024(cs.clone(), &a_var).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables(),
            //     cs.num_witness_variables(),
            //     cs.num_constraints(),
            // );
        };
    }
    #[test]
    fn test_enforce_less_than_1024() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        enforce_less_than_1024!(42, true);

        // edge case: 0
        enforce_less_than_1024!(0, true);

        // edge case: 1023
        enforce_less_than_1024!(1023, true);

        // =======================
        // bad path
        // =======================
        // edge case: 1024
        enforce_less_than_1024!(1024, false);

        // edge case: 1025
        enforce_less_than_1024!(1025, false);

        // edge case: 12289
        enforce_less_than_1024!(MODULUS, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..1000 {
            let t = rng.gen_range(0..2048);
            enforce_less_than_1024!(t, t < 1024);
        }

        // // the following code prints out the
        // // cost for arkworks native range proof
        // {
        //     let cs = ConstraintSystem::<Fq>::new_ref();
        //     let a = Fq::from(42);
        //     let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();
        //     let b_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(12289)).unwrap();
        //     a_var
        //         .enforce_cmp(&b_var, std::cmp::Ordering::Less, false)
        //         .unwrap();
        //     println!(
        //         "number of variables {} {} and constraints {}\n",
        //         cs.num_instance_variables(),
        //         cs.num_witness_variables(),
        //         cs.num_constraints(),
        //     );
        // }
        // assert!(false)
    }
}
