use super::*;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use falcon_rust::{MODULUS, N};
use num_bigint::BigUint;

/// Generate the variables c = a * B mod 12289;
/// with a guarantee that the inputs a and b satisfies:
/// * a is a dim n vector with a_i < 12289
/// * b is an n-by-m matrix with b_ij < 12289
/// Cost: (29 + a.len())*b.row() constraints
#[allow(dead_code)]
pub(crate) fn vector_matrix_mul_mod<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &[FpVar<F>],
    b: &[&[FpVar<F>]],
    modulus_var: &FpVar<F>,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    if a.is_empty() || b.is_empty() {
        panic!("Invalid input length: a {} vs b {}", a.len(), b.len());
    }

    b.iter()
        .map(|&b_i| inner_product_mod(cs.clone(), a, b_i, modulus_var))
        .collect::<Result<Vec<_>, _>>()
}

/// Generate the variable c = <a \cdot b> mod 12289;
/// with a guarantee that the inputs a and b satisfies:
/// * a_i < 12289
/// * b_i < 12289
/// Cost: 29 + a.len() constraints
pub(crate) fn inner_product_mod<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &[FpVar<F>],
    b: &[FpVar<F>],
    modulus_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    if a.len() != b.len() || a.is_empty() {
        panic!("Invalid input length: a {} vs b {}", a.len(), b.len());
    }

    // we want to prove that `c = <a \cdot b> mod 12289`
    // that is
    // (1) a_0 * b_0 + a_1 * b_1 + ... + a_k * b_k - t * 12289 = c
    // for some unknown t, with
    // (2) c < 12289
    //
    // Note that this implementation assumes the
    // native field's order is greater than 12289^2
    // so we do not have any overflows
    //
    // also note that this method is slightly more efficient
    // than calling mul_mod iteratively

    // rebuild the field elements
    let a_val = if cs.is_in_setup_mode() {
        vec![F::one(); N]
    } else {
        a.value()?
    };
    let b_val = if cs.is_in_setup_mode() {
        vec![F::one(); N]
    } else {
        b.value()?
    };

    let mut ab_val = a_val[0] * b_val[0];
    for (&a_i, &b_i) in a_val.iter().zip(b_val.iter()).skip(1) {
        ab_val += a_i * b_i;
    }
    let ab_int: BigUint = ab_val.into();

    let modulus_int: BigUint = F::from(MODULUS).into();
    let t_int = &ab_int / &modulus_int;
    let c_int = &ab_int % &modulus_int;

    let t_val = F::from(t_int);
    let c_val = F::from(c_int);

    // cast the variables
    let t_var = FpVar::<F>::new_witness(cs.clone(), || Ok(t_val))?;
    let c_var = FpVar::<F>::new_witness(cs.clone(), || Ok(c_val))?;

    // (1) a_0 * b_0 + a_1 * b_1 + ... + a_k * b_k - t * 12289 = c
    let mut ab_var = &a[0] * &b[0];
    for (a_i, b_i) in a.iter().zip(b.iter()).skip(1) {
        ab_var += a_i * b_i;
    }

    let t_12289 = t_var * modulus_var;
    let left = ab_var - t_12289;
    left.enforce_equal(&c_var)?;

    // (2) c < 12289
    enforce_less_than_q(cs, &c_var)?;

    Ok(c_var)
}

/// Generate the variable b = a mod 12289;
/// Cost: 30 constraints
#[allow(dead_code)]
pub fn mod_q<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
    modulus_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
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
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };

    let a_int: BigUint = a_val.into();

    let modulus_int: BigUint = F::from(MODULUS).into();
    let t_int = &a_int / &modulus_int;
    let b_int = &a_int % &modulus_int;

    let t_val = F::from(t_int);
    let b_val = F::from(b_int);

    // cast the variables
    let t_var = FpVar::<F>::new_witness(cs.clone(), || Ok(t_val))?;
    let b_var = FpVar::<F>::new_witness(cs.clone(), || Ok(b_val))?;

    // (1) a - t * 12289 = c
    let t_12289 = t_var * modulus_var;
    let left = a - t_12289;
    left.enforce_equal(&b_var)?;

    // (2) c < 12289
    enforce_less_than_q(cs, &b_var)?;

    Ok(b_var)
}

/// Generate the variable c = a * b mod 12289;
/// with a guarantee that the inputs a and b satisfies:
/// * a < 12289
/// * b < 12289
/// Cost: 30 constraints
#[allow(dead_code)]
pub(crate) fn mul_mod<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
    b: &FpVar<F>,
    modulus_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // we want to prove that `c = a * b mod 12289`
    // that is
    // (1) a * b - t * 12289 = c
    // for some unknown t, with
    // (2) c < 12289
    //
    // Note that this implementation assumes the
    // native field's order is greater than 12289^2
    // so we do not have any overflows

    // rebuild the field elements
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };
    let b_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        b.value()?
    };

    let ab_val = a_val * b_val;
    let ab_int: BigUint = ab_val.into();

    let modulus_int: BigUint = F::from(MODULUS).into();
    let t_int = &ab_int / &modulus_int;
    let c_int = &ab_int % &modulus_int;

    let t_val = F::from(t_int);
    let c_val = F::from(c_int);

    // cast the variables
    let t_var = FpVar::<F>::new_witness(cs.clone(), || Ok(t_val))?;
    let c_var = FpVar::<F>::new_witness(cs.clone(), || Ok(c_val))?;

    // (1) a * b - t * 12289 = c
    let ab_var = a * b;
    let t_q = t_var * modulus_var;
    let left = ab_var - t_q;
    left.enforce_equal(&c_var)?;

    // (2) c < 12289
    enforce_less_than_q(cs, &c_var)?;

    Ok(c_var)
}

/// Generate the variable c = a + b mod 12289;
/// Cost: 30 constraints
#[allow(dead_code)]
pub(crate) fn add_mod<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
    b: &FpVar<F>,
    modulus_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // we want to prove that `c = a + b mod 12289`
    // that is
    // (1) a + b - t * 12289 = c
    // for some t in {0, 1}, with
    // (2) c < 12289

    // rebuild the field elements
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };
    let b_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        b.value()?
    };

    let ab_val = a_val + b_val;
    let ab_int: BigUint = ab_val.into();

    let modulus_int: BigUint = F::from(MODULUS).into();
    let c_int = &ab_int % &modulus_int;
    let t_int = (&ab_int - &c_int) / &modulus_int;

    let t_val = F::from(t_int);
    let c_val = F::from(c_int);

    // cast the variables
    let t_var = FpVar::<F>::new_witness(cs.clone(), || Ok(t_val))?;
    let c_var = FpVar::<F>::new_witness(cs.clone(), || Ok(c_val))?;

    // (1) a + b - t * 12289 = c
    let ab_var = a + b;
    let t_q = t_var * modulus_var;
    let left = ab_var - t_q;
    left.enforce_equal(&c_var)?;

    // (2) c < 12289
    enforce_less_than_q(cs, &c_var)?;

    Ok(c_var)
}

/// Generate the variable c = a - b mod 12289;
/// Requires
///     a < 12289
/// Cost: 31 constraints
#[allow(dead_code)]
pub(crate) fn sub_mod<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    a: &FpVar<F>,
    b: &FpVar<F>,
    modulus_var: &FpVar<F>,
) -> Result<FpVar<F>, SynthesisError> {
    // we want to prove that `c = a - b mod 12289`
    // that is b + c = a mod 12289

    // rebuild the field elements
    let a_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        a.value()?
    };
    let b_val = if cs.is_in_setup_mode() {
        F::one()
    } else {
        b.value()?
    };

    let a_int: BigUint = a_val.into();
    let b_int: BigUint = b_val.into();
    let modulus_int: BigUint = F::from(MODULUS).into();
    let b_mod_q_int = &b_int % &modulus_int;
    let c_int = (&a_int + &modulus_int - &b_mod_q_int) % &modulus_int;

    let c_val = F::from(c_int);
    let c_var = FpVar::<F>::new_witness(cs.clone(), || Ok(c_val))?;

    a.enforce_equal(&add_mod(cs, b, &c_var, modulus_var)?)?;

    Ok(c_var)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::{rand::Rng, test_rng, UniformRand};

    macro_rules! test_mod_q {
        ($a:expr, $b:expr, $satisfied:expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($a);
            let b = Fq::from($b);

            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();
            let const_q_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();

            // let num_instance_variables = cs.num_instance_variables();
            // let num_witness_variables = cs.num_witness_variables();
            // let num_constraints = cs.num_constraints();

            let b_var = mod_q(cs.clone(), &a_var, &const_q_var).unwrap();
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables() - num_instance_variables,
            //     cs.num_witness_variables() - num_witness_variables,
            //     cs.num_constraints() - num_constraints,
            // );

            let b_var2 = FpVar::<Fq>::new_witness(cs.clone(), || Ok(b)).unwrap();
            b_var.enforce_equal(&b_var2).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);

            assert_eq!(b_var.value().unwrap() == b, $satisfied,);
        };
    }

    #[test]
    fn test_mod_q() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_mod_q!(6, 6, true);

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
        for _ in 0..1000 {
            let t = rng.gen_range(0..1 << 30);

            test_mod_q!(t, t % MODULUS as u32, true);
            test_mod_q!(t, (t + 1) % MODULUS as u32, false);
        }
        // assert!(false)
    }

    macro_rules! test_mul_mod {
        ($a:expr, $b:expr, $c:expr, $satisfied:expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($a);
            let b = Fq::from($b);
            let c = Fq::from($c);

            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();
            let b_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(b)).unwrap();
            let const_q_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();

            // let num_instance_variables = cs.num_instance_variables();
            // let num_witness_variables = cs.num_witness_variables();
            // let num_constraints = cs.num_constraints();

            let c_var = mul_mod(cs.clone(), &a_var, &b_var, &const_q_var).unwrap();
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables() - num_instance_variables,
            //     cs.num_witness_variables() - num_witness_variables,
            //     cs.num_constraints() - num_constraints,
            // );

            let c_var2 = FpVar::<Fq>::new_witness(cs.clone(), || Ok(c)).unwrap();
            c_var.enforce_equal(&c_var2).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);

            assert_eq!(
                c_var.value().unwrap() == c,
                $satisfied,
                "c_var: {}\nc: {}",
                c_var.value().unwrap().into_repr(),
                c.into_repr()
            );
        };
    }

    #[test]
    fn test_mul_mod() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_mul_mod!(6, 7, 42, true);

        // edge case: 0
        test_mul_mod!(0, 100, 0, true);
        test_mul_mod!(100, 0, 0, true);

        // edge case: wraparound
        test_mul_mod!(5, 12288, 12284, true);

        // =======================
        // bad path
        // =======================
        // wrong value
        test_mul_mod!(6, 7, 41, false);
        test_mul_mod!(5, 12288, 12283, false);

        // assert!(false)
    }

    macro_rules! test_add_mod {
        ($a:expr, $b:expr, $c:expr, $satisfied:expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($a);
            let b = Fq::from($b);
            let c = Fq::from($c);

            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();
            let b_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(b)).unwrap();
            let const_q_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();

            // let num_instance_variables = cs.num_instance_variables();
            // let num_witness_variables = cs.num_witness_variables();
            // let num_constraints = cs.num_constraints();

            let c_var = add_mod(cs.clone(), &a_var, &b_var, &const_q_var).unwrap();
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables() - num_instance_variables,
            //     cs.num_witness_variables() - num_witness_variables,
            //     cs.num_constraints() - num_constraints,
            // );

            let c_var2 = FpVar::<Fq>::new_witness(cs.clone(), || Ok(c)).unwrap();
            c_var.enforce_equal(&c_var2).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);

            assert_eq!(
                c_var.value().unwrap() == c,
                $satisfied,
                "c_var: {}\nc: {}",
                c_var.value().unwrap().into_repr(),
                c.into_repr()
            );
        };
    }

    #[test]
    fn test_add_mod() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_add_mod!(6, 36, 42, true);

        // edge case: 0
        test_add_mod!(0, 100, 100, true);
        test_add_mod!(100, 0, 100, true);

        // edge case: wraparound
        test_add_mod!(5, MODULUS - 1, 4, true);

        // =======================
        // bad path
        // =======================
        // wrong value
        test_add_mod!(6, 7, 41, false);
        test_add_mod!(5, MODULUS - 1, 3, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..1000 {
            let t1 = rng.gen_range(0..1 << 30);
            let t2 = rng.gen_range(0..1 << 30);
            test_add_mod!(t1, t2, (t1 + t2) % MODULUS as u32, true);
            test_add_mod!(t1, t2, (t1 + t2 + 1) % MODULUS as u32, false);
        }
        // assert!(false)
    }

    macro_rules! test_sub_mod {
        ($a:expr, $b:expr, $c:expr, $satisfied:expr) => {
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = Fq::from($a);
            let b = Fq::from($b);
            let c = Fq::from($c);

            let a_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(a)).unwrap();
            let b_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(b)).unwrap();
            let const_q_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();

            // let num_instance_variables = cs.num_instance_variables();
            // let num_witness_variables = cs.num_witness_variables();
            // let num_constraints = cs.num_constraints();

            let c_var = sub_mod(cs.clone(), &a_var, &b_var, &const_q_var).unwrap();
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables() - num_instance_variables,
            //     cs.num_witness_variables() - num_witness_variables,
            //     cs.num_constraints() - num_constraints,
            // );

            let c_var2 = FpVar::<Fq>::new_witness(cs.clone(), || Ok(c)).unwrap();
            c_var.enforce_equal(&c_var2).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), $satisfied);

            assert_eq!(
                c_var.value().unwrap() == c,
                $satisfied,
                "c_var: {}\nc: {}",
                c_var.value().unwrap().into_repr(),
                c.into_repr()
            );
        };
    }

    #[test]
    fn test_sub_mod() {
        // =======================
        // good path
        // =======================
        // the meaning of life
        test_sub_mod!(78, 36, 42, true);

        // edge case: 0
        test_sub_mod!(0, 0, 0, true);
        test_sub_mod!(100, 0, 100, true);

        // edge case: wraparound
        test_sub_mod!(0, 100, 12189, true);

        // =======================
        // bad path
        // =======================
        // wrong value
        test_sub_mod!(6, 7, 41, false);
        test_sub_mod!(5, MODULUS - 1, 3, false);

        // =======================
        // random path
        // =======================
        let mut rng = test_rng();
        for _ in 0..1000 {
            let t1 = rng.gen_range(0..MODULUS);
            let t2 = rng.gen_range(0..1 << 30);

            test_sub_mod!(
                t1,
                t2,
                (((t1 as i32 - t2 as i32) % MODULUS as i32 + MODULUS as i32) as u16) % MODULUS,
                true
            );
            test_sub_mod!(
                t1,
                t2,
                (((t1 as i32 - t2 as i32 + 1) % MODULUS as i32 + MODULUS as i32) as u16) % MODULUS,
                false
            );
        }
        // assert!(false)
    }
    fn inner_product(a: &[Fq], b: &[Fq]) -> Fq {
        let mut res = a[0] * b[0];
        for (&a_i, &b_i) in a.iter().zip(b.iter()).skip(1) {
            res += a_i * b_i;
        }
        let res_uint: BigUint = res.into();
        let res_uint = res_uint % BigUint::from(MODULUS);
        Fq::from(res_uint)
    }

    #[test]
    fn test_inner_product_mod() {
        let mut rng = test_rng();
        for i in 1..10 {
            let dim = 1 << i;
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = (0..dim)
                .map(|_| Fq::from(rng.gen_range(0..MODULUS)))
                .collect::<Vec<Fq>>();
            let b = (0..dim)
                .map(|_| Fq::from(rng.gen_range(0..MODULUS)))
                .collect::<Vec<Fq>>();
            let c = inner_product(&a, &b);

            let a_var: Vec<FpVar<Fq>> = a
                .iter()
                .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(x)).unwrap())
                .collect();
            let b_var: Vec<FpVar<Fq>> = b
                .iter()
                .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(x)).unwrap())
                .collect();
            let const_q_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();

            // let num_instance_variables = cs.num_instance_variables();
            // let num_witness_variables = cs.num_witness_variables();
            // let num_constraints = cs.num_constraints();

            let c_var = inner_product_mod(cs.clone(), a_var.as_ref(), b_var.as_ref(), &const_q_var)
                .unwrap();
            // println!(
            //     "number of variables {} {} and constraints {}\n",
            //     cs.num_instance_variables() - num_instance_variables,
            //     cs.num_witness_variables() - num_witness_variables,
            //     cs.num_constraints() - num_constraints,
            // );

            let c_var2 = FpVar::<Fq>::new_witness(cs.clone(), || Ok(c)).unwrap();
            c_var.enforce_equal(&c_var2).unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(c_var.value().unwrap(), c,);

            let bad_c_var =
                FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::rand(&mut rng))).unwrap();
            c_var.enforce_equal(&bad_c_var).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }

        // assert!(false)
    }

    #[test]
    fn test_vector_matrix_mod() {
        let mut rng = test_rng();
        for i in 1..10 {
            let row = 1 << i;
            let cs = ConstraintSystem::<Fq>::new_ref();
            let a = (0..row)
                .map(|_| Fq::from(rng.gen_range(0..MODULUS)))
                .collect::<Vec<Fq>>();

            for j in 1..10 {
                let col = 1 << j;

                let b: Vec<Vec<Fq>> = (0..col)
                    .map(|_| {
                        (0..row)
                            .map(|_| Fq::from(rng.gen_range(0..MODULUS)))
                            .collect::<Vec<Fq>>()
                    })
                    .collect();

                let c: Vec<Fq> = b.iter().map(|b_i| inner_product(&a, b_i)).collect();

                let a_var: Vec<FpVar<Fq>> = a
                    .iter()
                    .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(x)).unwrap())
                    .collect();
                let b_var: Vec<Vec<FpVar<Fq>>> = b
                    .iter()
                    .map(|bi| {
                        bi.iter()
                            .map(|bij| FpVar::<Fq>::new_witness(cs.clone(), || Ok(bij)).unwrap())
                            .collect::<Vec<FpVar<Fq>>>()
                    })
                    .collect();
                let const_q_var = FpVar::<Fq>::new_constant(cs.clone(), Fq::from(MODULUS)).unwrap();

                let b_var_ref: Vec<&[FpVar<Fq>]> = b_var.iter().map(|x| x.as_ref()).collect();

                // let num_instance_variables = cs.num_instance_variables();
                // let num_witness_variables = cs.num_witness_variables();
                // let num_constraints = cs.num_constraints();

                let c_var = vector_matrix_mul_mod(
                    cs.clone(),
                    a_var.as_ref(),
                    b_var_ref.as_ref(),
                    &const_q_var,
                )
                .unwrap();
                // println!(
                //     "number of variables {} {} and constraints {}\n",
                //     cs.num_instance_variables() - num_instance_variables,
                //     cs.num_witness_variables() - num_witness_variables,
                //     cs.num_constraints() - num_constraints,
                // );

                let c_var2: Vec<FpVar<Fq>> = c
                    .iter()
                    .map(|x| FpVar::<Fq>::new_witness(cs.clone(), || Ok(x)).unwrap())
                    .collect();
                c_var.enforce_equal(&c_var2).unwrap();
                assert!(cs.is_satisfied().unwrap());
                assert_eq!(c_var.value().unwrap(), c);
            }
        }

        // assert!(false)
    }
}
