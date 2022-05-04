use ark_ff::{BigInteger, PrimeField};
use jf_plonk::{
    circuit::{Circuit, PlonkCircuit, Variable},
    errors::PlonkError,
};

/// Constraint that the witness of a is smaller than 12289
/// Cost: XX constraints.
/// (This improves the range proof of 1264 constraints as in Arkworks.)
pub(crate) fn enforce_less_than_q<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
) -> Result<(), PlonkError> {
    // we want to decompose a input a into the following format
    // a = a_13*2^13 + a_12*2^12 + a_11*2^11 + ... + a_0 *2^0
    // where
    //  - a_0 ... a_13 are binary

    let a_val = cs.witness(*a)?;

    let a_bits = a_val.into_repr().to_bits_le();
    // a_bit_vars is the least 14 bits of a
    // (we only care for the first 14 bits of a_bits)
    let a_bit_vars = a_bits
        .iter()
        .take(14)
        .map(|&x| cs.create_bool_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

    // ensure that a_bits are the bit decomposition of a
    enforce_decompose(cs, a, a_bit_vars.as_ref())?;

    // argue that a < MODULUS = 2^13 + 2^12 + 1 via enforcing one of the following
    // TODO: complete the arguments

    Ok(())
}

/// Constraint that a = bits[0] + 2 bits[1] + 2^2 bits[2] ...
pub fn enforce_decompose<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
    bits: &[Variable],
) -> Result<(), PlonkError> {
    if bits.len() < 4 {
        panic!("Invalid input length: {}", bits.len());
    }

    // first 4 bits
    let wires_in = [bits[0], bits[1], bits[2], bits[3]];
    let coeffs = [F::one(), F::from(2u32), F::from(4u32), F::from(8u32)];
    let mut res = cs.lc(&wires_in, &coeffs)?;

    for (i, a) in bits[4..].chunks(3).enumerate() {
        let wires_in = [a[0], a[1], a[2], res];
        let coeffs = [
            F::from((1 << (3 * i + 4)) as u64),
            F::from((1 << (3 * i + 5)) as u64),
            F::from((1 << (3 * i + 6)) as u64),
            F::one(),
        ];
        res = cs.lc(&wires_in, &coeffs)?;
    }

    // enforce equal
    cs.equal_gate(res, *a)
}

pub(crate) fn enforce_leq_765<F: PrimeField>(
    cs: &mut PlonkCircuit<F>,
    a: &Variable,
) -> Result<(), PlonkError> {
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
    println!("a1 {}, a2 {}, a3 {}", a1, a2, a3);

    // ensure a1, a2, a3 <= 256
    cs.range_gate(a1_var, 8)?;
    cs.range_gate(a2_var, 8)?;
    cs.range_gate(a3_var, 8)?;

    // ensure a = a1 + a2 + a3
    let wires = [a1_var, a2_var, a3_var, cs.zero(), *a];
    let coeffs = [F::one(); 4];
    cs.lc_gate(&wires, &coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bls12_381::fq::Fq;
    use ark_std::{rand::Rng, test_rng};
    use falcon_rust::MODULUS;

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
        for _ in 0..1000 {
            let t = rng.gen_range(0..2048) as u64;
            enforce_leq_765!(t, t <= 765);
        }
        Ok(())

        // // the following code prints out the
        // // cost for arkworks native range proof
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
}
