mod arithmetics;
mod ntt_poly_var;
mod poly_var;
mod range_proof;

use ark_ff::PrimeField;
use jf_plonk::circuit::Variable;
use std::marker::PhantomData;

pub use arithmetics::*;
pub use range_proof::*;

#[derive(Debug, Clone)]
pub struct PolyVar<F: PrimeField> {
    pub coeff: Vec<Variable>,
    phantom: PhantomData<F>,
}

#[derive(Debug, Clone)]
pub struct NTTPolyVar<F: PrimeField> {
    pub coeff: Vec<Variable>,
    phantom: PhantomData<F>,
}
