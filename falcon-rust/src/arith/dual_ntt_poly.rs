use crate::{DualPolynomial, NTTPolynomial, MODULUS, N};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DualNTTPolynomial {
    pub pos: NTTPolynomial,
    pub neg: NTTPolynomial,
}

impl From<&DualPolynomial> for DualNTTPolynomial {
    fn from(poly: &DualPolynomial) -> Self {
        Self {
            pos: (&poly.pos).into(),
            neg: (&poly.neg).into(),
        }
    }
}

impl From<&DualNTTPolynomial> for NTTPolynomial {
    fn from(dual_poly: &DualNTTPolynomial) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.0[i] = (dual_poly.pos.coeff()[i] + MODULUS - dual_poly.neg.coeff()[i]) % MODULUS;
        }

        res
    }
}

impl DualNTTPolynomial {
    /// Multiply self by a Polynomial
    pub fn mul_by_poly(&self, other: &NTTPolynomial) -> Self {
        Self {
            pos: self.pos * *other,
            neg: self.neg * *other,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Polynomial;

    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    #[test]
    fn test_dual_ntt_poly_conversion() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        for _ in 0..100 {
            let poly = Polynomial::rand(&mut rng);
            let poly_ntt = NTTPolynomial::from(&poly);
            let dual_poly = DualPolynomial::from(&poly);
            let dual_ntt_poly = DualNTTPolynomial::from(&dual_poly);
            let poly_ntt_rec = NTTPolynomial::from(&dual_ntt_poly);
            assert_eq!(poly_ntt, poly_ntt_rec)
        }
    }
}
