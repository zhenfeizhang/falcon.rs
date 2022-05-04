use crate::{Polynomial, MODULUS, MODULUS_MINUS_1_OVER_TWO, N};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DualPolynomial {
    pub pos: Polynomial,
    pub neg: Polynomial,
}

impl From<&Polynomial> for DualPolynomial {
    fn from(poly: &Polynomial) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            if poly.coeff()[i] < MODULUS_MINUS_1_OVER_TWO {
                res.pos.0[i] = poly.coeff()[i]
            } else {
                res.neg.0[i] = MODULUS - poly.coeff()[i]
            }
        }

        res
    }
}

impl From<&DualPolynomial> for Polynomial {
    fn from(dual_poly: &DualPolynomial) -> Self {
        let mut res = Self::default();
        for i in 0..N {
            res.0[i] = (dual_poly.pos.coeff()[i] + MODULUS - dual_poly.neg.coeff()[i]) % MODULUS;
        }

        res
    }
}

impl DualPolynomial {
    /// square of l2 norm of the polynomial
    pub fn l2_norm(&self) -> u64 {
        self.pos.l2_norm() + self.neg.l2_norm()
    }

    /// Multiply self by a Polynomial
    pub fn mul_by_poly(&self, other: &Polynomial) -> Self {
        Self {
            pos: self.pos * *other,
            neg: self.neg * *other,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    #[test]
    fn test_dual_poly_conversion() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        for _ in 0..100 {
            let poly = Polynomial::rand(&mut rng);
            let dual_poly = DualPolynomial::from(&poly);
            let poly_rec = Polynomial::from(&dual_poly);
            assert_eq!(poly, poly_rec)
        }
    }
}
