use super::inv_ntt;
use super::NTTPolynomial;
use crate::shake256_context;
use crate::MODULUS_MINUS_1_OVER_TWO;
use crate::{MODULUS, N, U32_SAMPLE_THRESHOLD};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use std::ops::Sub;
use std::ops::{Add, Mul};

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Polynomial(pub(crate) [u16; N]);

impl Default for Polynomial {
    fn default() -> Self {
        Self([0u16; N])
    }
}

impl Mul for Polynomial {
    type Output = Self;
    fn mul(self, other: Self) -> <Self as Mul<Self>>::Output {
        let self_ntt: NTTPolynomial = (&self).into();
        let other_ntt: NTTPolynomial = (&other).into();

        (&(self_ntt * other_ntt)).into()
    }
}

impl Add for Polynomial {
    type Output = Self;
    fn add(self, other: Self) -> <Self as Add<Self>>::Output {
        let mut res = self;
        res.0
            .iter_mut()
            .zip(other.0.iter())
            .for_each(|(x, y)| *x = (*x + *y) % MODULUS as u16);

        res
    }
}

impl Sub for Polynomial {
    type Output = Self;
    fn sub(self, other: Self) -> <Self as Add<Self>>::Output {
        let mut res = self;
        res.0
            .iter_mut()
            .zip(other.0.iter())
            .for_each(|(x, y)| *x = (*x + MODULUS - *y) % MODULUS as u16);

        res
    }
}

impl From<&NTTPolynomial> for Polynomial {
    fn from(poly: &NTTPolynomial) -> Self {
        inv_ntt(poly)
    }
}

impl Polynomial {
    /// A non-constant time sampler for random polynomials
    pub fn rand<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut res = [0u16; N];
        for e in res.iter_mut() {
            let mut tmp = rng.next_u32();
            while tmp >= U32_SAMPLE_THRESHOLD {
                tmp = rng.next_u32();
            }
            *e = (tmp % MODULUS as u32) as u16;
        }
        Self(res)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        for b in self.0.iter() {
            res.push((b >> 8) as u8);
            res.push((b & 0xFF) as u8);
        }
        res
    }

    /// constant polynomial 1
    pub fn one() -> Self {
        let mut res = Self::default();
        res.0[0] = 1;
        res
    }

    /// build public param from a seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        Self::rand(&mut rng)
    }

    /// Negate a polynomial mod q
    pub fn neg_mod_q(&self) -> Self {
        let mut res = *self;
        for e in res.0.iter_mut() {
            *e = MODULUS as u16 - *e
        }
        res
    }

    /// school book multiplication
    /// output = a(x) * b(x) mod x^N +1 mod MODULUS
    /// using school-book multiplications
    pub fn schoolbook_mul(a: &Self, b: &Self) -> Self {
        let mut buf = [0u32; N << 1];
        let mut c = [0; N];
        for i in 0..N {
            for j in 0..N {
                buf[i + j] += (a.0[i] as u32 * b.0[j] as u32) % MODULUS as u32;
            }
        }

        for i in 0..N {
            c[i] =
                ((buf[i] + MODULUS as u32 - (buf[i + N] % MODULUS as u32)) % MODULUS as u32) as u16;
        }
        Self(c)
    }

    /// hash a message into a polynomial
    pub fn from_hash_of_message(message: &[u8], nonce: &[u8]) -> Self {
        // initialize and finalize the rng
        let mut rng = shake256_context::init();
        rng.inject(nonce);
        rng.inject(message);
        rng.finalize();

        // extract the data from rng and build the output
        let mut res = [0u16; N];
        let mut i = 0;
        while i < N {
            let output = rng.extract(2);
            let mut coeff = (output[0] as u16) << 8 | (output[1] as u16);
            if coeff < 61445 {
                while coeff >= MODULUS as u16 {
                    coeff -= MODULUS as u16;
                }
                res[i] = coeff;
                i += 1;
            }
        }
        Self(res)
    }

    /// square of l2 norm of the polynomial
    pub fn l2_norm(&self) -> u64 {
        let mut res = 0;
        for e in self.0 {
            if e > MODULUS_MINUS_1_OVER_TWO as u16 {
                res += (MODULUS - e) as u64 * (MODULUS - e) as u64
            } else {
                res += e as u64 * e as u64
            }
        }
        res
    }

    /// Access the coefficients
    pub fn coeff(&self) -> &[u16; N] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Polynomial;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_polynomial_mul() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        for _ in 0..100 {
            let t1 = Polynomial::rand(&mut rng);
            let t2 = Polynomial::rand(&mut rng);
            let tt = Polynomial::schoolbook_mul(&t1, &t2);
            let t = t1 * t2;
            assert_eq!(tt, t)
        }
    }
}
