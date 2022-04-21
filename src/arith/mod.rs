mod ntt_poly;
mod param;
mod poly;

pub use ntt_poly::NTTPolynomial;
pub use poly::Polynomial;

use crate::{LOG_N, MODULUS, N, ONE_OVER_N};
use param::NTT_TABLE;

use self::param::INV_NTT_TABLE;

/// convert a polynomial into its NTT form
pub(crate) fn ntt(input: &Polynomial) -> NTTPolynomial {
    let mut output = input.0;

    let mut t = N;
    for l in 0..LOG_N {
        let m = 1 << l;
        let ht = t / 2;
        let mut i = 0;
        let mut j1 = 0;
        while i < m {
            let s = NTT_TABLE[m + i];
            let j2 = j1 + ht;
            let mut j = j1;
            while j < j2 {
                let u = output[j];
                let v = (output[j + ht] as u32 * s as u32 % MODULUS as u32) as u16;
                output[j] = (u + v) % MODULUS;
                output[j + ht] = (u + MODULUS - v) % MODULUS;
                j += 1;
            }

            i += 1;
            j1 += t
        }
        t = ht;
    }

    NTTPolynomial(output)
}

/// convert an NTT form polynomial into its integer form
pub(crate) fn inv_ntt(input: &NTTPolynomial) -> Polynomial {
    let mut output = input.0;

    let mut t = 1;
    let mut m = N;
    while m > 1 {
        let hm = m / 2;
        let dt = t * 2;
        let mut i = 0;
        let mut j1 = 0;
        while i < hm {
            let j2 = j1 + t;
            let s = INV_NTT_TABLE[hm + i];
            let mut j = j1;
            while j < j2 {
                let u = output[j];
                let v = output[j + t];
                output[j] = (u + v) % MODULUS;
                let w = (u + MODULUS - v) % MODULUS;
                output[j + t] = (w as u32 * s as u32 % MODULUS as u32) as u16;
                j += 1;
            }

            i += 1;
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    for e in output.iter_mut() {
        *e = (*e as u32 * ONE_OVER_N % MODULUS as u32) as u16
    }
    Polynomial(output)
}
