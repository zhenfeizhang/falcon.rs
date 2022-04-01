#![allow(clippy::many_single_char_names)]
mod param;

use crate::{LOG_N, MODULUS, N, ONE_OVER_N};
pub use param::*;

pub fn ntt_mul(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut c = [0; N];
    for i in 0..N {
        c[i] = a[i] * b[i] % MODULUS as u32;
    }
    c
}

/// convert a polynomial into its NTT form
pub fn ntt(input: &[u32]) -> [u32; N] {
    if input.len() != N {
        panic!("input length {} is not {}", input.len(), N)
    }

    let mut output = [0u32; N];
    output.clone_from_slice(input);

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
                let v = output[j + ht] * s % MODULUS;
                output[j] = (u + v) % MODULUS;
                output[j + ht] = (u + MODULUS - v) % MODULUS;
                j += 1;
            }

            i += 1;
            j1 += t
        }
        t = ht;
    }

    output
}

/// convert an NTT form polynomial into its integer form
pub fn inv_ntt(input: &[u32]) -> [u32; N] {
    if input.len() != N {
        panic!("input length {} is not {}", input.len(), N)
    }

    let mut output = [0u32; N];
    output.clone_from_slice(input);

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
                output[j + t] = w * s % MODULUS;
                j += 1;
            }

            i += 1;
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    for e in output.iter_mut() {
        *e = *e * ONE_OVER_N % MODULUS
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn test_ntt_clear() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        for _ in 0..1000 {
            let input: Vec<u32> = (0..N).map(|_| rng.next_u32() % MODULUS as u32).collect();
            let ntt = ntt(input.as_ref());
            let output = inv_ntt(ntt.as_ref());

            assert_eq!(input, output);
        }
    }
}
