#![allow(clippy::many_single_char_names)]
mod param;

pub use param::*;

pub fn ntt_mul(a: &[u32; 512], b: &[u32; 512]) -> [u32; 512] {
    let mut c = [0; 512];
    for i in 0..512 {
        c[i] = a[i] * b[i] % 12289;
    }
    c
}

/// convert a polynomial into its NTT form
pub fn ntt(input: &[u32]) -> [u32; 512] {
    if input.len() != 512 {
        panic!("input length {} is not 512", input.len())
    }
    let mut output = [0u32; 512];
    output.clone_from_slice(input);

    let n = 512;
    let mut t = n;
    for l in 0..9 {
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
                let v = output[j + ht] * s % 12289;
                output[j] = (u + v) % 12289;
                output[j + ht] = (u + 12289 - v) % 12289;
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
pub fn inv_ntt(input: &[u32]) -> [u32; 512] {
    if input.len() != 512 {
        panic!("input length {} is not 512", input.len())
    }
    let mut output = [0u32; 512];
    output.clone_from_slice(input);

    let n = 512;
    let mut t = 1;
    let mut m = n;
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
                output[j] = (u + v) % 12289;
                let w = (u + 12289 - v) % 12289;
                output[j + t] = w * s % 12289;
                j += 1;
            }

            i += 1;
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    for e in output.iter_mut() {
        *e = *e * 12265 % 12289
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{rand::Rng, test_rng};

    #[test]
    fn test_ntt_clear() {
        let mut rng = test_rng();

        for _ in 0..1000 {
            let input: Vec<u32> = (0..512).map(|_| rng.gen_range(0..12289)).collect();
            let ntt = ntt(input.as_ref());
            let output = inv_ntt(ntt.as_ref());

            assert_eq!(input, output);
        }

        // assert!(false)
    }
}
