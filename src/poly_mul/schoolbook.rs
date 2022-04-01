use crate::{MODULUS, MODULUS_MINUS_1_OVER_TWO, N};

// output = a(x) * b(x) mod x^N +1 mod MODULUS
// using school-book multiplications
pub fn schoolbook_mul(a: &[u16; N], b: &[i16; N]) -> [i16; N] {
    let mut buf = [0i32; N << 1];
    let mut c = [0; N];
    for i in 0..N {
        for j in 0..N {
            buf[i + j] += (a[i] as i32) * (b[j] as i32);
        }
    }
    for i in 0..N {
        c[i] = ((buf[i] + MODULUS as i32 - buf[i + N]) % MODULUS as i32) as i16;
        if c[i] > MODULUS_MINUS_1_OVER_TWO {
            c[i] -= MODULUS as i16
        }
    }
    c
}
