// output = a(x) * b(x) mod x^512 +1 mod 12289
// using school-book multiplications
pub fn schoolbook_mul(a: &[u16; 512], b: &[i16; 512]) -> [i16; 512] {
    let mut buf = [0i32; 1024];
    let mut c = [0; 512];
    for i in 0..512 {
        for j in 0..512 {
            buf[i + j] += (a[i] as i32) * (b[j] as i32);
        }
    }
    for i in 0..512 {
        c[i] = ((buf[i] + 12289 - buf[i + 512]) % 12289) as i16;
        if c[i] > 6144 {
            c[i] -= 12289
        }
    }
    c
}
