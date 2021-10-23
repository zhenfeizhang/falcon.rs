// compute the l2 norm of two input slices
pub(crate) fn l2_norm(input1: &[i16], input2: &[i16]) -> u32 {
    let mut res = 0;
    for e in input1.iter() {
        res += ((*e as i32) * (*e as i32)) as u64;
    }

    for e in input2.iter() {
        res += ((*e as i32) * (*e as i32)) as u64;
    }
    res as u32
}
