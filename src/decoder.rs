use crate::N;

pub(crate) fn mod_q_decode(input: &[u8]) -> [u16; N] {
    if input.len() != (N * 14 + 7) / 8 {
        panic!("incorrect input length")
    }

    let mut input_pt = 0;
    let mut acc = 0u32;
    let mut acc_len = 0;

    let mut output_ptr = 0;
    let mut output = [0u16; N];

    while output_ptr < N {
        acc = (acc << 8) | (input[input_pt] as u32);
        input_pt += 1;
        acc_len += 8;

        if acc_len >= 14 {
            acc_len -= 14;
            let w = (acc >> acc_len) & 0x3FFF;
            assert!(w < 12289, "incorrect input: {}", w);
            output[output_ptr] = w as u16;
            output_ptr += 1;
        }
    }

    if (acc & ((1u32 << acc_len) - 1)) != 0 {
        panic!("incorrect remaining data")
    }

    output
}

pub(crate) fn comp_decode(input: &[u8]) -> [i16; N] {
    let mut input_pt = 0;
    let mut acc = 0u32;
    let mut acc_len = 0;
    let mut output = [0i16; N];

    for e in output.iter_mut() {
        /*
         * Get next eight bits: sign and low seven bits of the
         * absolute value.
         */

        acc = (acc << 8) | (input[input_pt] as u32);
        input_pt += 1;
        let b = acc >> acc_len;
        let s = b & 128;
        let mut m = b & 127;

        /*
         * Get next bits until a 1 is reached.
         */

        loop {
            if acc_len == 0 {
                acc = (acc << 8) | (input[input_pt] as u32);
                input_pt += 1;
                acc_len = 8;
            }
            acc_len -= 1;
            if ((acc >> acc_len) & 1) != 0 {
                break;
            }
            m += 128;
            assert!(m < 2048, "incorrect input: {}", m);
        }

        if s != 0 && m == 0 {
            panic!("incorrect remaining data")
        }
        *e = if s == 0 { -(m as i16) } else { m as i16 };
    }

    /*
     * Unused bits in the last byte must be zero.
     */
    if (acc & ((1 << acc_len) - 1)) != 0 {
        panic!("incorrect remaining data")
    }

    output
}
