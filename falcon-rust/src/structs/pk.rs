use super::sig::Signature;
use crate::{binder::*, param::*, DualPolynomial, NTTPolynomial, Polynomial};
use libc::c_void;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey(pub(crate) [u8; PK_LEN]);

impl PublicKey {
    /// Expose the public key as a byte string
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// verification using C wrapper
    pub fn verify(&self, message: &[u8], sig: &Signature) -> bool {
        let sig_type = 2;
        let mut buf = [0u8; VERIFY_BUF_LEN];

        let res = unsafe {
            falcon_verify(
                sig.0.as_ptr() as *const c_void,
                sig.0.len() as u64,
                sig_type,
                self.0.as_ptr() as *const c_void,
                self.0.len() as u64,
                message.as_ptr() as *const c_void,
                message.len() as u64,
                buf.as_mut_ptr() as *mut c_void,
                VERIFY_BUF_LEN as u64,
            )
        };

        res == 0
    }

    // Unpack the public key into a vector of integers
    // within the range of [0, MODULUS)
    pub fn unpack(&self) -> [u16; N] {
        assert!(self.0[0] == LOG_N as u8);
        mod_q_decode(self.0[1..].as_ref())
    }

    // using rust's functions to check the validity of a signature
    pub fn verify_rust(&self, message: &[u8], sig: &Signature) -> bool {
        let pk: Polynomial = self.into();
        let sig_u: Polynomial = sig.into();
        let hm = Polynomial::from_hash_of_message(message, sig.0[1..41].as_ref());

        // compute v = hm - uh
        let uh = sig_u * pk;
        let v = hm - uh;

        let l2_norm = sig_u.l2_norm() + v.l2_norm();
        l2_norm <= SIG_L2_BOUND
    }

    // check the validity of a signature via the parsed method
    // this is slow; but will improve circuit complexity for ZKP
    pub fn verify_parsed_sig(&self, message: &[u8], sig: &Signature) -> bool {
        let pk: Polynomial = self.into();
        let sig_u: DualPolynomial = sig.into();
        let hm = Polynomial::from_hash_of_message(message, sig.0[1..41].as_ref());

        // compute v = hm - uh
        let uh_pos = sig_u.pos * pk;
        let uh_neg = sig_u.neg * pk;
        let v = hm - uh_pos + uh_neg;

        let l2_norm = sig_u.l2_norm() + v.l2_norm();
        l2_norm <= SIG_L2_BOUND
    }
}

impl From<&PublicKey> for Polynomial {
    fn from(pk: &PublicKey) -> Self {
        Polynomial(pk.unpack())
    }
}

impl From<&PublicKey> for NTTPolynomial {
    fn from(pk: &PublicKey) -> Self {
        (&Polynomial(pk.unpack())).into()
    }
}

fn mod_q_decode(input: &[u8]) -> [u16; N] {
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
