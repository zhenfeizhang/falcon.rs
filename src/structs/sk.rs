use crate::binder::*;
use crate::param::*;
use libc::c_void;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use zeroize::Zeroize;

use super::PublicKey;
use super::Signature;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecretKey(pub(crate) [u8; SK_LEN]);

impl SecretKey {
    /// Recover the public key from the secret key
    pub fn make_public_key(&self) -> PublicKey {
        let mut pk = [0u8; PK_LEN];
        let mut buf = [0u8; MAKE_PK_BUF_LEN];

        unsafe {
            assert!(
                falcon_make_public(
                    pk.as_mut_ptr() as *mut c_void,
                    PK_LEN as u64,
                    self.0.as_ptr() as *const c_void,
                    SK_LEN as u64,
                    buf.as_mut_ptr() as *mut c_void,
                    MAKE_PK_BUF_LEN as u64
                ) == 0
            )
        }
        buf.zeroize();
        PublicKey(pk)
    }

    /// Sign a message with a secret key and a seed.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut seed);

        self.sign_with_seed(seed.as_ref(), message)
    }

    /// Sign a message with a secret key and a seed.
    pub fn sign_with_seed(&self, seed: &[u8], message: &[u8]) -> Signature {
        let mut shake256_context = shake256_context::init_with_seed(seed);
        let mut sig = [0u8; SIG_LEN];
        let sig_len = &mut (SIG_LEN as u64);
        let sig_type = 2;
        let mut buf = [0u8; SIGN_BUF_LEN];

        unsafe {
            assert!(
                falcon_sign_dyn(
                    &mut shake256_context as *mut shake256_context,
                    sig.as_mut_ptr() as *mut c_void,
                    sig_len as *mut u64,
                    sig_type,
                    self.0.as_ptr() as *const c_void,
                    SK_LEN as u64,
                    message.as_ptr() as *const c_void,
                    message.len() as u64,
                    buf.as_mut_ptr() as *mut c_void,
                    SIGN_BUF_LEN as u64
                ) == 0
            )
        }
        buf.zeroize();
        Signature(sig)
    }
}
