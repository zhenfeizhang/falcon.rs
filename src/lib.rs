#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]

use libc::c_void;
use param::*;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use zeroize::Zeroize;

mod param;

include!("./bindings.rs");

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PublicKey(pub(crate) [u8; PK_LEN]);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecretKey(pub(crate) [u8; SK_LEN]);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Signature(pub(crate) [u8; SIG_LEN]);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shake256Rng([u64; 26]);

impl Shake256Rng {
    /// Initializing an RNG; sample the entropy
    /// from local PRNG.
    pub fn init() -> Self {
        let mut seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut seed);

        Self::init_with_seed(seed.as_ref())
    }

    /// Initializing an RNG from seed.
    pub fn init_with_seed(seed: &[u8]) -> Self {
        let mut ctx = shake256_context {
            opaque_contents: [0u64; 26],
        };
        unsafe {
            shake256_init_prng_from_seed(
                &mut ctx as *mut shake256_context,
                seed.as_ptr() as *const c_void,
                seed.len() as u64,
            );
        }
        Self(ctx.opaque_contents)
    }
}

impl KeyPair {
    /// generate a pair of public and secret keys
    pub fn keygen(param: u32) -> Self {
        let mut seed = [0u8; 32];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut seed);

        Self::keygen_with_seed(seed.as_ref(), param)
    }

    /// generate a pair of public and secret keys from a seed
    pub fn keygen_with_seed(seed: &[u8], param: u32) -> Self {
        let ctx = Shake256Rng::init_with_seed(seed);
        let mut shake256_context = shake256_context {
            opaque_contents: ctx.0,
        };

        let mut pk = [0u8; PK_LEN];
        let mut sk = [0u8; SK_LEN];
        let mut buf = vec![0u8; KEYGEN_BUF_LEN];

        unsafe {
            assert!(
                falcon_keygen_make(
                    &mut shake256_context as *mut shake256_context,
                    param,
                    sk.as_mut_ptr() as *mut c_void,
                    SK_LEN as u64,
                    pk.as_mut_ptr() as *mut c_void,
                    PK_LEN as u64,
                    buf.as_mut_ptr() as *mut c_void,
                    KEYGEN_BUF_LEN as u64
                ) == 0
            );
        }
        buf.zeroize();

        Self {
            public_key: PublicKey(pk),
            secret_key: SecretKey(sk),
        }
    }
}

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
        let ctx = Shake256Rng::init_with_seed(seed);
        let mut shake256_context = shake256_context {
            opaque_contents: ctx.0,
        };

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

impl PublicKey {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng() {
        let _rng1 = Shake256Rng::init();
        let _rng2 = Shake256Rng::init_with_seed("test seed".as_ref());
    }

    #[test]
    fn test_key_gen() {
        let keypair = KeyPair::keygen(9);
        println!("{:?}", keypair);

        let pk2 = keypair.secret_key.make_public_key();

        assert_eq!(pk2, keypair.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::keygen(9);

        let message = "testing message";
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());
        assert!(keypair.public_key.verify(message.as_ref(), &sig))
    }
}
