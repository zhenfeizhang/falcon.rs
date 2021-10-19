#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
#![allow(dead_code)]

use libc::c_void;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use zeroize::Zeroize;

mod decoder;
mod param;
mod poly_mul;
mod utils;
mod binder;

use decoder::*;
pub use param::*;
use poly_mul::*;
use utils::*;
use binder::*;


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

// wrappers for unsafe functions
impl shake256_context {
    /// Initializing an RNG.
    pub fn init() -> Self {
        let mut ctx = shake256_context {
            opaque_contents: [0u64; 26],
        };
        unsafe {
            shake256_init(&mut ctx as *mut shake256_context);
        }
        ctx
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
        ctx
    }

    /// Inject data to the RNG
    pub fn inject(&mut self, data: &[u8]) {
        unsafe {
            shake256_inject(
                self as *mut shake256_context,
                data.as_ptr() as *const c_void,
                data.len() as u64,
            )
        }
    }

    /// Finalize the RNG
    pub fn finalize(&mut self) {
        unsafe { shake256_flip(self as *mut shake256_context) }
    }

    /// Extract data from the RNG
    pub fn extract(&mut self, len: usize) -> Vec<u8> {
        let data = vec![0u8; len];
        unsafe {
            shake256_extract(
                self as *mut shake256_context,
                data.as_ptr() as *mut c_void,
                len as u64,
            );
        }
        data
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
        let mut shake256_context = shake256_context::init_with_seed(seed);
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

    // Unpack the public key into a vector of integers
    // within the range of [0, 12289)
    pub fn unpack(&self) -> [u16; 512] {
        assert!(self.0[0] == 9);
        mod_q_decode(self.0[1..].as_ref())
    }

    // using rust's native functions to check the validity of a signature
    pub fn verify_rust_native(&self, message: &[u8], sig: &Signature) -> bool {
        let pk = self.unpack();
        let sig_u = sig.unpack();
        let hm = hash_message(message, sig);

        // compute v = hm - uh
        let uh = poly_mul(&pk, &sig_u);

        let mut v = [0i16; 512];
        for (c, (&a, &b)) in v.iter_mut().zip(uh.iter().zip(hm.iter())) {
            let c_i32 = (b as i32) + (a as i32);
            *c = (c_i32 % 12289) as i16;

            if *c >= 6144 {
                *c -= 12289;
            }

            if *c < -6144 {
                *c += 12289;
            }
        }
        let l2_norm = l2_norm(&sig_u, &v);
        l2_norm <= SIG_L2_BOUND
    }
}

impl Signature {
    // Unpack the signature into a vector of integers
    // within the range of [0, 12289)
    pub fn unpack(&self) -> [i16; 512] {
        let res = comp_decode(self.0[41..].as_ref());
        res
    }
}

fn hash_message(message: &[u8], sig: &Signature) -> [u16; 512] {
    // initialize and finalize the rng
    let mut rng = shake256_context::init();
    rng.inject(sig.0[1..41].as_ref());
    rng.inject(message);
    rng.finalize();

    // extract the data from rng and build the output
    let mut res = [0u16; 512];
    let mut i = 0;
    while i < 512 {
        let output = rng.extract(2);
        let mut coeff = (output[0] as u16) << 8 | (output[1] as u16);
        if coeff < 61445 {
            while coeff >= 12289 {
                coeff -= 12289;
            }
            res[i] = coeff;
            i += 1;
        }
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng() {
        let _rng1 = shake256_context::init();
        let _rng2 = shake256_context::init_with_seed("test seed".as_ref());
    }

    #[test]
    fn test_key_gen() {
        let keypair = KeyPair::keygen(9);
        let pk2 = keypair.secret_key.make_public_key();

        assert_eq!(pk2, keypair.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::keygen(9);

        let message = "testing message";
        let message2 = "another testing message";
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());
        assert!(keypair.public_key.verify(message.as_ref(), &sig));
        assert!(!keypair.public_key.verify(message2.as_ref(), &sig))
    }

    #[test]
    fn test_unpacking() {
        let keypair = KeyPair::keygen(9);
        let message = "testing message";
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());

        assert!(keypair.public_key.verify(message.as_ref(), &sig));
        assert!(keypair
            .public_key
            .verify_rust_native(message.as_ref(), &sig));
    }
}
