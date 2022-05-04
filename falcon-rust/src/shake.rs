pub use crate::binder::shake256_context;
use crate::binder::*;
use libc::c_void;

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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_prng() {
        let _rng1 = shake256_context::init();
        let _rng2 = shake256_context::init_with_seed("test seed".as_ref());
    }
}
