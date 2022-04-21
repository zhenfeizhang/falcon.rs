mod kp;
mod pk;
mod sig;
mod sk;

pub use kp::KeyPair;
pub use pk::PublicKey;
pub use sig::Signature;
pub use sk::SecretKey;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_gen() {
        let keypair = KeyPair::keygen();
        let pk2 = keypair.secret_key.make_public_key();

        assert_eq!(pk2, keypair.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::keygen();

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
        let keypair = KeyPair::keygen();
        let message = "testing message";
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());

        assert!(keypair.public_key.verify(message.as_ref(), &sig));
        assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));
    }
}
