#[macro_use]
extern crate criterion;

use criterion::Criterion;
use falcon_rust::{KeyPair, NTTPolynomial, Polynomial};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

criterion_main!(bench);
criterion_group!(bench, bench_falcon, bench_ntt,);

fn bench_ntt(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let num_tests = 1000;
    let polys: Vec<Polynomial> = (0..num_tests).map(|_| Polynomial::rand(&mut rng)).collect();
    let another_polys: Vec<Polynomial> =
        (0..num_tests).map(|_| Polynomial::rand(&mut rng)).collect();
    let poly_ntts: Vec<NTTPolynomial> = polys.iter().map(|x| x.into()).collect();
    let another_poly_ntts: Vec<NTTPolynomial> = another_polys.iter().map(|x| x.into()).collect();

    let mut bench_group = c.benchmark_group("NTT transforms");
    bench_group.sample_size(100);
    let bench_str = format!("{} of forward ntt", num_tests);
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            for i in 0..num_tests {
                let _: NTTPolynomial = (&polys[i]).into();
            }
        });
    });

    let poly_ntts_clone = poly_ntts.clone();
    let bench_str = format!("{} of inverse NTT transform", num_tests);
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            for i in 0..num_tests {
                let _: Polynomial = (&poly_ntts_clone[i]).into();
            }
        });
    });

    let poly_ntts_clone = poly_ntts.clone();
    let another_poly_ntts_clone = another_poly_ntts.clone();
    let bench_str = format!("{} of ntt additions", num_tests);
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            for i in 0..num_tests {
                let _ = poly_ntts_clone[i].clone() + another_poly_ntts_clone[i].clone();
            }
        });
    });

    let bench_str = format!("{} of ntt multiplications", num_tests);
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            for i in 0..num_tests {
                let _ = poly_ntts[i].clone() * another_poly_ntts[i].clone();
            }
        });
    });
}

fn bench_falcon(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("Signature scheme");
    let num_tests = 10;
    bench_group.sample_size(10);

    {
        let bench_str = format!("{} hash message", num_tests);
        let message = "testing message";
        bench_group.bench_function(bench_str, move |b| {
            b.iter(|| {
                for _ in 0..num_tests {
                    let _ = Polynomial::from_hash_of_message(message.as_ref(), [0u8; 40].as_ref());
                }
            });
        });
    }

    {
        let bench_str = format!("{} key generation", num_tests);
        bench_group.bench_function(bench_str, move |b| {
            b.iter(|| {
                for _ in 0..num_tests {
                    let _ = KeyPair::keygen();
                }
            });
        });
    }

    {
        let keypair = KeyPair::keygen();
        let message = "testing message";
        let bench_str = format!("{} signings", num_tests);
        bench_group.bench_function(bench_str, move |b| {
            b.iter(|| {
                for _ in 0..num_tests {
                    let _ = keypair
                        .secret_key
                        .sign_with_seed("test seed".as_ref(), message.as_ref());
                }
            });
        });
    }
    {
        let keypair = KeyPair::keygen();
        let message = "testing message";
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());
        let bench_str = format!("{} verifications w C wrapper", num_tests);
        bench_group.bench_function(bench_str, move |b| {
            b.iter(|| {
                for _ in 0..num_tests {
                    assert!(keypair.public_key.verify(message.as_ref(), &sig));
                }
            });
        });
    }

    {
        let keypair = KeyPair::keygen();
        let message = "testing message";
        let sig = keypair
            .secret_key
            .sign_with_seed("test seed".as_ref(), message.as_ref());
        let bench_str = format!("{} verifications in rust", num_tests);
        bench_group.bench_function(bench_str, move |b| {
            b.iter(|| {
                for _ in 0..num_tests {
                    assert!(keypair.public_key.verify_rust(message.as_ref(), &sig));
                }
            });
        });
    }
}
