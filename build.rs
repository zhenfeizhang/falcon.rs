extern crate cc;

fn main() {

    let src = [
        "Falcon-impl-round3/codec.c",
        "Falcon-impl-round3/common.c",
        "Falcon-impl-round3/falcon.c",
        "Falcon-impl-round3/fft.c",
        "Falcon-impl-round3/fpr.c",
        "Falcon-impl-round3/keygen.c",
        "Falcon-impl-round3/rng.c",
        "Falcon-impl-round3/shake.c",
        "Falcon-impl-round3/sign.c",
        "Falcon-impl-round3/vrfy.c",
    ];
    let mut builder = cc::Build::new();

    let build = builder
        .files(src.iter())
        .include("Falcon-impl-round3")
        .flag("-Wno-unused-parameter");
        
    build.compile("falcon");

}
