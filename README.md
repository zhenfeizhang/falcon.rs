Falcon-rust
------

This is a rust wrapper of falcon signature scheme, submitted to NIST PQC competition.
It supports both falcon-512 and falcon-1024 parameter sets. The default is set to falcon-1024.


To build for falcon-1024
```
    cargo build [--release]
```


To build for falcon-512
```
    cargo build [--release] --no-default-features --features=falcon-512
```