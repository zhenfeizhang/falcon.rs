Falcon signature and its ZKP extensions
------
Falcon signature is a lattice based signature, and a winner of [NIST PQC competition](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022).

This repo consists of the following components:
- falcon-rust: a rust wrapper of falcon signature scheme
- falcon-r1cs: an R1CS implementation for falcon verification circuit with Arkwork's backend
- falcon-plonk: a plonk implementation for falcon verification circuit with Jellyfish's backend