Falcon R1CS
-----

This crate generates the R1CS circuit for Falcon signature verifications.

# Build

To build for falcon-1024
```
cargo build [--release]
```


To build for falcon-512
```
cargo build [--release] --features=falcon-512 --no-default-features
```

# Example

`falcon-r1cs/example/pok_sig.rs` shows an example of how to generate a proof of knowledge
of the signature for Falcon. To run this example with Falcon-1024
```
cargo run --release --example pok_sig
```
with Falcon-512
```
cargo run --release --example pok_sig --no-default-features --features=falcon-512
```

# Performance

The total #constraints for a single Falcon-1024 signature verification is listed
below. The table can be obtained via
```
cargo run --release --example constraint_counts
```
|            | # instance variables |      # witness |      #constraints |
|---|---:|---:|---:|
ntt conversion|                      0 |          29696 |             30720 |
verify with ntt|                  2049 |         156724 |            162870 |
verify with schoolbook|           2049 |        1150004 |           1156150 |

That for Falcon-512 can be obtained via
```
cargo run --release --example constraint_counts --no-default-features --features=falcon-512
```

|                 | # instance variables |      # witness |      #constraints |
|---|---:|---:|---:|
|ntt conversion|                      0 |          14848 |             15360 |
|verify with ntt|                  1025 |          78386 |             81460 |
|verify with schoolbook|           1025 |         312882 |            315956 |



In comparison, an ECC scalar multiplication over Jubjub curve (\~256 bits) takes a little over __3k__ constraints (example [here](https://github.com/zhenfeizhang/bandersnatch/blob/main/bandersnatch/examples/constraint_count_jubjub.rs)).
So this will be something like 10 times more costly than proving, say, Schnorr over Jubjub curve.

# Pseudocode for NTT based verification

```
// signature; requires 1 ntt conversion circuit
u := sig
u_var = u.into_circuit()
u_ntt_var = ntt_circuit(u)

// public key; no ntt conversion circuit is required
h := pk              
h_ntt = ntt(h)                    
h_ntt_var = h_ntt.into_circuit()

// hash of the message; no ntt conversion circuit is required
hm = hash_message(msg, nonce) 
hm_ntt = ntt(hm)
hn_ntt_var = hm_ntt.into_circuit()

// compute v = hm + u * h in the clear
v =  hm + u * h

// compute v = hm + u * h with circuit
v_ntt_var = hm_ntt_var + u_ntt_var * h_ntt_var

// enforce v_ntt_var is indeed v, requires 1 ntt conversion
v_var = v.into_circuit()
v_ntt_var.is_equal( ntt_circuit(v_var) )

// enforce the l2 norm constraints
l2_norm_var = compute_l2_norm(v_var, u_var)
l2_nrom_var.is_smaller( L2_NORM_BOUND )
```

# Pseudocode for NTT conversion

The following code implements NTT circuit with just 15K constraints.
The component is 
- `n log(n)` number of __native__ field arithmetics
- `n` number of __non-native__ field arithmetics
In comparison, a previous version [here](https://github.com/zhenfeizhang/falcon-r1cs/blob/e171fe2d51cb1a679d3e78ed188e7242e03191e2/src/gadgets/ntt.rs#L10)
takes `n log(n)` number of  __non-native__ field arithmetics.
Since a non-native operation is around 30 times more costly than
a native one, we can fairly claim that this code achieves _almost_
linear cost for NTT circuit; and improves upon [the previous version](https://github.com/zhenfeizhang/falcon-r1cs/blob/e171fe2d51cb1a679d3e78ed188e7242e03191e2/src/gadgets/ntt.rs#L10)
by a factor of `~log(n)`.

The core idea is to handle the first `while loop` with native field arithmetic.
A subtly is how to compute a negation of an integer without modulo arithmetics.
For an integer `v`, and for a given round `l`,
we need to proper bound the max value of the current loop, i.e., 
`bound := 2^l * q^{l+1}`, and use this bound, which is also a multiple of q
to subtract `v`, i.e., `neg_v = bound - v`.
Know the bound for `u`, `v` and `neg_v` gives us a bound for `output` for the current
round, which recursively gives the bound for next round.

``` rust
// the  constant wires are [q, 2*q^2, 4 * q^3, ..., 2^9 * q^10]
let mut output = input.to_vec();
let mut t = 512;
for l in 0..9 {
    let m = 1 << l;
    let ht = t / 2;
    let mut i = 0;
    let mut j1 = 0;
    while i < m {
        let s = param[m + i].clone();
        let j2 = j1 + ht;
        let mut j = j1;
        while j < j2 {
            // for the l-th loop, we know that all the output's
            // coefficients are less than q^{l+1}
            // therefore we have
            //  u < 2^l * q^{l+1}
            //  v < 2^l * q^{l+2}
            // and we have
            //  neg_v = q^{l+2} - v
            // note that this works when q^10 < F::Modulus
            // so all operations here becomes native field operations
            let u = output[j].clone();
            let v = &output[j + ht] * &s;
            let neg_v = &const_vars[l + 1] - &v;

            // output[j] and output[j+ht]
            // are between 0 and 2^{l+1} * q^{l+2}
            output[j] = &u + &v;
            output[j + ht] = &u + &neg_v;
            j += 1;
        }
        i += 1;
        j1 += t
    }
    t = ht;
}

// perform a final mod reduction to make the
// output into the right range
// this is the only place that we need non-native circuits
for e in output.iter_mut() {
    *e = mod_q(cs.clone(), e, &const_vars[0])?;
}
```

