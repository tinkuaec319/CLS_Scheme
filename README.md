To implement our Certificateless Signature Scheme we have modified the
dilithium implementation present at [Argyle-Software/dilithium](https://github.com/Argyle-Software/dilithium).
The modified code is present in the `dilithium` directory.

The directories `xperiment_mode2`, `xperiment_mode3` and `xperiment_mode5` are
running the experiments for different levels of dilithium. They compare the
running times of our NO-PKI scheme with a version of dilithium that use PKI infrastructure.

## Running the benchmarks.
To run the benchmark for any level of dilithim just go to that respective mode's
xperiment directory. And run the following command:

```
cargo run --release
```

This might take a few seconds to compile and run.

NOTE: you will need `Rust` setup and its package manager `cargo` for this. To know how to
install Rust, follow [Install Rust](https://rust-lang.org/tools/install/).

The above command will print something like this.

```
----------------------------- NOPKI Dilithium-3 ---------------------------
ppk elapsed: 225 us
keygen elapsed: 1620 us
sig elapsed: 3388 us
verify elapsed: 556 us
total runs: 1000, verification success: 1000
----------------------------- PKI Dilithium-3 -----------------------------
keygen elapsed: 217 us
sig elapsed: 729 us
verify elapsed: 198 us
total runs: 1000, verification success: 1000
```

This compares our NO-PKI dilithium with one that uses PKI infrastructure.

This particular run is for dilithium3, i.e. from `xperiment_mode3` directory.

`ppk elapsed`: time taken to generate partial private key. \
`keygen elapsed`: time taken to generate public and secret key \
`sig elapsed`: time taken to sign a message \
`verify elapsed`: time taken to verify the signature for a message

...and also print the number of times the whole process is done. By default 1000
iterations are done, each with a random message of length 1024 bytes.
