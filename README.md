CLS\_Scheme

- Using a modified version of [dilithium](https://github.com/Argyle-Software/dilithium).

To run the benchmarks, for linux based systems.
```
cargo run --release 2>/dev/null # takes a few seconds to build and run.

```
Run this command form the 'xperiments' directory.

Some unnecessary logs are also printed, thats why pipe them to dev null.

Example results: NOPKI is our implementation, comparing it with the version that users PKI.
```
-----------------------------NOPKI---------------------------
ppk elapsed: 258 us
keygen elapsed: 1500 us
sig elapsed: 2259 us
-----------------------------PKI---------------------------
keygen elapsed: 243 us
sig elapsed: 809 us

```
ppk elapsed: partial private key generation time. \
keygen elapsed: key generation time in different schemes. \
sig elapsed: time taken for signing.

By default the tests are run for dilithium-3, feature flag `mode3` for `dilithium` crate. 

To run the experiments for mode2 and mode5 just add them as the required features for `dilithium` dependency in the `Cargo.toml` file of `xperiments`. At a time only add one mode, see [`dilithium`](https://github.com/Argyle-Software/dilithium) for more details. Here is an example:

```toml
[dependencies]
pqc_dilithium = { version = "0.2.0", path = "../dilithium", features = ["mode2"] }

```
