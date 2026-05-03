#[cfg(feature = "aes")]
mod aes256ctr;
mod api;
mod fips202;
mod ntt;
mod packing;
mod params;
mod poly;
mod polyvec;
mod randombytes;
mod reduce;
mod rounding;
mod sign;
mod symmetric;
pub use params::*;

pub use poly::{Poly, poly_caddq, poly_add, poly_reduce, poly_decompose, poly_make_hint};
pub use polyvec::{Polyveck, Polyvecl, polyveck_caddq, polyveck_add};

// No PKI related stuff.
pub mod nopki;

pub use api::*;

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(dilithium_kat)]
pub use sign::{
  crypto_sign_keypair, crypto_sign_signature, crypto_sign_verify,
};

pub fn decompose_test(a0: &mut i32, a: i32) -> i32 {
    rounding::decompose(a0, a)
}
