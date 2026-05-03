#![allow(unused)]

use pqc_dilithium::*;

// use pqc_dilithium::nopki;

// const Q_I32: i32 = 21;

use std::time::{self, Instant};

static mut RAND_STATE: i64 = 0xcafef00dfeedfaceu64 as i64;

fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn init_rand_state() {
    let mut tick = rdtsc();
    tick = tick.wrapping_mul(tick);

    unsafe { RAND_STATE = tick as i64 };
}

fn fastrand() -> i64 {
    let mut x = unsafe { RAND_STATE };
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;

    unsafe { RAND_STATE = x };

    x
}

// Input: `a` must be positive.
//
// Returns r1
fn decompose_scaled(a0: &mut i32, a: i32) -> i32 {
    // const Q_I32: i32 = 21;

    const ALPHA: i32 = 4 * GAMMA2_I32;
    // const ALPHA: i32 = 4;

    let mut r0 = a % ALPHA;
    if r0 > ALPHA / 2 {
        r0 -= ALPHA;
    } else if r0 <= -ALPHA / 2 {
        r0 += ALPHA;
    }

    let r1: i32;
    if a - r0 == Q_I32 - 1 {
        r1 = 0;
        r0 -= 1;
    } else {
        r1 = (a - r0) / ALPHA;
    }

    *a0 = r0;

    r1
}

pub fn use_hint_scaled(a: i32, hint: u8) -> i32 {
    let mut a0 = 0i32;
    let a1 = decompose_scaled(&mut a0, a);

    if hint == 0 {
        return a1;
    }

    const M: i32 = if GAMMA2 == (Q - 1) / 32 {
        8
    } else {
        22
    };

    if a0 > 0 {
        return (((a1 + 1) % M) + M) % M;
    } else {
        return (((a1 - 1) % M) + M) % M;
    }
}

pub fn make_hint_scaled(a0: i32, a1: i32) -> u8 {
    /*
    if a0 > GAMMA2_I32 || a0 < -GAMMA2_I32 || (a0 == -GAMMA2_I32 && a1 != 0) {
        return 1;
    }
    return 0;
    */

    let z = a0;
    let r = a1;

    let r_z = (((r + z) % Q_I32) + Q_I32) % Q_I32;

    let mut r_z_l = 0;
    let r_z_h = decompose_scaled(&mut r_z_l, r_z);

    let mut r_l = 0;
    let r_h = decompose_scaled(&mut r_l, r);

    (r_h != r_z_h) as u8
}

mod poly {
    use super::*;

    pub fn poly_make_hint_scaled(hint: &mut Poly, z: &Poly, y: &Poly) -> i32 {
        let mut s = 0;
        for i in 0..N {
            hint.coeffs[i] = make_hint_scaled(z.coeffs[i], y.coeffs[i]) as i32;
            s += hint.coeffs[i];
        }

        return s;
    }

    pub fn poly_use_hint_scaled(high: &mut Poly, hint: &Poly, y: &Poly) {
        for i in 0..N {
            high.coeffs[i] = use_hint_scaled(y.coeffs[i], hint.coeffs[i] as u8);
        }
    }

    pub fn poly_decompose_scaled(high: &mut Poly, low: &mut Poly, y: &Poly) {
        for i in 0..N {
            let mut coeff_low = 0;
            let coeff_high = decompose_scaled(&mut coeff_low, y.coeffs[i]);

            high.coeffs[i] = coeff_high;
            low.coeffs[i] = coeff_low;
        }
    }
}

mod polyvec {
    use super::*;

    pub fn polyveck_make_hint_scaled(
        hint: &mut Polyveck,
        z: &Polyveck,
        y: &Polyveck
    ) -> i32 {
        let mut s = 0;
        for i in 0..K {
            s += poly::poly_make_hint_scaled(&mut hint.vec[i], &z.vec[i], &y.vec[i]);
        }

        return s;
    }

    pub fn polyveck_use_hint_scaled(
        high: &mut Polyveck,
        hint: &Polyveck,
        y:    &Polyveck,
    ) {
        for i in 0..K {
            poly::poly_use_hint_scaled(&mut high.vec[i], &hint.vec[i], &y.vec[i]);
        }
    }

    pub fn polyveck_decompose_scaled(high: &mut Polyveck, low: &mut Polyveck, 
        y: &Polyveck) {
        for i in 0..K {
            poly::poly_decompose_scaled(&mut high.vec[i], &mut low.vec[i], &y.vec[i]);
        }
    }
}

fn polyvectorization() {
    init_rand_state();
    println!("{}", Q_I32);
    // let mut r_prime = [0u8; 64];
    // rand::fill(&mut r_prime[..]);
    // println!("r_prime: {:?}", r_prime);

    /*
    let mut unmatched = 0;
    println!("{}", Q_I32);
    for i in 0..Q_I32 {

        let z = fastrand() as i32 % GAMMA2_I32;

        let a0 = i;
        let a0_z = (((a0 + z) % Q_I32) + Q_I32) % Q_I32;
        let mut a0_z_l = 0;
        let a0_z_h = decompose_scaled(&mut a0_z_l, a0_z);

        let hint = make_hint_scaled(z, a0);

        let hinted = use_hint_scaled(a0, hint);

        if hinted != a0_z_h {
            unmatched += 1;
        }

    }
    println!("unmatched: {unmatched}");
    */

    /*
    let mut count_satisfied = 0;

    for i in 0..1024 * 1024 {
        let mut z = Poly::default();
        rand::fill(&mut z.coeffs[..]);
        for i in 0..N {
            z.coeffs[i] %= (2 * GAMMA2_I32);
        }

        let mut y = Poly::default();
        rand::fill(&mut y.coeffs[..]);
        for i in 0..N {
            y.coeffs[i] %= Q_I32;
        }
        poly_caddq(&mut y);

        // Add z to y.
        let mut y_z = y;
        poly_add(&mut y_z, &z);

        // Decompose y_z in to high and low bits.
        let mut low = Poly::default();
        let mut high = Poly::default();
        poly_caddq(&mut y_z);
        poly::poly_decompose_scaled(&mut high, &mut low, &y_z);

        let mut hint = Poly::default();
        let n = poly::poly_make_hint_scaled(&mut hint, &z, &y);
        // println!("hint: {}", n);

        let mut high_hinted = Poly::default();
        poly::poly_use_hint_scaled(&mut high_hinted, &hint, &y);

        assert_eq!(high_hinted.coeffs, high.coeffs);

        if n < 55 {
            count_satisfied += 1;
        }
    }
    println!("count_satisfied: {}", count_satisfied);
    */

    let mut count_satisfied = 0;

    for i in 0..1024 {
        let mut z = Polyveck::default();
        for i in 0..K {
            rand::fill(&mut z.vec[i].coeffs[..]);
            for j in 0..N {
                z.vec[i].coeffs[j] %= (2 * GAMMA2_I32);
            }
        }

        let mut y = Polyveck::default();
        for i in 0..K {
            rand::fill(&mut y.vec[i].coeffs[..]);
            for j in 0..N {
                y.vec[i].coeffs[j] %= Q_I32;
            }
        }
        polyveck_caddq(&mut y);

        // Add z to y.
        let mut y_z = y;
        polyveck_add(&mut y_z, &z);

        // Decompose y_z in to high and low bits.
        let mut low = Polyveck::default();
        let mut high = Polyveck::default();
        polyveck_caddq(&mut y_z);
        polyvec::polyveck_decompose_scaled(&mut high, &mut low, &y_z);

        let mut hint = Polyveck::default();
        let n = polyvec::polyveck_make_hint_scaled(&mut hint, &z, &y);
        // println!("hint: {}", n);

        let mut high_hinted = Polyveck::default();
        polyvec::polyveck_use_hint_scaled(&mut high_hinted, &hint, &y);

        // assert_eq!(high_hinted.coeffs, high.coeffs);
        for i in 0..K {
            assert_eq!(high_hinted.vec[i].coeffs, high.vec[i].coeffs);
        }

        if n < 8 * 55 {
            count_satisfied += 1;
        }
    }
    println!("count_satisfied: {}", count_satisfied);
}

/*
fn decomposer_test() {
    init_rand_state();
    // let begin = Instant::now();
    let mut unmatched = 0;
    println!("{}", Q_I32);
    for i in 0..Q_I32 {
        /*
        // let c = rand::random::<i32>();
        // let i = ((c % Q_I32) + Q_I32) % Q_I32;
        let mut a0 = i;
        let a1 = decompose_test(&mut a0, i);
        // println!("({}, {})", a1, a0);

        let mut r0 = i;
        let r1 = decompose_scaled(&mut r0, i);
        // println!("{i}: ({}, {}), ({}, {})", a1, a0, r1, r0);
        assert_eq!(a0, r0);
        assert_eq!(a1, r1);

        std::hint::black_box((a0, a1, r0, r1));
        */

        /*
        let z = fastrand() as i32 % GAMMA2_I32;

        let a0 = i;
        let a0_z = (((a0 + z) % Q_I32) + Q_I32) % Q_I32;
        let mut a0_z_l = 0;
        let a0_z_h = decompose(&mut a0_z_l, a0_z);

        let hint = make_hint(z, a0);

        let hinted = use_hint(a0, hint);
        // assert_eq!(hinted, a0_z_h, "i: {}", i);
        // println!("i: {i}, hinted: {}, a0_z_h: {}", hinted, a0_z_h);
        */

        let z = fastrand() as i32 % GAMMA2_I32;

        let a0 = i;
        let a0_z = (((a0 + z) % Q_I32) + Q_I32) % Q_I32;
        let mut a0_z_l = 0;
        let a0_z_h = decompose_scaled(&mut a0_z_l, a0_z);

        let hint = make_hint_scaled(z, a0);

        let hinted = use_hint_scaled(a0, hint);
        // assert_eq!(hinted, a0_z_h, "i: {}", i);
        // println!("i: {i}, hinted: {}, a0_z_h: {}", hinted, a0_z_h);

        if hinted != a0_z_h {
            unmatched += 1;
        }

    }
    println!("unmatched: {unmatched}");
    // let elapsed = begin.elapsed();
    // println!("elapsed: {}", elapsed.as_millis());
}
*/

fn main() {
    let mut identity = [0u8; 32];
    let mut rho = [0u8; SEEDBYTES];

    rand::fill(&mut identity[..]);
    rand::fill(&mut rho[..]);

    let ppk_begin = time::Instant::now();
    let (params, _msk, ppk) = nopki::kgc::partial_private_key_generation(
        &identity[..], &rho[..]);
    let ppk_elapsed = ppk_begin.elapsed();
    println!("ppk elapsed: {} us", ppk_elapsed.as_micros());

    let nopki_keygen_begin = time::Instant::now();
    let (pk, sk) = nopki::user_keygen::user_generate_key(&identity[..], 
        params.clone(), ppk, None);
    let nopki_keygen_elapsed = nopki_keygen_begin.elapsed();
    println!("nopki keygen elapsed: {} us", nopki_keygen_elapsed.as_micros());

    let nopki_sig_begin = time::Instant::now();
    let nopki_signature = nopki::user_keygen::generate_signature("lorem ipsum dolor sit amet".as_bytes(), &identity, params, pk, sk);

    let nopki_sig_elapsed = nopki_sig_begin.elapsed();
    println!("nopki sig elapsed: {}", nopki_sig_elapsed.as_micros());

    let pki_keygen_begin = time::Instant::now();
    let keys = Keypair::generate();
    let pki_keygen_elapsed = pki_keygen_begin.elapsed();
    println!("pki keygen elapsed: {} us", pki_keygen_elapsed.as_micros());

    let sig_begin = time::Instant::now();
    let signature = keys.sign("lorem ipsum dolor sit amet".as_bytes());
    let sig_elapsed = sig_begin.elapsed();
    println!("sig elapsed: {}", sig_elapsed.as_micros());

    let nopki_verify = nopki::user_keygen::verify_sign(
        "lorem ipsum dolor sit amet".as_bytes(),
        &identity,
        nopki_signature,
        params.clone(),
        pk.clone(),
    );
    println!("nopki verification: {}", nopki_verify);

    /*
    let v = verify(&signature, "lorem ipsum dolor sit amet".as_bytes(), 
        &keys.public).is_ok();

    println!("normal verify: {}", v);
    */
}
