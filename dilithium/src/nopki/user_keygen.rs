#![allow(unused)]

pub const POLY_V_H_PACKEDBYTES: usize = POLYW1_PACKEDBYTES;

use crate::{
    params::*,
    poly::*,
    polyvec::*,
    packing::*,
    fips202::*,
    randombytes::*,

    nopki::kgc::*,
};

fn rdtsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[derive(Copy, Clone)]
pub struct PublicKey {
    pub b12_h: Polyveck,
    pub z1:    Polyvecl,
    pub z2:    Polyvecl,
    pub c:     [u8; SEEDBYTES],
}

#[derive(Copy, Clone)]
pub struct SecretKey {
    pub b11_l:     Polyveck,
    pub b12_l:     Polyveck,
    pub y11:       Polyvecl,
    pub y12:       Polyvecl,
    pub s11:       Polyvecl,
    pub s12_prime: Polyvecl,
}

#[derive(Debug)]
pub enum KeygenError {
    ThresholdError,
}

pub fn user_generate_key(
    // pk:       &mut [u8],
    // sk:       &mut [u8],
    identity: &[u8],
    // params:   &[u8],
    // ppk:      &[u8],
    params:   Params,
    ppk:      PartialPrivateKey,
    seed:     Option<&[u8]>,
) -> Result<(PublicKey, SecretKey), KeygenError> {
    assert!(seed.is_none());
    // Buffer to contain seed.
    let mut init_seed = [0u8; SEEDBYTES];

    // If seed is Some then take that as the seed otherwise generate new random
    // seed.
    if let Some(seed) = seed {
        init_seed.copy_from_slice(seed);
    } else {
        randombytes(&mut init_seed, SEEDBYTES);
    }

    // Unpack params.
    /*
    let mut rho = [0u8; SEEDBYTES];
    let mut b11_h = Polyveck::default();
    unpack_params(&mut rho, &mut b11_h, params);
    */

    let Params {mut rho, mut b11_h} = params;

    assert_eq!(rho.len(), SEEDBYTES);
    assert_eq!(identity.len(), ID_SIZE);

    // Unpack ppk into s11, y11, b11_l.
    /*
    let mut s11 = Polyvecl::default();
    let mut y11 = Polyvecl::default();
    let mut b11_l = Polyveck::default();
    unpack_ppk(&mut s11, &mut y11, &mut b11_l, ppk);
    */
    let PartialPrivateKey {mut s11, mut y11, mut b11_l} = ppk;

    let mut s11_hat = s11;
    polyvecl_ntt(&mut s11_hat);

    let mut y11_hat = y11;
    polyvecl_ntt(&mut y11_hat);

    let mut b11_l_hat = b11_l;
    polyveck_ntt(&mut b11_l_hat);

    // 1) Compute seed r and r_prime
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES]; // r || r_prime

    let mut hash_input = [0u8; SEEDBYTES + ID_SIZE]; // rho || ID_A
    hash_input[..SEEDBYTES].copy_from_slice(&rho);
    hash_input[SEEDBYTES..].copy_from_slice(&identity);

    // Write seed to seedbuf.
    shake256(&mut seedbuf, 2 * SEEDBYTES + CRHBYTES, &hash_input, SEEDBYTES + ID_SIZE);

    let mut r = [0u8; 2 * SEEDBYTES];
    let mut r_prime = [0u8; CRHBYTES];

    r.copy_from_slice(&seedbuf[..2 * SEEDBYTES]);
    r_prime.copy_from_slice(&seedbuf[2 * SEEDBYTES..]);

    // 2) Seed Expansion: mat_a11, mat_a12.

    // Big matrix to hold both mat_a11 and mat_a12.
    let mut mat = [Polyvecl::default(); K * 2]; // K * 2 rows

    polyvec_matrix_expand(&mut mat[..K], &r[..SEEDBYTES]);
    polyvec_matrix_expand(&mut mat[K..], &r[SEEDBYTES..]);

    // First K rows to mat_a11.
    let mut mat_a11 = [Polyvecl::default(); K];
    mat_a11.copy_from_slice(&mat[..K]);
    // println!("mat_a11: {:?}", mat_a11[0].vec);

    // Later K rows to mat_a12.
    let mut mat_a12 = [Polyvecl::default(); K];
    mat_a12.copy_from_slice(&mat[K..]);
    // println!("mat_a12: {:?}", mat_a12[0].vec);

    // 3) Secret Sampling.

    // Generate s12_prime.
    let mut s12_prime = Polyvecl::default();
    polyvecl_uniform_eta(&mut s12_prime, &r_prime, 0);

    // NTT form of s12_prime
    let mut s12_prime_hat = s12_prime;
    polyvecl_ntt(&mut s12_prime_hat);

    // 4) Public Matrix Generation: b11 := mat_a12 x s12_prime + e12

    // Sample e12.
    let mut e12 = Polyveck::default();
    polyveck_uniform_eta(&mut e12, &r_prime, L_U16);

    let mut e12_hat = e12;
    polyveck_ntt(&mut e12_hat); // NTT form of e12

    let (mut b12_h, mut b12_l) = (
        Polyveck::default(),
        Polyveck::default(),
    );

    // Matrix-vector multiplication
    polyvec_matrix_pointwise_montgomery(&mut b12_h, &mat_a12, &s12_prime_hat);
    polyveck_reduce(&mut b12_h);
    polyveck_invntt_tomont(&mut b12_h);

    // Add error vector e12
    polyveck_add(&mut b12_h, &e12);

    // Extract b12_h
    polyveck_caddq(&mut b12_h);
    polyveck_power2round(&mut b12_h, &mut b12_l);

    let mut b12_l_hat = b12_l;
    polyveck_ntt(&mut b12_l_hat);

    // 6) Compute v11_h = A11 x y11
    let (mut v11_h, mut v11_l) = (Polyveck::default(), Polyveck::default());
    polyvec_matrix_pointwise_montgomery(&mut v11_h, &mat_a11, &y11_hat);
    polyveck_reduce(&mut v11_h);
    polyveck_invntt_tomont(&mut v11_h);

    // v1 will be (v11 + v12) inside the loop. Inside the loop only v12 changes,
    // not the v11. So store v11 in v1 here.
    let v1 = v11_h;

    // Decompose v11 into (v11_h, v11_l)
    // polyveck_caddq(&mut v11_h);
    polyveck_caddq(&mut v11_h);
    polyveck_decompose(&mut v11_h, &mut v11_l);

    // 7) Compute: e11
    let mut e11 = b11_h;
    polyveck_shiftl(&mut e11);
    polyveck_add(&mut e11, &b11_l);

    // Result of the matrix multiplication of mat_a11 with s11.
    let mut v_a11_s11 = Polyveck::default();
    polyvec_matrix_pointwise_montgomery(&mut v_a11_s11, &mat_a11, &s11_hat);
    polyveck_reduce(&mut v_a11_s11);
    polyveck_invntt_tomont(&mut v_a11_s11);

    // Update e11 by subtracting v_a11_s11 from it.
    polyveck_sub(&mut e11, &v_a11_s11);

    let mut e11_hat = e11;
    polyveck_ntt(&mut e11_hat);

    // 8) z := nil
    // let mut z = [Polyvecl::default(); 2]; // (z1, z2)

    // Allocate intermediates.
    let mut y12 = Polyvecl::default();
    let (mut v12_h, mut v12_l) = (Polyveck::default(), Polyveck::default());
    // let mut v1 = Polyveck::default();

    let mut state = KeccakState::default();

    let mut nonce = 0u16;

    const RETRY_THRESHOLD: usize = 25;
    let mut retry = 0;

    loop {
        if retry == RETRY_THRESHOLD {
            break Err(KeygenError::ThresholdError);
        }

        // let mut v1 = v1;

        // Sample intermediate vector y12
        polyvecl_uniform_gamma1(&mut y12, &r_prime, nonce);
        nonce += 1;

        // Compute v12_h as matrix-vector multiplication of mat_a12 and y12
        let mut y12_hat = y12;
        polyvecl_ntt(&mut y12_hat);
        
        polyvec_matrix_pointwise_montgomery(&mut v12_h, &mat_a12, &y12_hat);
        polyveck_reduce(&mut v12_h);
        polyveck_invntt_tomont(&mut v12_h);
        // println!("v12_h: {:?}", v12_h.vec[0]);

        // Create v1 = v11 + v12 before decomposing v12 into (v12_h, v12_l)
        let mut v1_full = v1;
        polyveck_add(&mut v1_full, &v12_h);
        // polyveck_reduce(&mut v1_full);

        // Decompose v12 into (v12_h, v12_l)
        polyveck_caddq(&mut v12_h);
        polyveck_decompose(&mut v12_h, &mut v12_l);

        // Sum of v11_h and v12_h
        let mut v_h_sum = v11_h;
        polyveck_add(&mut v_h_sum, &v12_h);

        polyveck_reduce(&mut v_h_sum);
        polyveck_caddq(&mut v_h_sum);

        let mut v_h_sum_packed = [0u8; K * POLY_V_H_PACKEDBYTES];
        polyveck_pack_w1(v_h_sum_packed.as_mut_slice(), &v_h_sum);

        let mut c = [0u8; SEEDBYTES];
        // let (mut c1_seed, mut c2_seed) = ([0u8; SEEDBYTES], [0u8; SEEDBYTES]);

        state.init();
        shake256_absorb(&mut state, &r, 2 * SEEDBYTES);
        shake256_absorb(&mut state, &v_h_sum_packed, K * POLY_V_H_PACKEDBYTES);
        shake256_finalize(&mut state);
        shake256_squeeze(&mut c, SEEDBYTES, &mut state);

        // Got c, now use it to create two seeds to then use them to sample from
        // B_tau.

        /*
        state.init();
        shake256_absorb(&mut state, &c, SEEDBYTES);
        shake256_finalize(&mut state);
        shake256_squeeze(&mut c1_seed, SEEDBYTES, &mut state);
        shake256_squeeze(&mut c2_seed, SEEDBYTES, &mut state);
        */

        /*
        c1_seed.copy_from_slice(&c[..SEEDBYTES]);
        c2_seed.copy_from_slice(&c[SEEDBYTES..]);
        */

        // Sample c1 and c2 from B_tau and convert them to NTT form.
        let mut c1 = Poly::default();
        poly_challenge_nonced(&mut c1, &c, 0);
        // poly_challenge(&mut c1, &c);
        poly_ntt(&mut c1);

        // println!("c1: {:?}", c1);

        let mut c2 = Poly::default();
        poly_challenge_nonced(&mut c2, &c, 1);
        // poly_challenge(&mut c2, &c);
        poly_ntt(&mut c2);

        // Create z1 and z2.
        let (mut z1, mut z2) = (Polyvecl::default(), Polyvecl::default());

        polyvecl_pointwise_poly_montgomery(&mut z1, &c1, &s11_hat);
        polyvecl_invntt_tomont(&mut z1);
        polyvecl_add(&mut z1, &y11);
        polyvecl_reduce(&mut z1);

        polyvecl_pointwise_poly_montgomery(&mut z2, &c2, &s12_prime_hat);
        polyvecl_invntt_tomont(&mut z2);
        polyvecl_add(&mut z2, &y12);
        polyvecl_reduce(&mut z2);

        // Check norm of z = (z1 z2)^T
        if polyvecl_chknorm(&z1, (GAMMA1 - BETA) as i32) > 0 {
            eprintln!("fail 1: z1 norm");
            retry += 1;
            continue;
        }

        if polyvecl_chknorm(&z2, (GAMMA1 - BETA) as i32) > 0 {
            eprintln!("fail 1: z2 norm");
            retry += 1;
            continue;
        }

        let mut rpoly_h = v1_full;
        let (mut c1_e11, mut c2_e12) = (Polyveck::default(), Polyveck::default());

        polyveck_pointwise_poly_montgomery(&mut c1_e11, &c1, &e11_hat);
        polyveck_invntt_tomont(&mut c1_e11);
        polyveck_sub(&mut rpoly_h, &c1_e11);
        polyveck_reduce(&mut rpoly_h);

        polyveck_pointwise_poly_montgomery(&mut c2_e12, &c2, &e12_hat);
        polyveck_invntt_tomont(&mut c2_e12);
        polyveck_sub(&mut rpoly_h, &c2_e12);
        polyveck_reduce(&mut rpoly_h);

        let mut rpoly_l = Polyveck::default();
        
        polyveck_caddq(&mut rpoly_h);
        polyveck_decompose(&mut rpoly_h, &mut rpoly_l);

        // Check norm of rpoly_l.
        if polyveck_chknorm(&rpoly_l, (GAMMA2 - BETA) as i32) > 0 {
            eprintln!("fail 2: rpoly_l norm");
            retry += 1;
            continue;
        }

        let mut v1_full_h = v1_full;
        let mut v1_full_l = Polyveck::default();
        polyveck_caddq(&mut v1_full_h);
        polyveck_decompose(&mut v1_full_h, &mut v1_full_l);

        // Check whether rpoly and v1_full have same high bits.
        let mut rh_vh_diff = rpoly_h;
        polyveck_sub(&mut rh_vh_diff, &v1_full_h);
        // polyveck_reduce(&mut rh_vh_diff);

        // Polyveck cannot be compared with each other using == operator.
        /*
        if rpoly_h != v1_full_h {
            continue;
        }
        */

        // The infinite norm must be strictly less than 1, ie be 0.
        if polyveck_chknorm(&rh_vh_diff, 1 as i32) > 0 {
            eprintln!("fail 3: rpoly_h != v1_full_h");
            retry += 1;
            continue;
        }

        let (mut c1_b11_l, mut c2_b12_l) = (Polyveck::default(), Polyveck::default());

        polyveck_pointwise_poly_montgomery(&mut c1_b11_l, &c1, &b11_l_hat);
        polyveck_invntt_tomont(&mut c1_b11_l);
        polyveck_reduce(&mut c1_b11_l);
        // polyveck_add(&mut cb, &c1_b11_l);

        polyveck_pointwise_poly_montgomery(&mut c2_b12_l, &c2, &b12_l_hat);
        polyveck_invntt_tomont(&mut c2_b12_l);
        polyveck_reduce(&mut c2_b12_l);
        // polyveck_add(&mut cb, &c2_b12_l);

        let mut cb = c1_b11_l;
        polyveck_add(&mut cb, &c2_b12_l);
        // polyveck_reduce(&mut cb);

        // Check if norm of cb is less than GAMMA2.
        if polyveck_chknorm(&cb, GAMMA2 as i32) > 0 {
            eprintln!("fail 4: cb norm");
            retry += 1;
            continue;
        }

        // No packing of pk, just pass plain b12_h and z = (z1 z2)^T
        let pk = PublicKey {
            b12_h, z1, z2, c,

        };

        // No packing of sk either, just pass the fields.
        let sk = SecretKey {
            b11_l, b12_l, y11, y12, s11, s12_prime
        };

        break Ok((pk, sk));

        // pack_sk
    }
}

#[derive(Debug)]
pub enum SigError {
    ThresholdError, // Too many attempts retrying within a loop.
}

#[derive(Copy, Clone)]
pub struct Signature {
    z_i1: Polyvecl,
    z_i2: Polyvecl,
    h_i:  Polyveck,
    // c_i:  Polyveck,
    c_i: [u8; SEEDBYTES], // TODO: is c_i a hash or a polynomial?
}

pub fn generate_signature(
    msg:        &[u8],
    identity:   &[u8],
    params:     Params, 
    public_key: PublicKey,
    secret_key: SecretKey,
) -> Result<Signature, SigError> {

    assert_eq!(identity.len(), ID_SIZE);

    // Unpack params, public key and secret key.
    let Params { rho, b11_h } = params;
    let PublicKey { b12_h, z1, z2, c: _ } = public_key;
    let SecretKey { b11_l, b12_l, y11, y12, s11, s12_prime } = secret_key;

    // NTT form of b11_l and b12_l for later use.
    let (mut b11_l_hat, mut b12_l_hat) = (b11_l, b12_l);
    polyveck_ntt(&mut b11_l_hat);
    polyveck_ntt(&mut b12_l_hat);

    // 1) Compute seed r and r_prime
    let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES]; // r || r_prime

    let mut hash_input = [0u8; SEEDBYTES + ID_SIZE]; // rho || ID_A
    hash_input[..SEEDBYTES].copy_from_slice(&rho);
    hash_input[SEEDBYTES..].copy_from_slice(&identity);

    // Write seed to seedbuf.
    shake256(&mut seedbuf, 2 * SEEDBYTES + CRHBYTES, &hash_input, SEEDBYTES + ID_SIZE);

    let mut r = [0u8; 2 * SEEDBYTES];
    let mut r_prime = [0u8; CRHBYTES];

    r.copy_from_slice(&seedbuf[..2 * SEEDBYTES]);
    // println!("r: {:?}", r);
    r_prime.copy_from_slice(&seedbuf[2 * SEEDBYTES..]);

    // 2) Seed Expansion: mat_a11, mat_a12.

    // Big matrix to hold both mat_a11 and mat_a12.
    let mut mat = [Polyvecl::default(); K * 2]; // K * 2 rows

    polyvec_matrix_expand(&mut mat[..K], &r[..SEEDBYTES]);
    polyvec_matrix_expand(&mut mat[K..], &r[SEEDBYTES..]);

    // First K rows to mat_a11.
    let mut mat_a11 = [Polyvecl::default(); K];
    mat_a11.copy_from_slice(&mat[..K]);

    // Later K rows to mat_a12.
    let mut mat_a12 = [Polyvecl::default(); K];
    mat_a12.copy_from_slice(&mat[K..]);

    // 3, 6) Compute v11 and v12, and decompose them into their high and low
    //       bits versions.
    let mut v11 = Polyveck::default();

    let mut y11_hat = y11;
    polyvecl_ntt(&mut y11_hat);

    polyvec_matrix_pointwise_montgomery(&mut v11, &mat_a11, &y11_hat);
    polyveck_reduce(&mut v11);
    polyveck_invntt_tomont(&mut v11);

    let mut v11_h = v11;
    let mut v11_l = Polyveck::default();
    polyveck_caddq(&mut v11_h);
    polyveck_decompose(&mut v11_h, &mut v11_l);

    // Do the same for v12.
    let mut v12 = Polyveck::default();

    let mut y12_hat = y12;
    polyvecl_ntt(&mut y12_hat);

    polyvec_matrix_pointwise_montgomery(&mut v12, &mat_a12, &y12_hat);
    polyveck_reduce(&mut v12);
    polyveck_invntt_tomont(&mut v12);

    let mut v12_h = v12;
    let mut v12_l = Polyveck::default();
    polyveck_caddq(&mut v12_h);
    polyveck_decompose(&mut v12_h, &mut v12_l);

    // Create v1 as sum of v11 and v12
    let mut v1 = v11;
    polyveck_add(&mut v1, &v12);
    // polyveck_reduce(&mut v1); // TODO: is reduction necessary?

    // Decompose v1 into high and low parts.
    let mut v1_h = v1;
    let mut v1_l = Polyveck::default();
    polyveck_reduce(&mut v1_h);
    polyveck_caddq(&mut v1_h);
    polyveck_decompose(&mut v1_h, &mut v1_l);


    // 7) Compute c := CRH(r || v11_h + v12_h)
    let mut v_h_sum = v11_h;
    polyveck_add(&mut v_h_sum, &v12_h);
    // polyveck_reduce(&mut v_h_sum); // TODO?

    let mut state = KeccakState::default();

    let mut v_h_sum_packed = [0u8; K * POLY_V_H_PACKEDBYTES];
    polyveck_pack_w1(v_h_sum_packed.as_mut_slice(), &v_h_sum);

    // let (mut c1_seed, mut c2_seed) = ([0u8; SEEDBYTES], [0u8; SEEDBYTES]);


    let mut c = [0u8; SEEDBYTES];

    state.init();
    shake256_absorb(&mut state, &r, 2 * SEEDBYTES);
    shake256_absorb(&mut state, &v_h_sum_packed, K * POLY_V_H_PACKEDBYTES);
    shake256_finalize(&mut state);
    shake256_squeeze(&mut c, SEEDBYTES, &mut state);

    // Sample c1 and c2 from B_tau and convert them to NTT form.
    let mut c1 = Poly::default();
    poly_challenge_nonced(&mut c1, &c, 0);
    poly_ntt(&mut c1);

    let mut c2 = Poly::default();
    poly_challenge_nonced(&mut c2, &c, 1);
    poly_ntt(&mut c2);

    // 5) Compute e11 and e12.
    let mut e11 = b11_h;
    polyveck_shiftl(&mut e11);
    polyveck_add(&mut e11, &b11_l);

    // Result of the matrix multiplication of mat_a11 with s11.
    let mut v_a11_s11 = Polyveck::default();
    let mut s11_hat = s11;
    polyvecl_ntt(&mut s11_hat);
    polyvec_matrix_pointwise_montgomery(&mut v_a11_s11, &mat_a11, &s11_hat);
    polyveck_reduce(&mut v_a11_s11);
    polyveck_invntt_tomont(&mut v_a11_s11);

    // Update e11 by subtracting v_a11_s11 from it.
    polyveck_sub(&mut e11, &v_a11_s11);

    // Convert e11 into NTT form.
    let mut e11_hat = e11;
    polyveck_ntt(&mut e11_hat);

    // Do the same for e12
    let mut e12 = b12_h;
    polyveck_shiftl(&mut e12);
    polyveck_add(&mut e12, &b12_l);

    // Result of the matrix multiplication of mat_a12 with s12.
    let mut v_a12_s12_prime = Polyveck::default();
    let mut s12_prime_hat = s12_prime;
    polyvecl_ntt(&mut s12_prime_hat);
    polyvec_matrix_pointwise_montgomery(&mut v_a12_s12_prime, &mat_a12, &s12_prime_hat);
    polyveck_reduce(&mut v_a12_s12_prime);
    polyveck_invntt_tomont(&mut v_a12_s12_prime);

    // Update e12 by subtracting v_a12_s12 from it.
    polyveck_sub(&mut e12, &v_a12_s12_prime);

    // Convert e12 into NTT form.
    let mut e12_hat = e12;
    polyveck_ntt(&mut e12_hat);

    // v1_hint_part
    let mut v1_hint_part = v1;

    let mut c1_e11 = Polyveck::default();
    polyveck_pointwise_poly_montgomery(&mut c1_e11, &c1, &e11_hat);
    polyveck_reduce(&mut c1_e11);
    polyveck_invntt_tomont(&mut c1_e11);

    let mut c2_e12 = Polyveck::default();
    polyveck_pointwise_poly_montgomery(&mut c2_e12, &c2, &e12_hat);
    polyveck_reduce(&mut c2_e12);
    polyveck_invntt_tomont(&mut c2_e12);

    polyveck_sub(&mut v1_hint_part, &c1_e11);
    polyveck_sub(&mut v1_hint_part, &c2_e12);
    polyveck_reduce(&mut v1_hint_part);

    // Decompose v1_hint_part into high and low parts.
    let (mut v1_hint_part_h, mut v1_hint_part_l) = (Polyveck::default(), 
        Polyveck::default());

    v1_hint_part_h = v1_hint_part;
    polyveck_caddq(&mut v1_hint_part_h);
    polyveck_decompose(&mut v1_hint_part_h, &mut v1_hint_part_l);

    // Test-13
    if cfg!(debug_assertions) {
        for i in 0..K {
            assert_eq!(v1_hint_part_h.vec[i].coeffs, v1_h.vec[i].coeffs, "i: {i}");
        }
        println!("Test-13 Passed");
    }

    let mut nonce = 0u16;
    let (mut y_i1, mut y_i2) = (Polyvecl::default(), Polyvecl::default());

    // Reset state, this will be used later to sample c_i
    let mut state = KeccakState::default();

    const RETRY_THRESHOLD: usize = 25;
    let mut retry = 0;

    loop {
        if retry == RETRY_THRESHOLD {
            break Err(SigError::ThresholdError);
        }

        // Sample intermediate vectors y_i1 and y_i2.
        polyvecl_uniform_gamma1(&mut y_i1, &r_prime, nonce);
        nonce += 1;

        polyvecl_uniform_gamma1(&mut y_i2, &r_prime, nonce);
        nonce += 1;

        // NTT transform both y_i1 and y_i2 for future multiplications.
        let mut y_i1_hat = y_i1;
        polyvecl_ntt(&mut y_i1_hat);

        let mut y_i2_hat = y_i2;
        polyvecl_ntt(&mut y_i2_hat);

        // Compute v_i1 and v_i2
        let mut v_i1 = Polyveck::default();
        polyvec_matrix_pointwise_montgomery(&mut v_i1, &mat_a11, &y_i1_hat);
        polyveck_reduce(&mut v_i1);
        polyveck_invntt_tomont(&mut v_i1);

        // Decompose v_i1 into high and low bits.
        let (mut v_i1_h, mut v_i1_l) = (Polyveck::default(), Polyveck::default());
        v_i1_h = v_i1;
        polyveck_caddq(&mut v_i1_h);
        polyveck_decompose(&mut v_i1_h, &mut v_i1_l);

        let mut v_i2 = Polyveck::default();
        polyvec_matrix_pointwise_montgomery(&mut v_i2, &mat_a12, &y_i2_hat);
        polyveck_reduce(&mut v_i2);
        polyveck_invntt_tomont(&mut v_i2);

        // Decompose v_i2 into high and low bits.
        let (mut v_i2_h, mut v_i2_l) = (Polyveck::default(), Polyveck::default());
        v_i2_h = v_i2;
        polyveck_caddq(&mut v_i2_h);
        polyveck_decompose(&mut v_i2_h, &mut v_i2_l);

        // Compute v_i for later use.
        let mut v_i = v_i1;
        polyveck_add(&mut v_i, &v_i2);

        // Compute c_i = CRH(r || v_... || msg)
        let mut v_h_sum = v11_h; // sum of 4 v's
        polyveck_add(&mut v_h_sum, &v12_h);
        polyveck_add(&mut v_h_sum, &v_i1_h);
        polyveck_add(&mut v_h_sum, &v_i2_h);

        polyveck_reduce(&mut v_h_sum);
        polyveck_caddq(&mut v_h_sum);

        let mut v_sum_packed = [0u8; K * POLY_V_H_PACKEDBYTES];
        polyveck_pack_w1(v_sum_packed.as_mut_slice(), &v_h_sum);

        let mut c_i = [0u8; SEEDBYTES];

        // let (mut c_i1_seed, mut c_i2_seed) = ([0u8; SEEDBYTES], [0u8; SEEDBYTES]);

        state.init();
        shake256_absorb(&mut state, &r, 2 * SEEDBYTES);
        shake256_absorb(&mut state, &v_sum_packed, K * POLY_V_H_PACKEDBYTES);
        shake256_absorb(&mut state, msg, msg.len());
        shake256_finalize(&mut state);
        shake256_squeeze(&mut c_i, SEEDBYTES, &mut state);

        /*
        // Sample in ball, using c_i seed.
        state.init();
        shake256_absorb(&mut state, &c_i, SEEDBYTES);
        shake256_finalize(&mut state);
        shake256_squeeze(&mut c_i1_seed, SEEDBYTES, &mut state);
        shake256_squeeze(&mut c_i2_seed, SEEDBYTES, &mut state);
        */

        let mut c_i1 = Poly::default();
        poly_challenge_nonced(&mut c_i1, &c_i, 0);
        poly_ntt(&mut c_i1);

        let mut c_i2 = Poly::default();
        poly_challenge_nonced(&mut c_i2, &c_i, 1);
        poly_ntt(&mut c_i2);

        let (mut z_i1, mut z_i2) = (Polyvecl::default(), Polyvecl::default());

        polyvecl_pointwise_poly_montgomery(&mut z_i1, &c_i1, &s11_hat);
        polyvecl_invntt_tomont(&mut z_i1);
        polyvecl_add(&mut z_i1, &y_i1);
        polyvecl_reduce(&mut z_i1);

        // Check norm of z_i1.
        if polyvecl_chknorm(&z_i1, (GAMMA1 - BETA) as i32) > 0 {
            eprintln!("sig: fail at z_i1");
            retry += 1;
            continue;
        }

        polyvecl_pointwise_poly_montgomery(&mut z_i2, &c_i2, &s12_prime_hat);
        polyvecl_invntt_tomont(&mut z_i2);
        polyvecl_add(&mut z_i2, &y_i2);
        polyvecl_reduce(&mut z_i2);

        // Check norm of z_i2.
        if polyvecl_chknorm(&z_i2, (GAMMA1 - BETA) as i32) > 0 {
            eprintln!("sig: fail at z_i2");
            retry += 1;
            continue;
        }

        // Compute r_poly and decompose it to high and low parts.
        let mut r_i_poly = v_i;
        let (mut ci1_e11, mut ci2_e12) = (Polyveck::default(), Polyveck::default());

        polyveck_pointwise_poly_montgomery(&mut ci1_e11, &c_i1, &e11_hat);
        polyveck_reduce(&mut ci1_e11);
        polyveck_invntt_tomont(&mut ci1_e11);
        polyveck_sub(&mut r_i_poly, &ci1_e11);

        polyveck_pointwise_poly_montgomery(&mut ci2_e12, &c_i2, &e12_hat);
        polyveck_reduce(&mut ci2_e12);
        polyveck_invntt_tomont(&mut ci2_e12);
        polyveck_sub(&mut r_i_poly, &ci2_e12);

        polyveck_reduce(&mut r_i_poly);

        let (mut r_i_poly_h, mut r_i_poly_l) = (Polyveck::default(), Polyveck::default());
        
        r_i_poly_h = r_i_poly;
        polyveck_caddq(&mut r_i_poly_h);
        polyveck_decompose(&mut r_i_poly_h, &mut r_i_poly_l);

        // Check norm of r_i_poly_l
        if polyveck_chknorm(&r_i_poly_l, (GAMMA2 - BETA) as i32) > 0 {
            eprintln!("sig: fail at r_i_poly_l");
            retry += 1;
            continue;
        }

        // Check whether rpoly and v_i_h have same high bits.
        let mut v_i_h = v_i;
        let mut v_i_l = Polyveck::default();
        polyveck_reduce(&mut v_i_h);
        polyveck_caddq(&mut v_i_h);
        polyveck_decompose(&mut v_i_h, &mut v_i_l);

        if cfg!(debug_assertions) {
            for i in 0..K {
                assert_eq!(v_i_h.vec[i].coeffs, r_i_poly_h.vec[i].coeffs, "i: {i}");
            }
            println!("Test-14 Passed");
        }

        let mut rih_vih_diff = r_i_poly_h;
        polyveck_sub(&mut rih_vih_diff, &v_i_h);
        polyveck_reduce(&mut rih_vih_diff);

        if polyveck_chknorm(&rih_vih_diff, 1 as i32) > 0 {
            retry += 1;
            continue;
        }

        // Create the big make hint arguments.
        // Decompose(h, y, alpha)
        // let mut h_i = Polyveck::default();

        let mut c_i1_b11_l = Polyveck::default();
        polyveck_pointwise_poly_montgomery(&mut c_i1_b11_l, &c_i1, &b11_l_hat);
        polyveck_reduce(&mut c_i1_b11_l);
        polyveck_invntt_tomont(&mut c_i1_b11_l);

        let mut c_i2_b12_l = Polyveck::default();
        polyveck_pointwise_poly_montgomery(&mut c_i2_b12_l, &c_i2, &b12_l_hat);
        polyveck_reduce(&mut c_i2_b12_l);
        polyveck_invntt_tomont(&mut c_i2_b12_l);

        let mut c1_b11_l = Polyveck::default();
        polyveck_pointwise_poly_montgomery(&mut c1_b11_l, &c1, &b11_l_hat);
        polyveck_reduce(&mut c1_b11_l);
        polyveck_invntt_tomont(&mut c1_b11_l);

        let mut c2_b12_l = Polyveck::default();
        polyveck_pointwise_poly_montgomery(&mut c2_b12_l, &c2, &b12_l_hat);
        polyveck_reduce(&mut c2_b12_l);
        polyveck_invntt_tomont(&mut c2_b12_l);

        /*
        let mut c_i1_e11 = Polyveck::default();
        polyveck_pointwise_poly_montgomery(&mut c_i1_e11, &c_i1, &e11_hat);
        polyveck_reduce(&mut c_i1_e11);
        polyveck_invntt_tomont(&mut c_i1_e11);

        let mut c_i2_e12 = Polyveck::default();
        polyveck_pointwise_poly_montgomery(&mut c_i2_e12, &c_i2, &e12_hat);
        polyveck_reduce(&mut c_i2_e12);
        polyveck_invntt_tomont(&mut c_i2_e12);
        */

        // Create h_i.
        let mut h_i = Polyveck::default();

        polyveck_sub(&mut h_i, &c_i1_b11_l);
        polyveck_reduce(&mut h_i); // TODO?

        polyveck_sub(&mut h_i, &c_i2_b12_l);
        polyveck_reduce(&mut h_i);

        polyveck_sub(&mut h_i, &c1_b11_l);
        polyveck_reduce(&mut h_i);

        polyveck_sub(&mut h_i, &c2_b12_l);
        polyveck_reduce(&mut h_i);

        // polyveck_caddq(&mut h_i);

        // Check norm of h_i
        if polyveck_chknorm(&h_i, 2 * GAMMA2_I32) > 0 {
            eprintln!("sig: fail at h_i norm");
            retry += 1;
            continue;
        }

        // Make hint and calculate 1's in hint.
        /*
        let mut y = v_i; // y for Decompose(h, y, alpha)

        polyveck_sub(&mut y, &c_i1_e11);
        polyveck_reduce(&mut y);

        polyveck_sub(&mut y, &c_i2_e12);
        polyveck_reduce(&mut y);

        polyveck_add(&mut y, &v1);
        polyveck_reduce(&mut y);

        polyveck_sub(&mut y, &c1_e11);
        polyveck_reduce(&mut y);

        polyveck_sub(&mut y, &c2_e12);
        polyveck_reduce(&mut y);

        /*
        polyveck_sub(&mut y, &h_i); // yes, it is polyveck_sub, instead of
                                  // polyveck_add.
        */
        polyveck_add(&mut y, &h_i);
        polyveck_reduce(&mut y);
        */

        let mut y = v1_hint_part;
        polyveck_add(&mut y, &r_i_poly);
        polyveck_sub(&mut y, &h_i);
        polyveck_reduce(&mut y);
        polyveck_caddq(&mut y);

        let mut h = h_i;
        let n = polyveck_make_hint_scaled(&mut h, &h_i, &y);
        if n > OMEGA as i32 {
            eprintln!("sig: fail at h_i vs omega, n: {n}, omega: {OMEGA}");
            retry += 1;
            continue;
        }
        eprintln!("OMEGA: {OMEGA}, n: {n}");

        // Sanity check.
        if cfg!(debug_assertions) {
            let mut before_sum = v1_hint_part;
            polyveck_add(&mut before_sum, &r_i_poly);
            polyveck_sub(&mut before_sum, &h_i);
            polyveck_reduce(&mut before_sum);
            polyveck_caddq(&mut before_sum);

            let mut summed = before_sum;
            polyveck_add(&mut summed, &h_i);
            polyveck_reduce(&mut summed);
            polyveck_caddq(&mut summed);

            let (mut summed_h, mut summed_l) = (Polyveck::default(), Polyveck::default());
            polyveck_decompose_scaled(&mut summed_h, &mut summed_l, &summed);

            let mut hint = Polyveck::default();
            polyveck_make_hint_scaled(&mut hint, &h_i, &before_sum);

            let mut high_hinted = Polyveck::default();
            polyveck_use_hint_scaled(&mut high_hinted, &hint, &before_sum);

            /*
            println!("high_hinted:\n{:?}", high_hinted.vec[0].coeffs);
            println!("summed_h:\n{:?}", summed_h.vec[0].coeffs);
            */

            for i in 0..K {
                for j in 0..N {
                    assert_eq!(
                        summed_h.vec[i].coeffs[j],
                        high_hinted.vec[i].coeffs[j],
                        "i: {i}, j: {j}",
                    );
                }
            }
            println!("\nSanity Check Pass!");
        }

        let signature = Signature {
            z_i1,
            z_i2,
            h_i: h,
            c_i,
        };

        // println!("c1: (verify)\n{:?}", c1);
        // println!("c2: (verify)\n{:?}", c2);
        // println!("r: (verify)\n{:?}", r);

        // println!("v_sum_packed: (signature)\n{:?}", v_sum_packed);

        // println!("v_h_sum: {:?}", v_h_sum.vec[0].coeffs);

        break Ok(signature);
    }
}

pub fn verify_sign(
    msg:       &[u8],
    identity:  &[u8],
    signature: Signature,
    params:    Params,
    pk:        PublicKey,
) -> bool {
    assert_eq!(identity.len(), ID_SIZE);

    let Params { rho, b11_h } = params;
    let PublicKey { b12_h, z1, z2, c } = pk;
    let Signature { z_i1, z_i2, h_i, c_i } = signature;

    // NTT form of b11_h and b12_h for later use.
    let (mut b11_h_hat, mut b12_h_hat) = (b11_h, b12_h);
    polyveck_shiftl(&mut b11_h_hat);
    polyveck_ntt(&mut b11_h_hat);

    polyveck_shiftl(&mut b12_h_hat);
    polyveck_ntt(&mut b12_h_hat);

    // 1) Compute seed: r
    let mut r = [0u8; 2 * SEEDBYTES];

    let mut hash_input = [0u8; SEEDBYTES + ID_SIZE]; // rho || ID_A
    hash_input[..SEEDBYTES].copy_from_slice(&rho);
    hash_input[SEEDBYTES..].copy_from_slice(&identity);

    // Write seed to r,
    shake256(&mut r, 2 * SEEDBYTES, &hash_input, SEEDBYTES + ID_SIZE);
    // println!("r: {:?}", r);

    // 2) Seed Expansion: mat_a11, mat_a12.

    // Big matrix to hold both mat_a11 and mat_a12.
    let mut mat = [Polyvecl::default(); K * 2]; // K * 2 rows

    polyvec_matrix_expand(&mut mat[..K], &r[..SEEDBYTES]);
    polyvec_matrix_expand(&mut mat[K..], &r[SEEDBYTES..]);

    // First K rows to mat_a11.
    let mut mat_a11 = [Polyvecl::default(); K];
    mat_a11.copy_from_slice(&mat[..K]);

    // Later K rows to mat_a12.
    let mut mat_a12 = [Polyvecl::default(); K];
    mat_a12.copy_from_slice(&mat[K..]);

    // Sample c1 and c2 from B_tau using c
    let mut c1 = Poly::default();
    poly_challenge_nonced(&mut c1, &c, 0);
    poly_ntt(&mut c1);

    let mut c2 = Poly::default();
    poly_challenge_nonced(&mut c2, &c, 1);
    poly_ntt(&mut c2);

    // Do the same thing for c_i1 and c_i2 using c_i
    let mut c_i1 = Poly::default();
    poly_challenge_nonced(&mut c_i1, &c_i, 0);
    poly_ntt(&mut c_i1);

    let mut c_i2 = Poly::default();
    poly_challenge_nonced(&mut c_i2, &c_i, 1);
    poly_ntt(&mut c_i2);

    // c1, c2, c_i1, and c_i2 are all in NTT form.

    // z_prime = (z_prime_1 z_prime_2)^T

    let mut z_prime_1 = z1;
    polyvecl_add(&mut z_prime_1, &z_i1);
    
    let mut z_prime_2 = z2;
    polyvecl_add(&mut z_prime_2, &z_i2);

    // Check the norm of z_prime
    if polyvecl_chknorm_big(&z_prime_1, 2 * (GAMMA1 - BETA) as i32) > 0 {
        println!("verify: z_prime_1 norm failed");
        return false;
    }

    if polyvecl_chknorm_big(&z_prime_2, 2 * (GAMMA1 - BETA) as i32) > 0 {
        println!("verify: z_prime_2 norm failed");
        return false;
    }

    // NTT versions for later use.
    let mut z_prime_1_hat = z_prime_1;
    polyvecl_ntt(&mut z_prime_1_hat);

    let mut z_prime_2_hat = z_prime_2;
    polyvecl_ntt(&mut z_prime_2_hat);

    // z_prime norm checks out!

    // let mut cb = Polyveck::default(); // this will hold all the cxbx summed up.

    let mut c_i1_b11_h = Polyveck::default();
    polyveck_pointwise_poly_montgomery(&mut c_i1_b11_h, &c_i1, &b11_h_hat);
    polyveck_invntt_tomont(&mut c_i1_b11_h);
    polyveck_reduce(&mut c_i1_b11_h);

    let mut c_i2_b12_h = Polyveck::default();
    polyveck_pointwise_poly_montgomery(&mut c_i2_b12_h, &c_i2, &b12_h_hat);
    polyveck_invntt_tomont(&mut c_i2_b12_h);
    polyveck_reduce(&mut c_i2_b12_h);
    
    let mut c1_b11_h = Polyveck::default();
    polyveck_pointwise_poly_montgomery(&mut c1_b11_h, &c1, &b11_h_hat);
    polyveck_invntt_tomont(&mut c1_b11_h);
    polyveck_reduce(&mut c1_b11_h);

    let mut c2_b12_h = Polyveck::default();
    polyveck_pointwise_poly_montgomery(&mut c2_b12_h, &c2, &b12_h_hat);
    polyveck_invntt_tomont(&mut c2_b12_h);
    polyveck_reduce(&mut c2_b12_h);

    let mut cb = c_i1_b11_h;

    // polyveck_add(&mut cb, &c_i1_b11_h);
    // polyveck_reduce(&mut cb);

    polyveck_add(&mut cb, &c_i2_b12_h);
    // polyveck_reduce(&mut cb);

    polyveck_add(&mut cb, &c1_b11_h);
    // polyveck_reduce(&mut cb);

    polyveck_add(&mut cb, &c2_b12_h);
    polyveck_reduce(&mut cb);
    polyveck_caddq(&mut cb);

    // Shift cb by multiplying with 2^d
    // polyveck_shiftl(&mut cb);

    let mut a11_z1_prime = Polyveck::default();
    polyvec_matrix_pointwise_montgomery(&mut a11_z1_prime, &mat_a11, &z_prime_1_hat);
    polyveck_reduce(&mut a11_z1_prime);
    polyveck_invntt_tomont(&mut a11_z1_prime);

    let mut a12_z2_prime = Polyveck::default();
    polyvec_matrix_pointwise_montgomery(&mut a12_z2_prime, &mat_a12, &z_prime_2_hat);
    polyveck_reduce(&mut a12_z2_prime);
    polyveck_invntt_tomont(&mut a12_z2_prime);

    let mut az = a11_z1_prime; // sum of a11_z1_prime and a12_z2_prime
    polyveck_add(&mut az, &a12_z2_prime);
    polyveck_reduce(&mut az);
    polyveck_caddq(&mut az);

    polyveck_sub(&mut az, &cb);
    polyveck_reduce(&mut az);
    polyveck_caddq(&mut az);

    let mut vc_prime = Polyveck::default();
    polyveck_use_hint_scaled(&mut vc_prime, &h_i, &az);

    // To store packed vc_prime. TODO: is the bounds correct?
    let mut buf = [0u8; K * POLYW1_PACKEDBYTES];

    polyveck_pack_w1(buf.as_mut_slice(), &vc_prime);
    // println!("c1: (verify)\n{:?}", c1);
    // println!("c2: (verify)\n{:?}", c2);
    // println!("r: (verify)\n{:?}", r);

    // println!("v_sum: (verify)\n{:?}", buf);
    println!("vc_prime: {:?}", vc_prime.vec[0].coeffs);

    let mut c_hash_bytes = [0u8; SEEDBYTES];

    let mut state = KeccakState::default();

    state.init();
    shake256_absorb(&mut state, &r, 2 * SEEDBYTES);
    shake256_absorb(&mut state, &buf, K * POLYW1_PACKEDBYTES);
    shake256_absorb(&mut state, msg, msg.len());
    shake256_finalize(&mut state);
    shake256_squeeze(&mut c_hash_bytes, SEEDBYTES, &mut state);

    if c_hash_bytes != c_i {
        println!("verify: c_hash_bytes != c_i");
        // println!("c_hash_bytes:\n{:?}", c_hash_bytes);
        // println!("c_i:\n{:?}", c_i);
        return false;
    }

    // TODO: do h_i vs omega test as well.

    true
}
