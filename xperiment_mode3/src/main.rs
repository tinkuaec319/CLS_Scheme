use pqc_dilithium::*;

use std::time::Instant;

const RUNS: usize = 1000;
const MSG_SIZE: usize = 1024; // different messages of size 1024 bytes is
                              // encrypted 1000 times

fn main() {
    let mut iterations = 0usize;

    let mut nopki_ppk_elapsed = 0u128;
    let mut nopki_keygen_elapsed = 0u128;
    let mut nopki_sig_elapsed = 0u128;
    let mut nopki_verify_elapsed = 0u128;
    let mut nopki_verify_success = 0;

    let mut pki_keygen_elapsed = 0u128;
    let mut pki_sig_elapsed = 0u128;
    let mut pki_verify_elapsed = 0u128;
    let mut pki_verify_success = 0;

    let mut message: Vec<u8> = Vec::with_capacity(MSG_SIZE);
    for _ in 0..MSG_SIZE {
        message.push(0);
    }

    loop {
        if iterations == RUNS {
            break;
        }

        // Create a random message for this run.
        rand::fill(&mut message[..]);

        // Create rho and ID
        let mut rho = [0u8; SEEDBYTES];
        let mut identity = [0u8; SEEDBYTES];
        rand::fill(&mut rho[..]);
        rand::fill(&mut identity[..]);

        // Do partial private key generation. It is successful only if the user
        // key generation succeeds.
        let ppk_begin = Instant::now();
        let (params, _msk, ppk) = nopki::kgc::partial_private_key_generation(
            &identity[..], &rho[..]);
        let ppk_elapsed_one = ppk_begin.elapsed();

        // Create user key based on the partial private key.
        let nopki_keygen_begin = Instant::now();

        let nopki_pk;
        let nopki_sk;

        if let Ok((pk, sk)) = nopki::user_keygen::user_generate_key(&identity[..], 
            params.clone(), ppk, None) {
            nopki_pk = pk;
            nopki_sk = sk;
        } else {
            continue;
        }
        let nopki_keygen_elapsed_one = nopki_keygen_begin.elapsed();

        // Update ppk and keygen time.
        nopki_ppk_elapsed += ppk_elapsed_one.as_micros();
        nopki_keygen_elapsed += nopki_keygen_elapsed_one.as_micros();

        // Generate NOPKI signature.
        let nopki_sig_begin = Instant::now();
        let nopki_signature;
        if let Ok(signature) = nopki::user_keygen::generate_signature(
            &message,
            &identity, params, nopki_pk, nopki_sk){
            nopki_signature = signature;
        } else {

            continue;
        }
        let nopki_sig_elapsed_one = nopki_sig_begin.elapsed();
        nopki_sig_elapsed += nopki_sig_elapsed_one.as_micros();

        // Verify NOPKI signature.
        let nopki_verify_begin = Instant::now();
        let verify_result = nopki::user_keygen::verify_sign(
            &message,
            &identity,
            nopki_signature,
            params,
            nopki_pk
        );
        let nopki_verify_elapsed_one = nopki_verify_begin.elapsed();
        nopki_verify_elapsed += nopki_verify_elapsed_one.as_micros();

        // If NOPKI signature verification succeeds.
        if verify_result {
            nopki_verify_success += 1;
        }

        // Generate PKI key.
        let pki_keygen_begin = Instant::now();
        let keys = Keypair::generate();
        let pki_keygen_elapsed_one = pki_keygen_begin.elapsed();
        pki_keygen_elapsed += pki_keygen_elapsed_one.as_micros();

        // Generate PKI signature.
        let pki_sig_begin = Instant::now();
        let pki_sign = keys.sign(&message);
        let pki_sig_elapsed_one = pki_sig_begin.elapsed();
        pki_sig_elapsed += pki_sig_elapsed_one.as_micros();

        // Verify signature done using PKI.
        let pki_verify_begin = Instant::now();
        let sig_verify = verify(&pki_sign, &message,
            &keys.public);
        let pki_verify_elapsed_one = pki_verify_begin.elapsed();
        pki_verify_elapsed += pki_verify_elapsed_one.as_micros();

        // If PKI signature verification succeeds.
        if sig_verify.is_ok() {
            pki_verify_success += 1;
        }

        iterations += 1;
    }


    println!("------------------- NOPKI Dilithium-3 ---------------------------");
    println!("ppk elapsed: {} us", nopki_ppk_elapsed / RUNS as u128);
    println!("keygen elapsed: {} us", nopki_keygen_elapsed / RUNS as u128);
    println!("sig elapsed: {} us", nopki_sig_elapsed / RUNS as u128);
    println!("verify elapsed: {} us", nopki_verify_elapsed / RUNS as u128);
    println!("total runs: {}, verification success: {}", RUNS, nopki_verify_success);
    println!("random message size of each run: {} bytes", MSG_SIZE);

    println!("--------------------- PKI Dilithium-3 ---------------------------");
    println!("keygen elapsed: {} us", pki_keygen_elapsed / RUNS as u128);
    println!("sig elapsed: {} us", pki_sig_elapsed / RUNS as u128);
    println!("verify elapsed: {} us", pki_verify_elapsed / RUNS as u128);
    println!("total runs: {}, verification success: {}", RUNS, pki_verify_success);
    println!("random message size of each run: {} bytes", MSG_SIZE);

}

