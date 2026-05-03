use pqc_dilithium::*;

use std::time::Instant;

const RUNS: usize = 1000;

fn main() {
    let mut iterations = 0usize;

    let mut nopki_ppk_elapsed = 0u128;
    let mut nopki_keygen_elapsed = 0u128;
    let mut nopki_sig_elapsed = 0u128;

    let mut pki_keygen_elapsed = 0u128;
    let mut pki_sig_elapsed = 0u128;


    loop {
        if iterations == RUNS {
            break;
        }

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

        let nopki_sig_begin = Instant::now();
        let _nopki_signature;
        if let Ok(signature) = nopki::user_keygen::generate_signature(
            "lorem ipsum dolor sit amet".as_bytes(),
            &identity, params, nopki_pk, nopki_sk){
            _nopki_signature = signature;
        } else {

            continue;
        }
        let nopki_sig_elapsed_one = nopki_sig_begin.elapsed();
        nopki_sig_elapsed += nopki_sig_elapsed_one.as_micros();

        let pki_keygen_begin = Instant::now();
        let keys = Keypair::generate();
        let pki_keygen_elapsed_one = pki_keygen_begin.elapsed();
        pki_keygen_elapsed += pki_keygen_elapsed_one.as_micros();

        let pki_sig_begin = Instant::now();
        let pki_sign = keys.sign("lorem ipsum dolor sit amet".as_bytes());
        let pki_sig_elapsed_one = pki_sig_begin.elapsed();
        pki_sig_elapsed += pki_sig_elapsed_one.as_micros();


        iterations += 1;
    }

    println!("-----------------------------NOPKI---------------------------");
    println!("ppk elapsed: {} us", nopki_ppk_elapsed / RUNS as u128);
    println!("keygen elapsed: {} us", nopki_keygen_elapsed / RUNS as u128);
    println!("sig elapsed: {} us", nopki_sig_elapsed / RUNS as u128);

    println!("-----------------------------PKI---------------------------");
    println!("keygen elapsed: {} us", pki_keygen_elapsed / RUNS as u128);
    println!("sig elapsed: {} us", pki_sig_elapsed / RUNS as u128);

}

