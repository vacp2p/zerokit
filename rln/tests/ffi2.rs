#[cfg(test)]
mod general_tests {

    // use ark_std::{rand::thread_rng, UniformRand};
    // use rand::Rng;
    // use rln::circuit::*;
    // use rln::ffi::{hash as ffi_hash, poseidon_hash as ffi_poseidon_hash, *};
    use rln::ffi2::{
        ffi2_seeded_key_gen
    };
    use rln::utils::str_to_fr;
    // use rln::hashers::{
    //     hash_to_field_be, hash_to_field_le, poseidon_hash as utils_poseidon_hash, ROUND_PARAMS,
    // };
    // use rln::protocol::*;
    // use rln::utils::*;
    // use std::mem::MaybeUninit;

    #[test]
    // Tests hash to field using FFI APIs
    fn ffi2_test_seeded_keygen_stateless_ffi() {

        // We generate a new identity pair from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let res = ffi2_seeded_key_gen(seed_bytes.into());

        assert_eq!(res.len(), 2, "seeded key gen call failed");
        let identity_secret_hash = res.get(0).unwrap();
        let id_commitment = res.get(1).unwrap();

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        );

        assert_eq!(
            *identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(*id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }
}