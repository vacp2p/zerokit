#[cfg(test)]
mod test {
    use rln::prelude::*;
    use zeroize::Zeroize;

    fn fr_from_hex(hex: &str) -> Fr {
        hex.trim_start_matches("0x")
            .chars()
            .fold(Fr::from(0), |acc, c| {
                acc * Fr::from(16) + Fr::from(c.to_digit(16).unwrap())
            })
    }

    #[test]
    fn test_keygen_commitment_relation() {
        let (identity_secret, id_commitment) = keygen();
        let mut to_hash = [*identity_secret.clone()];
        let expected_id_commitment = poseidon_hash(&to_hash);
        to_hash[0].zeroize();
        assert_eq!(id_commitment, expected_id_commitment);
    }

    #[test]
    fn test_seeded_keygen() {
        // Generate identity pair using a seed phrase
        let seed_phrase: &str = "A seed phrase example";
        let (identity_secret, id_commitment) = seeded_keygen(seed_phrase.as_bytes());

        // We check against expected values
        let expected_identity_secret_seed_phrase =
            fr_from_hex("0x20df38f3f00496f19fe7c6535492543b21798ed7cb91aebe4af8012db884eda3");
        let expected_id_commitment_seed_phrase =
            fr_from_hex("0x1223a78a5d66043a7f9863e14507dc80720a5602b2a894923e5b5147d5a9c325");

        assert_eq!(identity_secret, expected_identity_secret_seed_phrase);
        assert_eq!(id_commitment, expected_id_commitment_seed_phrase);

        // Generate identity pair using a byte array
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let (identity_secret, id_commitment) = seeded_keygen(seed_bytes);

        // We check against expected values
        let expected_identity_secret_seed_bytes =
            fr_from_hex("0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716");
        let expected_id_commitment_seed_bytes =
            fr_from_hex("0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f");

        assert_eq!(identity_secret, expected_identity_secret_seed_bytes);
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);

        // We check again if the identity pair generated with the same seed phrase corresponds to the previously generated one
        let (identity_secret, id_commitment) = seeded_keygen(seed_phrase.as_bytes());

        assert_eq!(identity_secret, expected_identity_secret_seed_phrase);
        assert_eq!(id_commitment, expected_id_commitment_seed_phrase);
    }

    #[test]
    fn test_extended_seeded_keygen_hex_fixture() {
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let (identity_trapdoor, identity_nullifier, identity_secret, id_commitment) =
            extended_seeded_keygen(seed_bytes);

        let expected_identity_trapdoor =
            fr_from_hex("0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716");
        let expected_identity_nullifier =
            fr_from_hex("0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4");
        let expected_identity_secret =
            fr_from_hex("0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521");
        let expected_id_commitment =
            fr_from_hex("0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c");

        assert_eq!(identity_trapdoor, expected_identity_trapdoor);
        assert_eq!(identity_nullifier, expected_identity_nullifier);
        assert_eq!(identity_secret, expected_identity_secret);
        assert_eq!(id_commitment, expected_id_commitment);
    }

    #[test]
    fn test_extended_keygen_relations() {
        let (trapdoor, nullifier, identity_secret, id_commitment) = extended_keygen();

        let expected_identity_secret = poseidon_hash_pair(trapdoor, nullifier);
        let mut to_hash = [identity_secret];
        let expected_id_commitment = poseidon_hash(&to_hash);
        to_hash[0].zeroize();
        assert_eq!(identity_secret, expected_identity_secret);
        assert_eq!(id_commitment, expected_id_commitment);
    }

    #[test]
    fn test_extended_seeded_keygen_determinism() {
        let seed = b"test-seed-extended";
        let first = extended_seeded_keygen(seed);
        let second = extended_seeded_keygen(seed);

        assert_eq!(first, second);

        let (trapdoor, nullifier, identity_secret, id_commitment) = first;
        let expected_identity_secret = poseidon_hash_pair(trapdoor, nullifier);
        let mut to_hash = [identity_secret];
        let expected_id_commitment = poseidon_hash(&to_hash);
        to_hash[0].zeroize();

        assert_eq!(identity_secret, expected_identity_secret);
        assert_eq!(id_commitment, expected_id_commitment);
    }
}
