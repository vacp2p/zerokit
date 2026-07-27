#[cfg(test)]
mod test {
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::{rngs::ThreadRng, thread_rng};
    use rand_chacha::ChaCha20Rng;
    use rln::prelude::*;

    #[test]
    fn test_keygen_commitment_relation() {
        let identity_keys = IdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng());
        let expected_id_commitment =
            Hasher::<PoseidonHash>::hash_single(*identity_keys.identity_secret());
        assert_eq!(identity_keys.id_commitment(), expected_id_commitment);
    }

    #[test]
    fn test_seeded_keygen() {
        // Generate identity pair using a seed phrase
        let seed_phrase: &str = "A seed phrase example";
        let identity_keys =
            IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed_phrase.as_bytes());

        // We check against expected values
        let expected_identity_secret_seed_phrase = Fr::from(
            BigUint::from_str_radix(
                "20df38f3f00496f19fe7c6535492543b21798ed7cb91aebe4af8012db884eda3",
                16,
            )
            .unwrap(),
        );
        let expected_id_commitment_seed_phrase = Fr::from(
            BigUint::from_str_radix(
                "1223a78a5d66043a7f9863e14507dc80720a5602b2a894923e5b5147d5a9c325",
                16,
            )
            .unwrap(),
        );

        assert_eq!(
            *identity_keys.identity_secret(),
            expected_identity_secret_seed_phrase
        );
        assert_eq!(
            identity_keys.id_commitment(),
            expected_id_commitment_seed_phrase
        );

        // Generate identity pair using a byte array
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let identity_keys = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed_bytes);

        // We check against expected values
        let expected_identity_secret_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
                16,
            )
            .unwrap(),
        );
        let expected_id_commitment_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "bf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
                16,
            )
            .unwrap(),
        );

        assert_eq!(
            *identity_keys.identity_secret(),
            expected_identity_secret_seed_bytes
        );
        assert_eq!(
            identity_keys.id_commitment(),
            expected_id_commitment_seed_bytes
        );

        // We check again if the identity pair generated with the same seed phrase corresponds to
        // the previously generated one
        let identity_keys =
            IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed_phrase.as_bytes());

        assert_eq!(
            *identity_keys.identity_secret(),
            expected_identity_secret_seed_phrase
        );
        assert_eq!(
            identity_keys.id_commitment(),
            expected_id_commitment_seed_phrase
        );
    }

    #[test]
    fn test_extended_keygen_relations() {
        let extended_identity_keys =
            ExtendedIdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng());

        let expected_identity_secret = Hasher::<PoseidonHash>::hash_pair(
            *extended_identity_keys.identity_trapdoor(),
            *extended_identity_keys.identity_nullifier(),
        );
        let expected_id_commitment =
            Hasher::<PoseidonHash>::hash_single(*extended_identity_keys.identity_secret());
        assert_eq!(
            *extended_identity_keys.identity_secret(),
            expected_identity_secret
        );
        assert_eq!(
            extended_identity_keys.id_commitment(),
            expected_id_commitment
        );
    }

    #[test]
    fn test_extended_seeded_keygen() {
        // Generate identity tuple using a byte array
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let extended_identity_keys =
            ExtendedIdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed_bytes);

        // We check against expected values
        let expected_identity_trapdoor = Fr::from(
            BigUint::from_str_radix(
                "766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
                16,
            )
            .unwrap(),
        );
        let expected_identity_nullifier = Fr::from(
            BigUint::from_str_radix(
                "1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
                16,
            )
            .unwrap(),
        );
        let expected_identity_secret = Fr::from(
            BigUint::from_str_radix(
                "2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
                16,
            )
            .unwrap(),
        );
        let expected_id_commitment = Fr::from(
            BigUint::from_str_radix(
                "68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
                16,
            )
            .unwrap(),
        );

        assert_eq!(
            *extended_identity_keys.identity_trapdoor(),
            expected_identity_trapdoor
        );
        assert_eq!(
            *extended_identity_keys.identity_nullifier(),
            expected_identity_nullifier
        );
        assert_eq!(
            *extended_identity_keys.identity_secret(),
            expected_identity_secret
        );
        assert_eq!(
            extended_identity_keys.id_commitment(),
            expected_id_commitment
        );

        // We check again if the identity tuple generated with the same byte array corresponds to
        // the previously generated one
        let second = ExtendedIdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed_bytes);
        assert_eq!(
            (
                *second.identity_trapdoor(),
                *second.identity_nullifier(),
                *second.identity_secret(),
                second.id_commitment()
            ),
            (
                expected_identity_trapdoor,
                expected_identity_nullifier,
                expected_identity_secret,
                expected_id_commitment
            )
        );
    }

    #[test]
    fn test_identity_keys_serde_roundtrip() {
        // IdentityKeys: little-endian roundtrip
        let identity_keys = IdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng());
        let mut bytes = Vec::new();
        identity_keys.serialize_compressed(&mut bytes).unwrap();
        let recovered = IdentityKeys::deserialize_compressed(&bytes[..]).unwrap();
        assert_eq!(identity_keys.identity_secret(), recovered.identity_secret());
        assert_eq!(identity_keys.id_commitment(), recovered.id_commitment());

        // IdentityKeys: big-endian roundtrip
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&identity_keys, &mut bytes).unwrap();
        let recovered = <IdentityKeys as CanonicalDeserializeBE>::deserialize(&bytes[..]).unwrap();
        assert_eq!(identity_keys.identity_secret(), recovered.identity_secret());
        assert_eq!(identity_keys.id_commitment(), recovered.id_commitment());

        // ExtendedIdentityKeys: little-endian roundtrip
        let extended_keys =
            ExtendedIdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng());
        let mut bytes = Vec::new();
        extended_keys.serialize_compressed(&mut bytes).unwrap();
        let recovered = ExtendedIdentityKeys::deserialize_compressed(&bytes[..]).unwrap();
        assert_eq!(
            extended_keys.identity_trapdoor(),
            recovered.identity_trapdoor()
        );
        assert_eq!(
            extended_keys.identity_nullifier(),
            recovered.identity_nullifier()
        );
        assert_eq!(extended_keys.identity_secret(), recovered.identity_secret());
        assert_eq!(extended_keys.id_commitment(), recovered.id_commitment());

        // ExtendedIdentityKeys: big-endian roundtrip
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&extended_keys, &mut bytes).unwrap();
        let recovered =
            <ExtendedIdentityKeys as CanonicalDeserializeBE>::deserialize(&bytes[..]).unwrap();
        assert_eq!(
            extended_keys.identity_trapdoor(),
            recovered.identity_trapdoor()
        );
        assert_eq!(
            extended_keys.identity_nullifier(),
            recovered.identity_nullifier()
        );
        assert_eq!(extended_keys.identity_secret(), recovered.identity_secret());
        assert_eq!(extended_keys.id_commitment(), recovered.id_commitment());
    }
}
