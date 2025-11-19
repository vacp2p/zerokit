#[cfg(test)]
#[cfg(feature = "stateless")]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::{Fr, TEST_TREE_DEPTH};
    use rln::ffi::{ffi_rln::*, ffi_utils::*};
    use rln::hashers::{hash_to_field_le, poseidon_hash as utils_poseidon_hash, PoseidonHash};
    use rln::utils::*;
    use safer_ffi::prelude::repr_c;
    use utils::{OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

    fn create_rln_instance() -> repr_c::Box<FFI_RLN> {
        match ffi_rln_new() {
            CResult {
                ok: Some(rln),
                err: None,
            } => rln,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("RLN object creation failed: {}", err),
            _ => unreachable!(),
        }
    }

    fn identity_pair_gen() -> (IdSecret, Fr) {
        let key_gen = ffi_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];
        (id_secret_hash, id_commitment)
    }

    // ...existing code...

    #[test]
    fn test_recover_id_secret_stateless_ffi() {
        let default_leaf = Fr::from(0);
        let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
            TEST_TREE_DEPTH,
            default_leaf,
            ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
        )
        .unwrap();

        let ffi_rln_instance = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();

        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

        // We generate two proofs using same epoch but different signals.
        // We generate a random signal
        let mut rng = thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let x1 = hash_to_field_le(&signal1);

        let signal2: [u8; 32] = rng.gen();
        let x2 = hash_to_field_le(&signal2);

        let identity_index = tree.leaves_set();
        let merkle_proof = tree.proof(identity_index).expect("proof should exist");

        let path_elements: repr_c::Vec<CFr> = merkle_proof
            .get_path_elements()
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let identity_path_index: repr_c::Vec<u8> = merkle_proof.get_path_index().to_vec().into();

        // We call generate_rln_proof for first proof values
        let rln_proof1 = match ffi_generate_rln_proof_stateless(
            &ffi_rln_instance,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements,
            &identity_path_index,
            &CFr::from(x1),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        // We call generate_rln_proof for second proof values
        let rln_proof2 = match ffi_generate_rln_proof_stateless(
            &ffi_rln_instance,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements,
            &identity_path_index,
            &CFr::from(x2),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        let recovered_id_secret_cfr = match ffi_recover_id_secret(&rln_proof1, &rln_proof2) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        // We check if the recovered identity secret hash corresponds to the original one
        let recovered_identity_secret_hash = *recovered_id_secret_cfr;
        assert_eq!(recovered_identity_secret_hash, *identity_secret_hash);

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = identity_pair_gen();
        let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);
        tree.update_next(rate_commitment_new).unwrap();

        // We generate a random signal
        let signal3: [u8; 32] = rng.gen();
        let x3 = hash_to_field_le(&signal3);

        let identity_index_new = tree.leaves_set();
        let merkle_proof_new = tree.proof(identity_index_new).expect("proof should exist");

        let path_elements_new: repr_c::Vec<CFr> = merkle_proof_new
            .get_path_elements()
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let identity_path_index_new: repr_c::Vec<u8> =
            merkle_proof_new.get_path_index().to_vec().into();

        // We call generate_rln_proof
        let rln_proof3 = match ffi_generate_rln_proof_stateless(
            &ffi_rln_instance,
            &CFr::from(*identity_secret_hash_new.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements_new,
            &identity_path_index_new,
            &CFr::from(x3),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let recovered_id_secret_new_cfr = match ffi_recover_id_secret(&rln_proof1, &rln_proof3) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        let recovered_identity_secret_hash_new = recovered_id_secret_new_cfr;

        // ensure that the recovered secret does not match with either of the
        // used secrets in proof generation
        assert_ne!(
            *recovered_identity_secret_hash_new,
            *identity_secret_hash_new
        );
    }

    #[test]
    fn test_verify_with_roots_stateless_ffi() {
        let default_leaf = Fr::from(0);
        let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
            TEST_TREE_DEPTH,
            default_leaf,
            ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
        )
        .unwrap();

        let ffi_rln_instance = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();

        let identity_index = tree.leaves_set();
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

        // We generate a random signal
        let mut rng = thread_rng();
        let signal: [u8; 32] = rng.gen();
        let x = hash_to_field_le(&signal);

        let merkle_proof = tree.proof(identity_index).expect("proof should exist");

        // We prepare input for generate_rln_proof API
        let path_elements: repr_c::Vec<CFr> = merkle_proof
            .get_path_elements()
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let identity_path_index: repr_c::Vec<u8> = merkle_proof.get_path_index().to_vec().into();

        let rln_proof = match ffi_generate_rln_proof_stateless(
            &ffi_rln_instance,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements,
            &identity_path_index,
            &CFr::from(x),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
        let roots_empty: repr_c::Vec<CFr> = vec![].into();

        assert!(
            ffi_verify_with_roots(&ffi_rln_instance, &rln_proof, &roots_empty, &CFr::from(x)).ok
        );

        // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
        let mut roots_random: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_random.push(CFr::from(Fr::rand(&mut rng)));
        }
        let roots_random_vec: repr_c::Vec<CFr> = roots_random.into();

        assert!(
            !ffi_verify_with_roots(
                &ffi_rln_instance,
                &rln_proof,
                &roots_random_vec,
                &CFr::from(x),
            )
            .ok
        );

        // We get the root of the tree obtained adding one leaf per time
        let root = tree.root();

        // We add the real root and we check if now the proof is verified
        let mut roots_with_correct: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_with_correct.push(CFr::from(Fr::rand(&mut rng)));
        }
        roots_with_correct.push(CFr::from(root));
        let roots_correct_vec: repr_c::Vec<CFr> = roots_with_correct.into();

        assert!(
            ffi_verify_with_roots(
                &ffi_rln_instance,
                &rln_proof,
                &roots_correct_vec,
                &CFr::from(x)
            )
            .ok
        );
    }
}
