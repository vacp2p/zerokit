// This crate defines the RLN module default Merkle tree implementation and its Hasher

// Implementation inspired by https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs (no differences)

use crate::circuit::Fr;
use crate::poseidon_hash::poseidon_hash;
use cfg_if::cfg_if;
use utils::merkle_tree::*;

// The zerokit RLN default Merkle tree implementation is the OptimalMerkleTree.
// To switch to FullMerkleTree implementation, it is enough to enable the fullmerkletree feature

cfg_if! {
    if #[cfg(feature = "fullmerkletree")] {
        pub type PoseidonTree = FullMerkleTree<PoseidonHash>;
        pub type MerkleProof = FullMerkleProof<PoseidonHash>;
    } else {
        pub type PoseidonTree = OptimalMerkleTree<PoseidonHash>;
        pub type MerkleProof = OptimalMerkleProof<PoseidonHash>;
    }
}

// The zerokit RLN Merkle tree Hasher
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PoseidonHash;

// The default Hasher trait used by Merkle tree implementation in utils
impl utils::merkle_tree::Hasher for PoseidonHash {
    type Fr = Fr;

    fn default_leaf() -> Self::Fr {
        Self::Fr::from(0)
    }

    fn hash(inputs: &[Self::Fr]) -> Self::Fr {
        poseidon_hash(inputs)
    }
}

////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// A basic performance comparison between the two supported Merkle Tree implementations
    fn test_zerokit_merkle_implementations_performances() {
        use std::time::{Duration, Instant};

        let tree_height = 20;
        let sample_size = 100;

        let leaves: Vec<Fr> = (0..sample_size).map(|s| Fr::from(s)).collect();

        let mut gen_time_full: u128 = 0;
        let mut upd_time_full: u128 = 0;
        let mut gen_time_opt: u128 = 0;
        let mut upd_time_opt: u128 = 0;

        for _ in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            FullMerkleTree::<PoseidonHash>::default(tree_height);
            gen_time_full += now.elapsed().as_nanos();

            let now = Instant::now();
            OptimalMerkleTree::<PoseidonHash>::default(tree_height);
            gen_time_opt += now.elapsed().as_nanos();
        }

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(tree_height);
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(tree_height);

        for i in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            tree_full.set(i, leaves[i]).unwrap();
            upd_time_full += now.elapsed().as_nanos();
            let proof = tree_full.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            let now = Instant::now();
            tree_opt.set(i, leaves[i]).unwrap();
            upd_time_opt += now.elapsed().as_nanos();
            let proof = tree_opt.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);
        }

        // We check all roots are the same
        let tree_full_root = tree_full.root();
        let tree_opt_root = tree_opt.root();

        assert_eq!(tree_full_root, tree_opt_root);

        println!(" Average tree generation time:");
        println!(
            "   - Full Merkle Tree:  {:?}",
            Duration::from_nanos((gen_time_full / sample_size).try_into().unwrap())
        );
        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_opt / sample_size).try_into().unwrap())
        );

        println!(" Average update_next execution time:");
        println!(
            "   - Full Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_full / sample_size).try_into().unwrap())
        );

        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_opt / sample_size).try_into().unwrap())
        );
    }
}

// Test module for testing pmtree integration and features in zerokit
// enabled only if the pmtree feature is enabled

#[cfg(feature = "pmtree")]
#[cfg(test)]
mod pmtree_test {

    use super::*;
    use crate::protocol::hash_to_field;
    use crate::utils::{bytes_le_to_fr, fr_to_bytes_le, str_to_fr};
    use pmtree::*;
    use sled::Db as Sled;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    // The pmtree Hasher trait used by pmtree Merkle tree
    impl pmtree::Hasher for PoseidonHash {
        type Fr = Fr;

        fn default_leaf() -> Self::Fr {
            Fr::from(0)
        }

        fn serialize(value: Self::Fr) -> Value {
            fr_to_bytes_le(&value)
        }

        fn deserialize(value: Value) -> Self::Fr {
            let (fr, _) = bytes_le_to_fr(&value);
            fr
        }

        fn hash(inputs: &[Self::Fr]) -> Self::Fr {
            poseidon_hash(inputs)
        }
    }

    // pmtree supports in-memory and on-disk databases (Database trait) for storing the Merkle tree state

    // We implement Database for hashmaps, an in-memory database
    struct MemoryDB(HashMap<DBKey, Value>);

    impl Database for MemoryDB {
        fn new(_dbpath: &str) -> Result<Self> {
            Ok(MemoryDB(HashMap::new()))
        }

        fn load(_dbpath: &str) -> Result<Self> {
            Err(Error("Cannot load in-memory DB".to_string()))
        }

        fn get(&self, key: DBKey) -> Result<Option<Value>> {
            Ok(self.0.get(&key).cloned())
        }

        fn put(&mut self, key: DBKey, value: Value) -> Result<()> {
            self.0.insert(key, value);

            Ok(())
        }
    }

    // We implement Database for sled DB, an on-disk database
    struct SledDB(Sled);

    impl Database for SledDB {
        fn new(dbpath: &str) -> Result<Self> {
            if Path::new(dbpath).exists() {
                match fs::remove_dir_all(dbpath) {
                    Ok(x) => x,
                    Err(e) => return Err(Error(e.to_string())),
                }
            }

            let db: Sled = match sled::open(dbpath) {
                Ok(db) => db,
                Err(e) => return Err(Error(e.to_string())),
            };

            Ok(SledDB(db))
        }

        fn load(dbpath: &str) -> Result<Self> {
            let db: Sled = match sled::open(dbpath) {
                Ok(db) => db,
                Err(e) => return Err(Error(e.to_string())),
            };

            if !db.was_recovered() {
                return Err(Error("Trying to load non-existing database!".to_string()));
            }

            Ok(SledDB(db))
        }

        fn get(&self, key: DBKey) -> Result<Option<Value>> {
            match self.0.get(key) {
                Ok(value) => Ok(value.map(|val| val.to_vec())),
                Err(e) => Err(Error(e.to_string())),
            }
        }

        fn put(&mut self, key: DBKey, value: Value) -> Result<()> {
            match self.0.insert(key, value) {
                Ok(_) => Ok(()),
                Err(e) => Err(Error(e.to_string())),
            }
        }
    }

    #[test]
    /// A basic performance comparison between the two supported Merkle Tree implementations and in-memory/on-disk pmtree implementations
    fn test_zerokit_and_pmtree_merkle_implementations_performances() {
        use std::time::{Duration, Instant};

        let tree_height = 20;
        let sample_size = 100;

        let leaves: Vec<Fr> = (0..sample_size).map(|s| Fr::from(s)).collect();

        let mut gen_time_full: u128 = 0;
        let mut upd_time_full: u128 = 0;
        let mut gen_time_opt: u128 = 0;
        let mut upd_time_opt: u128 = 0;
        let mut gen_time_pm_memory: u128 = 0;
        let mut upd_time_pm_memory: u128 = 0;
        let mut gen_time_pm_sled: u128 = 0;
        let mut upd_time_pm_sled: u128 = 0;

        for _ in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            FullMerkleTree::<PoseidonHash>::default(tree_height);
            gen_time_full += now.elapsed().as_nanos();

            let now = Instant::now();
            OptimalMerkleTree::<PoseidonHash>::default(tree_height);
            gen_time_opt += now.elapsed().as_nanos();

            let now = Instant::now();
            pmtree::MerkleTree::<MemoryDB, PoseidonHash>::default(tree_height).unwrap();
            gen_time_pm_memory += now.elapsed().as_nanos();

            let now = Instant::now();
            pmtree::MerkleTree::<SledDB, PoseidonHash>::default(tree_height).unwrap();
            gen_time_pm_sled += now.elapsed().as_nanos();
        }

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(tree_height);
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(tree_height);
        let mut tree_pm_memory =
            pmtree::MerkleTree::<MemoryDB, PoseidonHash>::default(tree_height).unwrap();
        let mut tree_pm_sled =
            pmtree::MerkleTree::<SledDB, PoseidonHash>::default(tree_height).unwrap();

        for i in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            tree_full.set(i, leaves[i]).unwrap();
            upd_time_full += now.elapsed().as_nanos();
            let proof = tree_full.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            let now = Instant::now();
            tree_opt.set(i, leaves[i]).unwrap();
            upd_time_opt += now.elapsed().as_nanos();
            let proof = tree_opt.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            let now = Instant::now();
            tree_pm_memory.set(i, leaves[i]).unwrap();
            upd_time_pm_memory += now.elapsed().as_nanos();
            let proof = tree_pm_memory.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            let now = Instant::now();
            tree_pm_sled.set(i, leaves[i]).unwrap();
            upd_time_pm_sled += now.elapsed().as_nanos();
            let proof = tree_pm_sled.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);
        }

        // We check all roots are the same
        let tree_full_root = tree_full.root();
        let tree_opt_root = tree_opt.root();
        let tree_pm_memory_root = tree_pm_memory.root();
        let tree_pm_sled_root = tree_pm_sled.root();

        assert_eq!(tree_full_root, tree_opt_root);
        assert_eq!(tree_opt_root, tree_pm_memory_root);
        assert_eq!(tree_pm_memory_root, tree_pm_sled_root);

        println!(" Average tree generation time:");
        println!(
            "   - Full Merkle Tree:  {:?}",
            Duration::from_nanos((gen_time_full / sample_size).try_into().unwrap())
        );
        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_opt / sample_size).try_into().unwrap())
        );

        println!(
            "   - Pmtree-HashMap Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_pm_memory / sample_size).try_into().unwrap())
        );

        println!(
            "   - Pmtree-Sled Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_pm_sled / sample_size).try_into().unwrap())
        );

        println!(" Average update_next execution time:");
        println!(
            "   - Full Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_full / sample_size).try_into().unwrap())
        );

        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_opt / sample_size).try_into().unwrap())
        );

        println!(
            "   - Pmtree-HashMap Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_pm_memory / sample_size).try_into().unwrap())
        );

        println!(
            "   - Pmtree-Sled Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_pm_sled / sample_size).try_into().unwrap())
        );
    }

    // The following two tests contain values that come from public::test_merkle_proof test
    // We check that pmtree and zerokit Merkle tree implementations match.

    #[test]
    fn test_pmtree_hashmap() -> Result<()> {
        let tree_height = 20;

        let mut tree = pmtree::MerkleTree::<MemoryDB, PoseidonHash>::default(tree_height).unwrap();

        let leaf_index = 3;

        let identity_secret = hash_to_field(b"test-merkle-proof");
        let id_commitment = poseidon_hash(&[identity_secret]);

        // let default_leaf = Fr::from(0);
        tree.set(leaf_index, id_commitment).unwrap();

        // We check correct computation of the root
        let root = tree.root();

        assert_eq!(
            root,
            str_to_fr(
                "0x21947ffd0bce0c385f876e7c97d6a42eec5b1fe935aab2f01c1f8a8cbcc356d2",
                16
            )
        );

        let merkle_proof = tree.proof(leaf_index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        // We check correct computation of the path and indexes
        // These values refers to tree height = 20
        let expected_path_elements = vec![
            str_to_fr(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                16,
            ),
            str_to_fr(
                "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
                16,
            ),
            str_to_fr(
                "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
                16,
            ),
            str_to_fr(
                "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
                16,
            ),
            str_to_fr(
                "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
                16,
            ),
            str_to_fr(
                "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
                16,
            ),
            str_to_fr(
                "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
                16,
            ),
            str_to_fr(
                "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
                16,
            ),
            str_to_fr(
                "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
                16,
            ),
            str_to_fr(
                "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
                16,
            ),
            str_to_fr(
                "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
                16,
            ),
            str_to_fr(
                "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
                16,
            ),
            str_to_fr(
                "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
                16,
            ),
            str_to_fr(
                "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
                16,
            ),
            str_to_fr(
                "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
                16,
            ),
            str_to_fr(
                "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
                16,
            ),
            str_to_fr(
                "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
                16,
            ),
            str_to_fr(
                "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
                16,
            ),
            str_to_fr(
                "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
                16,
            ),
            str_to_fr(
                "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
                16,
            ),
        ];

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We check correct verification of the proof
        assert!(tree.verify(&id_commitment, &merkle_proof));

        Ok(())
    }

    #[test]
    fn test_pmtree_sled() -> Result<()> {
        let tree_height = 20;

        let mut tree = pmtree::MerkleTree::<SledDB, PoseidonHash>::default(tree_height).unwrap();

        let leaf_index = 3;

        let identity_secret = hash_to_field(b"test-merkle-proof");
        let id_commitment = poseidon_hash(&[identity_secret]);

        // let default_leaf = Fr::from(0);
        tree.set(leaf_index, id_commitment).unwrap();

        // We check correct computation of the root
        let root = tree.root();

        assert_eq!(
            root,
            str_to_fr(
                "0x21947ffd0bce0c385f876e7c97d6a42eec5b1fe935aab2f01c1f8a8cbcc356d2",
                16
            )
        );

        let merkle_proof = tree.proof(leaf_index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        // We check correct computation of the path and indexes
        // These values refers to tree height = 20
        let expected_path_elements = vec![
            str_to_fr(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                16,
            ),
            str_to_fr(
                "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
                16,
            ),
            str_to_fr(
                "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
                16,
            ),
            str_to_fr(
                "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
                16,
            ),
            str_to_fr(
                "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
                16,
            ),
            str_to_fr(
                "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
                16,
            ),
            str_to_fr(
                "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
                16,
            ),
            str_to_fr(
                "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
                16,
            ),
            str_to_fr(
                "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
                16,
            ),
            str_to_fr(
                "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
                16,
            ),
            str_to_fr(
                "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
                16,
            ),
            str_to_fr(
                "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
                16,
            ),
            str_to_fr(
                "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
                16,
            ),
            str_to_fr(
                "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
                16,
            ),
            str_to_fr(
                "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
                16,
            ),
            str_to_fr(
                "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
                16,
            ),
            str_to_fr(
                "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
                16,
            ),
            str_to_fr(
                "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
                16,
            ),
            str_to_fr(
                "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
                16,
            ),
            str_to_fr(
                "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
                16,
            ),
        ];

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We check correct verification of the proof
        assert!(tree.verify(&id_commitment, &merkle_proof));

        Ok(())
    }
}
