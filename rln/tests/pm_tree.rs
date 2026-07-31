#![cfg(not(target_arch = "wasm32"))]

#[cfg(test)]
mod test {
    use std::{collections::HashMap, path::PathBuf, str::FromStr};

    use ark_ff::AdditiveGroup;
    use pmtree::{DBKey, Database, PmtreeError, PmtreeResult};
    use rln::prelude::*;
    use tempfile::TempDir;
    use zerokit_utils::merkle_tree::{
        FullMerkleTree, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
        ZerokitMerkleTreeError,
    };

    const TEST_DEPTH: usize = 10;

    fn temp_config() -> PmTreeSledConfig {
        PmTreeSledConfig::new().temporary(true).build().unwrap()
    }

    fn persistent_config(path: PathBuf) -> PmTreeSledConfig {
        PmTreeSledConfig::new()
            .path(path)
            .temporary(false)
            .build()
            .unwrap()
    }

    // A simple in-memory backend for testing the generic PmTree over any Database.
    #[derive(Clone, Default)]
    struct MemConfig;
    impl FromStr for MemConfig {
        type Err = std::convert::Infallible;
        fn from_str(_: &str) -> Result<Self, Self::Err> {
            Ok(Self)
        }
    }
    impl PmTreeBackendConfig for MemConfig {
        fn tree_depth(&self) -> Option<usize> {
            None
        }

        fn is_fresh(&self) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct MemDB(HashMap<DBKey, pmtree::Value>);
    impl Database for MemDB {
        type Config = MemConfig;
        fn new(_config: Self::Config) -> PmtreeResult<Self> {
            Ok(Self::default())
        }
        fn load(_config: Self::Config) -> PmtreeResult<Self> {
            Err(PmtreeError::Database("MemDB is not persistent".into()))
        }
        fn get(&self, key: DBKey) -> PmtreeResult<Option<pmtree::Value>> {
            Ok(self.0.get(&key).cloned())
        }
        fn put(&mut self, key: DBKey, value: pmtree::Value) -> PmtreeResult<()> {
            self.0.insert(key, value);
            Ok(())
        }
        fn put_batch(&mut self, subtree: HashMap<DBKey, pmtree::Value>) -> PmtreeResult<()> {
            self.0.extend(subtree);
            Ok(())
        }
        fn close(&mut self) -> PmtreeResult<()> {
            Ok(())
        }
    }

    #[test]
    fn test_pmtree_generic_over_backend() {
        let mut tree = PmTree::<MemDB, PoseidonHash>::new(2, Fr::from(0u64), MemConfig).unwrap();
        let leaf = Fr::from(7u64);
        tree.set(0, leaf).unwrap();
        assert_eq!(tree.get(0).unwrap(), leaf);
        assert_eq!(tree.leaves_set(), 1);
        let proof = tree.proof(0).unwrap();
        assert!(tree.verify(&leaf, &proof).unwrap());
    }

    #[test]
    fn test_pmtree_config_builder() {
        let config = PmTreeSledConfig::new()
            .temporary(true)
            .cache_capacity(1 << 30)
            .flush_every_ms(1000)
            .mode(PmTreeMode::LowSpace)
            .use_compression(false)
            .build()
            .unwrap();

        // Indirect confirmation: create a tree with the config and verify operations work
        let mut tree = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config).unwrap();
        let leaf = Fr::from(42);
        tree.set(0, leaf).unwrap();
        assert_eq!(tree.get(0).unwrap(), leaf);
        assert_eq!(tree.leaves_set(), 1);
        let root = tree.root();
        assert_ne!(root, Fr::ZERO);
    }

    #[test]
    fn test_pmtree_config_from_str() {
        let temp_dir = TempDir::new().unwrap();
        let json = format!(
            r#"
        {{
            "path": "{}",
            "temporary": false,
            "cache_capacity": 1073741824,
            "flush_every_ms": 500,
            "mode": "HighThroughput",
            "use_compression": false
        }}"#,
            temp_dir.path().display()
        );

        let config: PmTreeSledConfig = json.parse().unwrap();

        // Verify the config by creating a persistent tree
        let mut tree1 =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config.clone()).unwrap();
        let leaf = Fr::from(42);
        tree1.set(0, leaf).unwrap();
        let root1 = tree1.root();
        tree1.close().unwrap();
        drop(tree1);

        // Reopen and verify persistence
        let tree2 = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config).unwrap();
        assert_eq!(tree2.get(0).unwrap(), leaf);
        assert_eq!(tree2.root(), root1);
    }

    #[test]
    fn test_pmtree_config_from_str_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let existing_path = temp_dir.path().to_str().unwrap();
        let invalid_json = format!(r#"{{"temporary": true, "path": "{}"}}"#, existing_path);
        let result: Result<PmTreeSledConfig, _> = invalid_json.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_pmtree_tree_creation_default() {
        let tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        assert_eq!(tree.depth(), TEST_DEPTH);
        assert_eq!(tree.capacity(), 1 << TEST_DEPTH);
        assert_eq!(tree.leaves_set(), 0);
    }

    #[test]
    fn test_pmtree_tree_creation_new() {
        let config = temp_config();
        let tree = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::from(0), config).unwrap();
        assert_eq!(tree.depth(), TEST_DEPTH);
    }

    #[test]
    fn test_pmtree_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = persistent_config(db_path.clone());

        // Create and populate
        let mut tree1 =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config.clone()).unwrap();
        let leaf = Fr::from(42);
        tree1.update_next(leaf).unwrap();
        let root1 = tree1.root();
        tree1.set_metadata(b"test metadata").unwrap();
        tree1.close().unwrap();
        drop(tree1);

        // Load and verify
        let tree2 = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config).unwrap();
        assert_eq!(tree2.root(), root1);
        assert_eq!(tree2.metadata().unwrap(), b"test metadata");
        assert_eq!(tree2.leaves_set(), 1);
        assert_eq!(tree2.get(0).unwrap(), leaf);
    }

    #[test]
    fn test_pmtree_reload_depth_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = persistent_config(db_path);

        let mut tree =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config.clone()).unwrap();
        tree.update_next(Fr::from(1)).unwrap();
        tree.close().unwrap();
        drop(tree);

        let result = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH + 1, Fr::ZERO, config.clone());
        assert!(matches!(
            result,
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::DepthMismatch
            ))
        ));

        let tree = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config).unwrap();
        assert_eq!(tree.depth(), TEST_DEPTH);
        assert_eq!(tree.get(0).unwrap(), Fr::from(1));
    }

    #[test]
    fn test_pmtree_reload_rebuilds_empty_leaves_cache() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = persistent_config(db_path);

        let mut tree =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config.clone()).unwrap();
        for i in 1..=3u64 {
            tree.update_next(Fr::from(i)).unwrap();
        }
        tree.delete(1).unwrap();
        let empty_before = tree.get_empty_leaves_indices();
        assert_eq!(empty_before, vec![1]);
        tree.close().unwrap();
        drop(tree);

        let tree = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config).unwrap();
        assert_eq!(tree.leaves_set(), 3);
        assert_eq!(tree.get_empty_leaves_indices(), empty_before);
    }

    #[test]
    fn test_pmtree_load_nonexistent() {
        let config = persistent_config(PathBuf::from("\0invalid"));
        let result = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config);
        assert!(matches!(result, Err(PmTreeError::Backend(_))));
    }

    #[test]
    fn test_pmtree_depth_shift_overflow() {
        let depth = usize::BITS as usize;
        let result = PmTree::<SledDB, PoseidonHash>::new(depth, Fr::ZERO, temp_config());
        assert!(matches!(
            result,
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::DepthTooLarge
            ))
        ));
    }

    #[test]
    fn test_pmtree_basic_operations() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let leaf = Fr::from(123);
        tree.set(5, leaf).unwrap();
        assert_eq!(tree.get(5).unwrap(), leaf);
        assert_eq!(tree.leaves_set(), 6); // Next index
        assert_ne!(tree.root(), Fr::ZERO);
    }

    #[test]
    fn test_pmtree_update_next() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        for i in 0..5 {
            tree.update_next(Fr::from(i as u64)).unwrap();
        }
        assert_eq!(tree.leaves_set(), 5);
        for i in 0..5 {
            assert_eq!(tree.get(i).unwrap(), Fr::from(i as u64));
        }
    }

    #[test]
    fn test_pmtree_set_range() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let leaves: Vec<Fr> = (0..4).map(|i| Fr::from(i as u64)).collect();
        tree.set_range(1, leaves.into_iter()).unwrap();
        assert_eq!(tree.get(1).unwrap(), Fr::from(0));
        assert_eq!(tree.get(4).unwrap(), Fr::from(3));
        assert_eq!(tree.get_empty_leaves_indices(), vec![0]);
    }

    #[test]
    fn test_pmtree_delete() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let leaf = Fr::from(99);
        tree.set(2, leaf).unwrap();
        assert_eq!(tree.get(2).unwrap(), leaf);
        tree.delete(2).unwrap();
        assert_eq!(tree.get(2).unwrap(), Fr::ZERO); // Default leaf
        assert_eq!(tree.leaves_set(), 3); // Unchanged

        let unset = tree.leaves_set();
        assert!(matches!(
            tree.delete(unset),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::DeleteUnsetLeaf
            ))
        ));
    }

    #[test]
    fn test_pmtree_override_range() {
        // PmTree routes override_range to pmtree's atomic `batch_set` (single commit), so the same
        // cases the in-memory backends cover must hold here too. Each case sets a fresh tree,
        // applies one override_range, then checks BOTH the leaf values and the empty-leaves cache.

        // Full overlap: write [5,6] over deleted [0,1] (writes win, untouched leaves preserved).
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![Fr::from(10), Fr::from(20), Fr::from(30), Fr::from(40)].into_iter(),
        )
        .unwrap();
        tree.override_range(0, vec![Fr::from(5), Fr::from(6)], vec![0usize, 1])
            .unwrap();
        for (i, &v) in [5u64, 6, 30, 40].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), Vec::<usize>::new());

        // Shift repro: delete idx0, write 99 at idx2 (the write must NOT shift right).
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![Fr::from(10), Fr::from(20), Fr::from(30), Fr::from(40)].into_iter(),
        )
        .unwrap();
        tree.override_range(2, vec![Fr::from(99)], vec![0usize])
            .unwrap();
        for (i, &v) in [0u64, 20, 99, 40].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), vec![0]);

        // More deletes than writes: write [5,6] at start, delete [0,1,2,3].
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![Fr::from(10), Fr::from(20), Fr::from(30), Fr::from(40)].into_iter(),
        )
        .unwrap();
        tree.override_range(0, vec![Fr::from(5), Fr::from(6)], vec![0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [5u64, 6, 0, 0].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), vec![2, 3]);

        // Deletes entirely before the write range (no overlap).
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![
                Fr::from(10),
                Fr::from(20),
                Fr::from(30),
                Fr::from(40),
                Fr::from(50),
                Fr::from(60),
                Fr::from(70),
                Fr::from(80),
            ]
            .into_iter(),
        )
        .unwrap();
        tree.override_range(
            4,
            vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)],
            vec![0usize, 1, 2, 3],
        )
        .unwrap();
        for (i, &v) in [0u64, 0, 0, 0, 1, 2, 3, 4].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), vec![0, 1, 2, 3]);

        // Partial overlap: write [1,2,3,4] at idx2, delete [0,1,2,3] (idx2,3 overlap the write).
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![
                Fr::from(10),
                Fr::from(20),
                Fr::from(30),
                Fr::from(40),
                Fr::from(50),
                Fr::from(60),
                Fr::from(70),
                Fr::from(80),
            ]
            .into_iter(),
        )
        .unwrap();
        tree.override_range(
            2,
            vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)],
            vec![0usize, 1, 2, 3],
        )
        .unwrap();
        for (i, &v) in [0u64, 0, 1, 2, 3, 4, 70, 80].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), vec![0, 1]);

        // Writes only (empty deletes).
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![Fr::from(10), Fr::from(20), Fr::from(30), Fr::from(40)].into_iter(),
        )
        .unwrap();
        tree.override_range(1, vec![Fr::from(7), Fr::from(8)], Vec::new())
            .unwrap();
        for (i, &v) in [10u64, 7, 8, 40].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), Vec::<usize>::new());

        // Deletes only (empty writes).
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(
            0,
            vec![Fr::from(10), Fr::from(20), Fr::from(30), Fr::from(40)].into_iter(),
        )
        .unwrap();
        tree.override_range(0, Vec::new(), vec![1usize, 3]).unwrap();
        for (i, &v) in [10u64, 0, 30, 0].iter().enumerate() {
            assert_eq!(tree.get(i).unwrap(), Fr::from(v), "leaf {i}");
        }
        assert_eq!(tree.get_empty_leaves_indices(), vec![1, 3]);

        // Validation: both inputs empty -> EmptyOverrideArgs.
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(0, vec![Fr::from(10), Fr::from(20)].into_iter())
            .unwrap();
        assert!(matches!(
            tree.override_range(0, Vec::new(), Vec::new()),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::EmptyOverrideArgs
            ))
        ));

        // Validation: a non-overlapping delete index >= leaves_set -> InvalidRemoveIndex.
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap();
        tree.set_range(0, vec![Fr::from(10), Fr::from(20)].into_iter())
            .unwrap();
        assert!(matches!(
            tree.override_range(0, vec![Fr::from(5)], vec![5usize]),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::InvalidRemoveIndex
            ))
        ));

        // Validation: start + leaves.len() > capacity -> RangeTooLarge.
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(2).unwrap();
        assert!(matches!(
            tree.override_range(3, vec![Fr::from(1), Fr::from(2)], Vec::new()),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::RangeTooLarge
            ))
        ));

        // Validation: start + leaves.len() overflows usize -> RangeTooLarge.
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(2).unwrap();
        assert!(matches!(
            tree.override_range(usize::MAX, vec![Fr::from(1)], Vec::new()),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::RangeTooLarge
            ))
        ));
    }

    #[test]
    fn test_pmtree_get_empty_leaves_indices() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        tree.set(0, Fr::from(1)).unwrap();
        tree.set(2, Fr::from(3)).unwrap();
        tree.delete(0).unwrap();
        let empty = tree.get_empty_leaves_indices();
        assert!(empty.contains(&0));
        assert!(empty.contains(&1));
        assert!(!empty.contains(&2));
    }

    #[test]
    fn test_pmtree_proof_and_verify() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let leaf = Fr::from(42);
        tree.set(3, leaf).unwrap();
        let proof = tree.proof(3).unwrap();
        assert_eq!(proof.leaf_index(), 3);
        assert!(tree.verify(&leaf, &proof).unwrap());
        assert!(matches!(
            tree.verify(&Fr::from(43), &proof),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::InvalidMerkleProof
            ))
        ));
    }

    #[test]
    fn test_pmtree_get_subtree_root() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(3).unwrap(); // Depth 3 for simplicity
        tree.set(0, Fr::from(1)).unwrap();
        tree.set(1, Fr::from(2)).unwrap();
        // Root is level 0
        assert_eq!(tree.get_subtree_root(0, 0).unwrap(), tree.root());
        // Leaf is level 3
        assert_eq!(tree.get_subtree_root(3, 0).unwrap(), Fr::from(1));
    }

    #[test]
    fn test_pmtree_metadata() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let meta = b"hello world";
        tree.set_metadata(meta).unwrap();
        assert_eq!(tree.metadata().unwrap(), meta);
    }

    #[test]
    fn test_pmtree_close_db() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        tree.close().unwrap();
        // Verify idempotence: calling close again should succeed
        tree.close().unwrap();
        // Verify that the tree still works after close (close is a no-op)
        assert_eq!(tree.get(0).unwrap(), Fr::ZERO);
    }

    #[test]
    fn test_pmtree_invalid_index() {
        let tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let capacity = tree.capacity();
        assert!(matches!(
            tree.proof(capacity),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::LeafIndexOutOfBounds
            ))
        ));
        assert!(matches!(
            tree.get(capacity),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::LeafIndexOutOfBounds
            ))
        ));
    }

    #[test]
    fn test_pmtree_invalid_subtree_root() {
        let tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        assert!(matches!(
            tree.get_subtree_root(TEST_DEPTH + 1, 0),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::LevelOutOfBounds
            ))
        ));
    }

    #[test]
    fn test_pmtree_proof_binds_to_leaf_index_even_if_leaf_value_same() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();

        let leaf = Fr::from(42);
        tree.set(0, leaf).unwrap();
        tree.set(1, leaf).unwrap();

        let proof0 = tree.proof(0).unwrap();
        let proof1 = tree.proof(1).unwrap();

        // Both proofs should reconstruct the current root when used with the correct leaf value,
        // but their *paths/indexes* should differ.
        let root0 = proof0.compute_root_from(&leaf);
        let root1 = proof1.compute_root_from(&leaf);
        assert_eq!(root0, tree.root());
        assert_eq!(root1, tree.root());

        // The "index binding" evidence: either leaf_index differs or path_index differs.
        assert_ne!(proof0.leaf_index(), proof1.leaf_index());
        assert_ne!(proof0.get_path_index(), proof1.get_path_index());
    }

    #[test]
    fn test_pmtree_modes() {
        let config_ht = PmTreeSledConfig::new()
            .mode(PmTreeMode::HighThroughput)
            .build()
            .unwrap();
        let config_ls = PmTreeSledConfig::new()
            .mode(PmTreeMode::LowSpace)
            .build()
            .unwrap();
        let mut tree_ht =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config_ht).unwrap();
        let mut tree_ls =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config_ls).unwrap();
        tree_ht.set(0, Fr::from(1)).unwrap();
        tree_ls.set(0, Fr::from(1)).unwrap();
        // Roots should be same regardless of mode
        assert_eq!(tree_ht.root(), tree_ls.root());
    }

    #[test]
    fn test_pmtree_compression() {
        let config_comp = PmTreeSledConfig::new()
            .use_compression(true)
            .build()
            .unwrap();
        let config_no_comp = PmTreeSledConfig::new()
            .use_compression(false)
            .build()
            .unwrap();
        let mut tree_comp =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config_comp).unwrap();
        let mut tree_no_comp =
            PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config_no_comp).unwrap();
        tree_comp.set(0, Fr::from(1)).unwrap();
        tree_no_comp.set(0, Fr::from(1)).unwrap();
        assert_eq!(tree_comp.root(), tree_no_comp.root());
    }

    #[test]
    fn test_pmtree_stress_large() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(15).unwrap(); // Smaller for test
        for i in 0..100 {
            tree.update_next(Fr::from(i as u64)).unwrap();
        }
        assert_eq!(tree.leaves_set(), 100);
        let proof = tree.proof(50).unwrap();
        assert!(tree.verify(&Fr::from(50), &proof).unwrap());
    }

    #[test]
    fn test_pmtree_full_tree() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(4).unwrap(); // 16 capacity
        for i in 0..16 {
            tree.set(i, Fr::from(i as u64)).unwrap();
        }
        assert_eq!(tree.leaves_set(), 16);
        assert_eq!(tree.capacity(), 16);
        // Try overflow
        assert!(matches!(
            tree.update_next(Fr::from(16)),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::RangeTooLarge
            ))
        ));
        assert!(matches!(
            tree.set(16, Fr::from(16)),
            Err(PmTreeError::MerkleTree(
                ZerokitMerkleTreeError::LeafIndexOutOfBounds
            ))
        ));
    }

    #[test]
    fn test_pmtree_large_batch() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        let leaves: Vec<Fr> = (0..100).map(|i| Fr::from(i as u64)).collect();
        tree.set_range(0, leaves.into_iter()).unwrap();
        assert_eq!(tree.leaves_set(), 100);
        for i in 0..100 {
            assert_eq!(tree.get(i).unwrap(), Fr::from(i as u64));
        }
    }

    #[test]
    fn test_pmtree_multiple_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = persistent_config(db_path);

        // First open: write data, close, and fully drop the tree.
        {
            let mut tree1 =
                PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config.clone()).unwrap();
            tree1.set(0, Fr::from(1)).unwrap();

            // Optional stronger signal than just leaf persistence:
            assert_ne!(tree1.root(), Fr::ZERO);

            tree1.close().unwrap();
        }

        // Second open: verify data, close, and drop.
        {
            let mut tree2 =
                PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config.clone()).unwrap();
            assert_eq!(tree2.get(0).unwrap(), Fr::from(1));

            // Optional: verify tree is still non-empty (depending on semantics).
            assert_ne!(tree2.root(), Fr::ZERO);

            tree2.close().unwrap();
        }

        // Third open: verify again.
        {
            let tree3 = PmTree::<SledDB, PoseidonHash>::new(TEST_DEPTH, Fr::ZERO, config).unwrap();
            assert_eq!(tree3.get(0).unwrap(), Fr::from(1));
            assert_ne!(tree3.root(), Fr::ZERO);
        }
    }

    #[test]
    fn test_pmtree_depth_extremes() {
        // Depth 0 (minimal valid depth)
        let result = PmTree::<SledDB, PoseidonHash>::default(0);
        assert!(result.is_ok());
        if let Ok(tree) = result {
            assert_eq!(tree.depth(), 0);
            assert_eq!(tree.capacity(), 1);
        }
        // Depth 32
        let result = PmTree::<SledDB, PoseidonHash>::default(32);
        if let Ok(tree) = result {
            assert_eq!(tree.depth(), 32);
            assert_eq!(tree.capacity(), 1usize << 32);
        }
    }

    #[test]
    fn test_pmtree_compaction() {
        let mut tree = PmTree::<SledDB, PoseidonHash>::default(TEST_DEPTH).unwrap();
        for i in 0..50 {
            tree.set(i, Fr::from(i as u64)).unwrap();
        }
        assert_eq!(tree.leaves_set(), 50);
        for i in 0..25 {
            tree.delete(i).unwrap();
        }
        assert_eq!(tree.leaves_set(), 50); // Unchanged
        let empty = tree.get_empty_leaves_indices();
        assert_eq!(empty.len(), 25);
        assert!(empty.iter().all(|&i| i < 25));
    }

    #[test]
    fn test_pmtree_subtree_root() {
        const DEPTH: usize = 3;
        const LEAF_COUNT: usize = 8;

        let mut tree =
            PmTree::<SledDB, PoseidonHash>::new(DEPTH, Fr::from(0), temp_config()).unwrap();
        let leaves: Vec<Fr> = (0..LEAF_COUNT).map(|s| Fr::from(s as i32)).collect();
        tree.set_range(0, leaves.into_iter()).unwrap();

        for i in 0..LEAF_COUNT {
            // check leaves
            assert_eq!(
                tree.get(i).unwrap(),
                tree.get_subtree_root(DEPTH, i).unwrap()
            );
            // check root
            assert_eq!(tree.root(), tree.get_subtree_root(0, i).unwrap());
        }

        // check intermediate nodes
        for n in (1..=DEPTH).rev() {
            for i in (0..(1 << n)).step_by(2) {
                let idx_l = i * (1 << (DEPTH - n));
                let idx_r = (i + 1) * (1 << (DEPTH - n));
                let idx_sr = idx_l;

                let prev_l = tree.get_subtree_root(n, idx_l).unwrap();
                let prev_r = tree.get_subtree_root(n, idx_r).unwrap();
                let subroot = tree.get_subtree_root(n - 1, idx_sr).unwrap();

                assert_eq!(Hasher::<PoseidonHash>::hash_pair(prev_l, prev_r), subroot);
            }
        }
    }

    #[test]
    fn test_pmtree_full_root_and_proof_equivalence() {
        // PmTree must agree with FullMerkleTree on the root and proof for the same set of leaves.
        let depth = 4;
        let leaves: Vec<Fr> = (0..(1u64 << depth)).map(|i| Fr::from(i * 3 + 1)).collect();

        let mut tree_pm = PmTree::<SledDB, PoseidonHash>::default(depth).unwrap();
        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(depth).unwrap();
        tree_pm.set_range(0, leaves.clone().into_iter()).unwrap();
        tree_full.set_range(0, leaves.clone().into_iter()).unwrap();

        assert_eq!(tree_pm.root(), tree_full.root());

        for (index, leaf) in leaves.iter().enumerate() {
            let proof_pm = tree_pm.proof(index).unwrap();
            let proof_full = tree_full.proof(index).unwrap();
            assert_eq!(
                proof_pm.get_path_elements(),
                proof_full.get_path_elements(),
                "path elements at {index}"
            );
            assert_eq!(
                proof_pm.get_path_index(),
                proof_full.get_path_index(),
                "path index at {index}"
            );
            assert_eq!(
                proof_pm.compute_root_from(leaf),
                tree_pm.root(),
                "recomputed root at {index}"
            );
        }
    }

    #[test]
    fn test_pmtree_optimal_root_and_proof_equivalence() {
        // PmTree must agree with OptimalMerkleTree on the root and proof for the same set of
        // leaves.
        let depth = 4;
        let leaves: Vec<Fr> = (0..(1u64 << depth)).map(|i| Fr::from(i * 3 + 1)).collect();

        let mut tree_pm = PmTree::<SledDB, PoseidonHash>::default(depth).unwrap();
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(depth).unwrap();
        tree_pm.set_range(0, leaves.clone().into_iter()).unwrap();
        tree_opt.set_range(0, leaves.clone().into_iter()).unwrap();

        assert_eq!(tree_pm.root(), tree_opt.root());

        for (index, leaf) in leaves.iter().enumerate() {
            let proof_pm = tree_pm.proof(index).unwrap();
            let proof_opt = tree_opt.proof(index).unwrap();
            assert_eq!(
                proof_pm.get_path_elements(),
                proof_opt.get_path_elements(),
                "path elements at {index}"
            );
            assert_eq!(
                proof_pm.get_path_index(),
                proof_opt.get_path_index(),
                "path index at {index}"
            );
            assert_eq!(
                proof_pm.compute_root_from(leaf),
                tree_pm.root(),
                "recomputed root at {index}"
            );
        }
    }
}
