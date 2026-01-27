#![cfg(feature = "pmtree-ft")]

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test {
    use std::path::PathBuf;

    use num_traits::identities::Zero;
    use rln::pm_tree_adapter::{PmTree, PmTreeProof, PmtreeConfig};
    use rln::prelude::*;
    use tempfile::TempDir;
    use zerokit_utils::merkle_tree::{
        ZerokitMerkleProof, ZerokitMerkleTree, ZerokitMerkleTreeError,
    };
    use zerokit_utils::pm_tree::Mode;

    const TEST_DEPTH: usize = 10;

    fn _default_config() -> PmtreeConfig {
        PmtreeConfig::default()
    }

    fn temp_config() -> PmtreeConfig {
        PmtreeConfig::builder().temporary(true).build().unwrap()
    }

    fn persistent_config(path: PathBuf) -> PmtreeConfig {
        PmtreeConfig::builder()
            .path(path)
            .temporary(false)
            .build()
            .unwrap()
    }

    #[test]
    fn test_pmtree_config_builder() {
        let config = PmtreeConfig::builder()
            .temporary(true)
            .cache_capacity(1 << 30)
            .flush_every_ms(1000)
            .mode(Mode::LowSpace)
            .use_compression(false)
            .build()
            .unwrap();

        // Indirect confirmation: create a tree with the config and verify operations work
        let mut tree = PmTree::new(TEST_DEPTH, Fr::zero(), config).unwrap();
        let leaf = Fr::from(42);
        tree.set(0, leaf).unwrap();
        assert_eq!(tree.get(0).unwrap(), leaf);
        assert_eq!(tree.leaves_set(), 1);
        let root = tree.root();
        assert_ne!(root, Fr::zero());
    }

    #[test]
    fn test_pmtree_config_from_str() {
        let json = r#"
        {
            "path": "test-path",
            "temporary": false,
            "cache_capacity": 1073741824,
            "flush_every_ms": 500,
            "mode": "HighThroughput",
            "use_compression": false
        }"#;

        let config: PmtreeConfig = json.parse().unwrap();

        // Verify the config by creating a persistent tree
        let mut tree1 = PmTree::new(TEST_DEPTH, Fr::zero(), config.clone()).unwrap();
        let leaf = Fr::from(42);
        tree1.set(0, leaf).unwrap();
        let root1 = tree1.root();
        tree1.close_db_connection().unwrap();
        drop(tree1);

        // Reopen and verify persistence
        let tree2 = PmTree::new(TEST_DEPTH, Fr::zero(), config).unwrap();
        assert_eq!(tree2.get(0).unwrap(), leaf);
        assert_eq!(tree2.root(), root1);
    }

    #[test]
    fn test_pmtree_config_from_str_invalid() {
        let temp_dir = TempDir::new().unwrap();
        let existing_path = temp_dir.path().to_str().unwrap();
        let invalid_json = format!(r#"{{"temporary": true, "path": "{}"}}"#, existing_path);
        let result: Result<PmtreeConfig, _> = invalid_json.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_pmtree_tree_creation_default() {
        let tree = PmTree::default(TEST_DEPTH).unwrap();
        assert_eq!(tree.depth(), TEST_DEPTH);
        assert_eq!(tree.capacity(), 1 << TEST_DEPTH);
        assert_eq!(tree.leaves_set(), 0);
    }

    #[test]
    fn test_pmtree_tree_creation_new() {
        let config = temp_config();
        let tree = PmTree::new(TEST_DEPTH, Fr::from(0), config).unwrap();
        assert_eq!(tree.depth(), TEST_DEPTH);
    }

    #[test]
    fn test_pmtree_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let config = persistent_config(db_path.clone());

        // Create and populate
        let mut tree1 = PmTree::new(TEST_DEPTH, Fr::zero(), config.clone()).unwrap();
        let leaf = Fr::from(42);
        tree1.update_next(leaf).unwrap();
        let root1 = tree1.root();
        tree1.set_metadata(b"test metadata").unwrap();
        tree1.close_db_connection().unwrap();
        drop(tree1);

        // Load and verify
        let tree2 = PmTree::new(TEST_DEPTH, Fr::zero(), config).unwrap();
        assert_eq!(tree2.root(), root1);
        assert_eq!(tree2.metadata().unwrap(), b"test metadata");
        assert_eq!(tree2.leaves_set(), 1);
        assert_eq!(tree2.get(0).unwrap(), leaf);
    }

    #[test]
    fn test_pmtree_load_nonexistent() {
        let config = persistent_config(PathBuf::from("\0invalid"));
        let result = PmTree::new(TEST_DEPTH, Fr::zero(), config);
        assert!(matches!(
            result,
            Err(ZerokitMerkleTreeError::PmtreeErrorKind(_))
        ));
    }

    #[test]
    fn test_pmtree_basic_operations() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        let leaf = Fr::from(123);
        tree.set(5, leaf).unwrap();
        assert_eq!(tree.get(5).unwrap(), leaf);
        assert_eq!(tree.leaves_set(), 6); // Next index
        assert_ne!(tree.root(), Fr::zero());
    }

    #[test]
    fn test_pmtree_update_next() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
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
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        let leaves: Vec<Fr> = (0..4).map(|i| Fr::from(i as u64)).collect();
        tree.set_range(1, leaves.into_iter()).unwrap();
        assert_eq!(tree.get(1).unwrap(), Fr::from(0));
        assert_eq!(tree.get(4).unwrap(), Fr::from(3));
    }

    #[test]
    fn test_pmtree_delete() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        let leaf = Fr::from(99);
        tree.set(2, leaf).unwrap();
        assert_eq!(tree.get(2).unwrap(), leaf);
        tree.delete(2).unwrap();
        assert_eq!(tree.get(2).unwrap(), Fr::zero()); // Default leaf
        assert_eq!(tree.leaves_set(), 3); // Unchanged
    }

    #[test]
    fn test_pmtree_override_range() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        tree.set(0, Fr::from(1)).unwrap();
        tree.set(1, Fr::from(2)).unwrap();

        // Set new leaves
        let new_leaves = vec![Fr::from(10), Fr::from(20)];
        tree.override_range(0, new_leaves.into_iter(), vec![].into_iter())
            .unwrap();
        assert_eq!(tree.get(0).unwrap(), Fr::from(10));
        assert_eq!(tree.get(1).unwrap(), Fr::from(20));

        // Delete indices
        tree.override_range(0, vec![].into_iter(), vec![0].into_iter())
            .unwrap();
        assert_eq!(tree.get(0).unwrap(), Fr::zero());
    }

    #[test]
    fn test_pmtree_get_empty_leaves_indices() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
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
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        let leaf = Fr::from(42);
        tree.set(3, leaf).unwrap();
        let proof: PmTreeProof = tree.proof(3).unwrap();
        assert_eq!(proof.leaf_index(), 3);
        assert!(tree.verify(&leaf, &proof).unwrap());
        assert!(matches!(
            tree.verify(&Fr::from(43), &proof),
            Err(ZerokitMerkleTreeError::InvalidMerkleProof)
        ));
    }

    #[test]
    fn test_pmtree_get_subtree_root() {
        let mut tree = PmTree::default(3).unwrap(); // Depth 3 for simplicity
        tree.set(0, Fr::from(1)).unwrap();
        tree.set(1, Fr::from(2)).unwrap();
        // Root is level 0
        assert_eq!(tree.get_subtree_root(0, 0).unwrap(), tree.root());
        // Leaf is level 3
        assert_eq!(tree.get_subtree_root(3, 0).unwrap(), Fr::from(1));
    }

    #[test]
    fn test_pmtree_metadata() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        let meta = b"hello world";
        tree.set_metadata(meta).unwrap();
        assert_eq!(tree.metadata().unwrap(), meta);
    }

    #[test]
    fn test_pmtree_close_db() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
        tree.close_db_connection().unwrap();
        // Verify idempotence: calling close again should succeed
        tree.close_db_connection().unwrap();
        // Verify that the tree still works after close (close is a no-op)
        assert_eq!(tree.get(0).unwrap(), Fr::zero());
    }

    #[test]
    fn test_pmtree_invalid_index() {
        let tree = PmTree::default(TEST_DEPTH).unwrap();
        let capacity = tree.capacity();
        assert!(matches!(
            tree.proof(capacity),
            Err(ZerokitMerkleTreeError::PmtreeErrorKind(_))
        ));
        assert!(matches!(
            tree.get(capacity),
            Err(ZerokitMerkleTreeError::PmtreeErrorKind(_))
        ));
    }

    #[test]
    fn test_pmtree_invalid_subtree_root() {
        let tree = PmTree::default(TEST_DEPTH).unwrap();
        assert!(matches!(
            tree.get_subtree_root(TEST_DEPTH + 1, 0),
            Err(ZerokitMerkleTreeError::InvalidLevel)
        ));
    }

    #[test]
    fn test_pmtree_proof_binds_to_leaf_index_even_if_leaf_value_same() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();

        let leaf = Fr::from(42);
        tree.set(0, leaf).unwrap();
        tree.set(1, leaf).unwrap();

        let proof0: PmTreeProof = tree.proof(0).unwrap();
        let proof1: PmTreeProof = tree.proof(1).unwrap();

        // Both proofs should reconstruct the current root when used with the correct leaf value,
        // but their *paths/indexes* should differ.
        let root0 = proof0.compute_root_from(&leaf).unwrap();
        let root1 = proof1.compute_root_from(&leaf).unwrap();
        assert_eq!(root0, tree.root());
        assert_eq!(root1, tree.root());

        // The "index binding" evidence: either leaf_index differs or path_index differs.
        assert_ne!(proof0.leaf_index(), proof1.leaf_index());
        assert_ne!(proof0.get_path_index(), proof1.get_path_index());
    }

    #[test]
    fn test_pmtree_modes() {
        let config_ht = PmtreeConfig::builder()
            .mode(Mode::HighThroughput)
            .build()
            .unwrap();
        let config_ls = PmtreeConfig::builder()
            .mode(Mode::LowSpace)
            .build()
            .unwrap();
        let mut tree_ht = PmTree::new(TEST_DEPTH, Fr::zero(), config_ht).unwrap();
        let mut tree_ls = PmTree::new(TEST_DEPTH, Fr::zero(), config_ls).unwrap();
        tree_ht.set(0, Fr::from(1)).unwrap();
        tree_ls.set(0, Fr::from(1)).unwrap();
        // Roots should be same regardless of mode
        assert_eq!(tree_ht.root(), tree_ls.root());
    }

    #[test]
    fn test_pmtree_compression() {
        let config_comp = PmtreeConfig::builder()
            .use_compression(true)
            .build()
            .unwrap();
        let config_no_comp = PmtreeConfig::builder()
            .use_compression(false)
            .build()
            .unwrap();
        let mut tree_comp = PmTree::new(TEST_DEPTH, Fr::zero(), config_comp).unwrap();
        let mut tree_no_comp = PmTree::new(TEST_DEPTH, Fr::zero(), config_no_comp).unwrap();
        tree_comp.set(0, Fr::from(1)).unwrap();
        tree_no_comp.set(0, Fr::from(1)).unwrap();
        assert_eq!(tree_comp.root(), tree_no_comp.root());
    }

    #[test]
    fn test_pmtree_stress_large() {
        let mut tree = PmTree::default(15).unwrap(); // Smaller for test
        for i in 0..100 {
            tree.update_next(Fr::from(i as u64)).unwrap();
        }
        assert_eq!(tree.leaves_set(), 100);
        let proof = tree.proof(50).unwrap();
        assert!(tree.verify(&Fr::from(50), &proof).unwrap());
    }

    #[test]
    fn test_pmtree_full_tree() {
        let mut tree = PmTree::default(4).unwrap(); // 16 capacity
        for i in 0..16 {
            tree.set(i, Fr::from(i as u64)).unwrap();
        }
        assert_eq!(tree.leaves_set(), 16);
        assert_eq!(tree.capacity(), 16);
        // Try overflow
        assert!(matches!(
            tree.update_next(Fr::from(16)),
            Err(ZerokitMerkleTreeError::PmtreeErrorKind(_))
        ));
        assert!(matches!(
            tree.set(16, Fr::from(16)),
            Err(ZerokitMerkleTreeError::PmtreeErrorKind(_))
        ));
    }

    #[test]
    fn test_pmtree_large_batch() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
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
            let mut tree1 = PmTree::new(TEST_DEPTH, Fr::zero(), config.clone()).unwrap();
            tree1.set(0, Fr::from(1)).unwrap();

            // Optional stronger signal than just leaf persistence:
            assert_ne!(tree1.root(), Fr::zero());

            tree1.close_db_connection().unwrap();
        }

        // Second open: verify data, close, and drop.
        {
            let mut tree2 = PmTree::new(TEST_DEPTH, Fr::zero(), config.clone()).unwrap();
            assert_eq!(tree2.get(0).unwrap(), Fr::from(1));

            // Optional: verify tree is still non-empty (depending on semantics).
            assert_ne!(tree2.root(), Fr::zero());

            tree2.close_db_connection().unwrap();
        }

        // Third open: verify again.
        {
            let tree3 = PmTree::new(TEST_DEPTH, Fr::zero(), config).unwrap();
            assert_eq!(tree3.get(0).unwrap(), Fr::from(1));
            assert_ne!(tree3.root(), Fr::zero());
        }
    }

    #[test]
    fn test_pmtree_depth_extremes() {
        // Depth 0 (minimal valid depth)
        let result = PmTree::default(0);
        assert!(result.is_ok());
        if let Ok(tree) = result {
            assert_eq!(tree.depth(), 0);
            assert_eq!(tree.capacity(), 1);
        }
        // Depth 32
        let result = PmTree::default(32);
        if let Ok(tree) = result {
            assert_eq!(tree.depth(), 32);
            assert_eq!(tree.capacity(), 1usize << 32);
        }
    }

    #[test]
    fn test_pmtree_compaction() {
        let mut tree = PmTree::default(TEST_DEPTH).unwrap();
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
}
