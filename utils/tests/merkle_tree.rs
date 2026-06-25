// Tests adapted from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
#[cfg(test)]
mod test {
    use std::{fmt::Display, str::FromStr};

    use hex_literal::hex;
    use tiny_keccak::{Hasher as _, Keccak};
    use zerokit_utils::merkle_tree::{
        FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig, OptimalMerkleTree,
        ZerokitMerkleProof, ZerokitMerkleTree, ZerokitMerkleTreeError, MIN_PARALLEL_NODES,
    };
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Keccak256;

    #[derive(Clone, Copy, Eq, PartialEq, Debug, Default)]
    struct TestFr([u8; 32]);

    impl Hasher for Keccak256 {
        type Fr = TestFr;

        fn default_leaf() -> Self::Fr {
            TestFr([0; 32])
        }

        fn hash_pair(left: Self::Fr, right: Self::Fr) -> Self::Fr {
            let mut output = [0; 32];
            let mut hasher = Keccak::v256();
            hasher.update(left.0.as_slice());
            hasher.update(right.0.as_slice());
            hasher.finalize(&mut output);
            TestFr(output)
        }
    }

    impl Display for TestFr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", hex::encode(self.0.as_slice()))
        }
    }

    impl FromStr for TestFr {
        type Err = std::string::FromUtf8Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(TestFr(s.as_bytes().try_into().unwrap()))
        }
    }

    impl From<u32> for TestFr {
        fn from(value: u32) -> Self {
            let mut bytes: Vec<u8> = vec![0; 28];
            bytes.extend_from_slice(&value.to_be_bytes());
            TestFr(bytes.as_slice().try_into().unwrap())
        }
    }

    const DEFAULT_DEPTH: usize = 2;

    fn default_full_merkle_tree(depth: usize) -> FullMerkleTree<Keccak256> {
        FullMerkleTree::<Keccak256>::new(depth, TestFr([0; 32]), FullMerkleConfig::default())
            .unwrap()
    }

    fn default_optimal_merkle_tree(depth: usize) -> OptimalMerkleTree<Keccak256> {
        OptimalMerkleTree::<Keccak256>::new(depth, TestFr([0; 32]), OptimalMerkleConfig::default())
            .unwrap()
    }

    #[test]
    fn test_root() {
        let default_tree_root = TestFr(hex!(
            "b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30"
        ));

        let roots = [
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95"),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b"),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c"),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36"),
        ]
        .map(TestFr);

        let leaf_count = 4;
        let leaves: Vec<TestFr> = (1..=leaf_count as u32).map(TestFr::from).collect();

        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        assert_eq!(tree_full.root(), default_tree_root);
        for i in 0..leaf_count {
            tree_full.set(i, leaves[i]).unwrap();
            assert_eq!(tree_full.root(), roots[i]);
        }

        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        assert_eq!(tree_opt.root(), default_tree_root);
        for i in 0..leaf_count {
            tree_opt.set(i, leaves[i]).unwrap();
            assert_eq!(tree_opt.root(), roots[i]);
        }
    }

    #[test]
    fn test_set_range() {
        let depth = 4;
        let leaves: Vec<TestFr> = (0..(1 << depth) as u32).map(TestFr::from).collect();

        let mut tree_full = default_full_merkle_tree(depth);
        let root_before = tree_full.root();
        tree_full.set_range(0, leaves.iter().cloned()).unwrap();
        let root_after = tree_full.root();
        assert_ne!(root_before, root_after);

        let mut tree_opt = default_optimal_merkle_tree(depth);
        let root_before = tree_opt.root();
        tree_opt.set_range(0, leaves.iter().cloned()).unwrap();
        let root_after = tree_opt.root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_full_merkle_tree_new_depth_shift_overflow() {
        let depth = usize::BITS as usize;
        let result =
            FullMerkleTree::<Keccak256>::new(depth, TestFr([0; 32]), FullMerkleConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_optimal_merkle_tree_new_depth_shift_overflow() {
        let depth = usize::BITS as usize;
        let result = OptimalMerkleTree::<Keccak256>::new(
            depth,
            TestFr([0; 32]),
            OptimalMerkleConfig::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_full_merkle_tree_set_range_start_overflow() {
        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let result = tree_full.set_range(usize::MAX, std::iter::once(TestFr::from(1u32)));
        assert!(result.is_err());
    }

    #[test]
    fn test_optimal_merkle_tree_set_range_start_overflow() {
        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        let result = tree_opt.set_range(usize::MAX, std::iter::once(TestFr::from(1u32)));
        assert!(result.is_err());
    }

    #[test]
    fn test_full_merkle_tree_override_range() {
        // Full overlap: write [5,6] over deleted [0,1] (writes win, untouched leaves preserved).
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_full
            .override_range(0, [5, 6].map(TestFr::from), [0usize, 1])
            .unwrap();
        for (i, &v) in [5u32, 6, 30, 40].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), Vec::<usize>::new());

        // Shift repro: delete idx0, write 99 at idx2 (the write must NOT shift right).
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_full
            .override_range(2, std::iter::once(TestFr::from(99)), [0usize])
            .unwrap();
        for (i, &v) in [0u32, 20, 99, 40].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![0]);

        // More deletes than writes: write [5,6] at start, delete [0,1,2,3] (writes win, untouched leaves preserved).
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_full
            .override_range(0, [5, 6].map(TestFr::from), [0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [5u32, 6, 0, 0].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![2, 3]);

        // Deletes entirely before the write range (no overlap).
        let mut tree_full = default_full_merkle_tree(4);
        tree_full
            .set_range(
                0,
                [10, 20, 30, 40, 50, 60, 70, 80]
                    .map(TestFr::from)
                    .into_iter(),
            )
            .unwrap();
        tree_full
            .override_range(4, [1, 2, 3, 4].map(TestFr::from), [0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [0u32, 0, 0, 0, 1, 2, 3, 4].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![0, 1, 2, 3]);

        // Partial overlap: write [1,2,3,4] at idx2, delete [0,1,2,3] (idx2,3 overlap the write).
        let mut tree_full = default_full_merkle_tree(4);
        tree_full
            .set_range(
                0,
                [10, 20, 30, 40, 50, 60, 70, 80]
                    .map(TestFr::from)
                    .into_iter(),
            )
            .unwrap();
        tree_full
            .override_range(2, [1, 2, 3, 4].map(TestFr::from), [0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [0u32, 0, 1, 2, 3, 4, 70, 80].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![0, 1]);

        // Writes only (empty deletes).
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_full
            .override_range(1, [7, 8].map(TestFr::from), std::iter::empty::<usize>())
            .unwrap();
        for (i, &v) in [10u32, 7, 8, 40].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), Vec::<usize>::new());

        // Deletes only (empty writes).
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_full
            .override_range(0, std::iter::empty::<TestFr>(), [1usize, 3])
            .unwrap();
        for (i, &v) in [10u32, 0, 30, 0].iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), TestFr::from(v), "full leaf {i}");
        }
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![1, 3]);

        // Validation: both inputs empty -> InvalidLeaf.
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20].map(TestFr::from).into_iter())
            .unwrap();
        assert!(matches!(
            tree_full.override_range(0, std::iter::empty::<TestFr>(), std::iter::empty::<usize>()),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));

        // Validation: a non-overlapping delete index >= leaves_set -> InvalidIndices.
        let mut tree_full = default_full_merkle_tree(3);
        tree_full
            .set_range(0, [10, 20].map(TestFr::from).into_iter())
            .unwrap();
        assert!(matches!(
            tree_full.override_range(0, std::iter::once(TestFr::from(5)), [5usize]),
            Err(ZerokitMerkleTreeError::InvalidIndices)
        ));

        // Validation: start + leaves.len() > capacity -> TooManySet.
        let mut tree_full = default_full_merkle_tree(2);
        assert!(matches!(
            tree_full.override_range(3, [1, 2].map(TestFr::from), std::iter::empty::<usize>()),
            Err(ZerokitMerkleTreeError::TooManySet)
        ));

        // Validation: start + leaves.len() overflows usize -> TooManySet.
        let mut tree_full = default_full_merkle_tree(2);
        assert!(matches!(
            tree_full.override_range(
                usize::MAX,
                std::iter::once(TestFr::from(1)),
                std::iter::empty::<usize>()
            ),
            Err(ZerokitMerkleTreeError::TooManySet)
        ));
    }

    #[test]
    fn test_optimal_merkle_tree_override_range() {
        // Full overlap: write [5,6] over deleted [0,1] (writes win, untouched leaves preserved).
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_opt
            .override_range(0, [5, 6].map(TestFr::from), [0usize, 1])
            .unwrap();
        for (i, &v) in [5u32, 6, 30, 40].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), Vec::<usize>::new());

        // Shift repro: delete idx0, write 99 at idx2 (the write must NOT shift right).
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_opt
            .override_range(2, std::iter::once(TestFr::from(99)), [0usize])
            .unwrap();
        for (i, &v) in [0u32, 20, 99, 40].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![0]);

        // More deletes than writes: write [5,6] at start, delete [0,1,2,3].
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_opt
            .override_range(0, [5, 6].map(TestFr::from), [0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [5u32, 6, 0, 0].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![2, 3]);

        // Deletes entirely before the write range (no overlap).
        let mut tree_opt = default_optimal_merkle_tree(4);
        tree_opt
            .set_range(
                0,
                [10, 20, 30, 40, 50, 60, 70, 80]
                    .map(TestFr::from)
                    .into_iter(),
            )
            .unwrap();
        tree_opt
            .override_range(4, [1, 2, 3, 4].map(TestFr::from), [0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [0u32, 0, 0, 0, 1, 2, 3, 4].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![0, 1, 2, 3]);

        // Partial overlap: write [1,2,3,4] at idx2, delete [0,1,2,3] (idx2,3 overlap the write).
        let mut tree_opt = default_optimal_merkle_tree(4);
        tree_opt
            .set_range(
                0,
                [10, 20, 30, 40, 50, 60, 70, 80]
                    .map(TestFr::from)
                    .into_iter(),
            )
            .unwrap();
        tree_opt
            .override_range(2, [1, 2, 3, 4].map(TestFr::from), [0usize, 1, 2, 3])
            .unwrap();
        for (i, &v) in [0u32, 0, 1, 2, 3, 4, 70, 80].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![0, 1]);

        // Writes only (empty deletes).
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_opt
            .override_range(1, [7, 8].map(TestFr::from), std::iter::empty::<usize>())
            .unwrap();
        for (i, &v) in [10u32, 7, 8, 40].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), Vec::<usize>::new());

        // Deletes only (empty writes).
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20, 30, 40].map(TestFr::from).into_iter())
            .unwrap();
        tree_opt
            .override_range(0, std::iter::empty::<TestFr>(), [1usize, 3])
            .unwrap();
        for (i, &v) in [10u32, 0, 30, 0].iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), TestFr::from(v), "opt leaf {i}");
        }
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![1, 3]);

        // Validation: both inputs empty -> InvalidLeaf.
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20].map(TestFr::from).into_iter())
            .unwrap();
        assert!(matches!(
            tree_opt.override_range(0, std::iter::empty::<TestFr>(), std::iter::empty::<usize>()),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));

        // Validation: a non-overlapping delete index >= leaves_set -> InvalidIndices.
        let mut tree_opt = default_optimal_merkle_tree(3);
        tree_opt
            .set_range(0, [10, 20].map(TestFr::from).into_iter())
            .unwrap();
        assert!(matches!(
            tree_opt.override_range(0, std::iter::once(TestFr::from(5)), [5usize]),
            Err(ZerokitMerkleTreeError::InvalidIndices)
        ));

        // Validation: start + leaves.len() > capacity -> TooManySet.
        let mut tree_opt = default_optimal_merkle_tree(2);
        assert!(matches!(
            tree_opt.override_range(3, [1, 2].map(TestFr::from), std::iter::empty::<usize>()),
            Err(ZerokitMerkleTreeError::TooManySet)
        ));

        // Validation: start + leaves.len() overflows usize -> TooManySet.
        let mut tree_opt = default_optimal_merkle_tree(2);
        assert!(matches!(
            tree_opt.override_range(
                usize::MAX,
                std::iter::once(TestFr::from(1)),
                std::iter::empty::<usize>()
            ),
            Err(ZerokitMerkleTreeError::TooManySet)
        ));
    }

    #[test]
    fn test_update_next() {
        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);

        for i in 0..4 {
            let leaf = TestFr::from(i as u32);
            tree_full.update_next(leaf).unwrap();
            tree_opt.update_next(leaf).unwrap();
            assert_eq!(tree_full.get(i).unwrap(), leaf);
            assert_eq!(tree_opt.get(i).unwrap(), leaf);
        }

        assert_eq!(tree_full.leaves_set(), 4);
        assert_eq!(tree_opt.leaves_set(), 4);
    }

    #[test]
    fn test_delete_and_reset() {
        let index = 1;
        let original_leaf = TestFr::from(42);
        let new_leaf = TestFr::from(99);

        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        tree_full.set(index, original_leaf).unwrap();
        let root_with_original = tree_full.root();

        tree_full.delete(index).unwrap();
        let root_after_delete = tree_full.root();
        assert_ne!(root_with_original, root_after_delete);

        tree_full.set(index, new_leaf).unwrap();
        let root_after_reset = tree_full.root();

        assert_ne!(root_after_delete, root_after_reset);
        assert_ne!(root_with_original, root_after_reset);
        assert_eq!(tree_full.get(index).unwrap(), new_leaf);

        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        tree_opt.set(index, original_leaf).unwrap();
        let root_with_original = tree_opt.root();

        tree_opt.delete(index).unwrap();
        let root_after_delete = tree_opt.root();
        assert_ne!(root_with_original, root_after_delete);

        tree_opt.set(index, new_leaf).unwrap();
        let root_after_reset = tree_opt.root();

        assert_ne!(root_after_delete, root_after_reset);
        assert_ne!(root_with_original, root_after_reset);
        assert_eq!(tree_opt.get(index).unwrap(), new_leaf);

        // Deleting an unset index (>= leaves_set) errors on both in-memory backends.
        let unset_full = tree_full.leaves_set();
        assert!(matches!(
            tree_full.delete(unset_full),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));
        let unset_opt = tree_opt.leaves_set();
        assert!(matches!(
            tree_opt.delete(unset_opt),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));
    }

    #[test]
    fn test_get_empty_leaves_indices() {
        let depth = 4;
        let leaf_count: usize = 1 << (depth - 1);
        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();

        let mut tree_full = default_full_merkle_tree(depth);
        let _ = tree_full.set_range(0, leaves.clone().into_iter());
        assert!(tree_full.get_empty_leaves_indices().is_empty());

        let mut vec_idxs = Vec::new();
        for i in 0..leaf_count {
            vec_idxs.push(i);
            let _ = tree_full.delete(i);
            assert_eq!(tree_full.get_empty_leaves_indices(), vec_idxs);
        }

        for i in (0..leaf_count).rev() {
            vec_idxs.pop();
            let _ = tree_full.set(i, leaves[i]);
            assert_eq!(tree_full.get_empty_leaves_indices(), vec_idxs);
        }
        assert!(tree_full.get_empty_leaves_indices().is_empty());

        let mut tree_opt = default_optimal_merkle_tree(depth);
        let _ = tree_opt.set_range(0, leaves.clone().into_iter());
        assert!(tree_opt.get_empty_leaves_indices().is_empty());

        let mut vec_idxs = Vec::new();
        for i in 0..leaf_count {
            vec_idxs.push(i);
            let _ = tree_opt.delete(i);
            assert_eq!(tree_opt.get_empty_leaves_indices(), vec_idxs);
        }
        for i in (0..leaf_count).rev() {
            vec_idxs.pop();
            let _ = tree_opt.set(i, leaves[i]);
            assert_eq!(tree_opt.get_empty_leaves_indices(), vec_idxs);
        }
        assert!(tree_opt.get_empty_leaves_indices().is_empty());
    }

    #[test]
    fn test_subtree_root() {
        let depth = 3;
        let leaf_count: usize = 4;
        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();

        let mut tree_full = default_full_merkle_tree(depth);
        let _ = tree_full.set_range(0, leaves.iter().cloned());

        for i in 0..leaf_count {
            // check leaves
            assert_eq!(
                tree_full.get(i).unwrap(),
                tree_full.get_subtree_root(depth, i).unwrap()
            );

            // check root
            assert_eq!(tree_full.root(), tree_full.get_subtree_root(0, i).unwrap());
        }

        // check intermediate nodes
        for n in (1..=depth).rev() {
            for i in (0..(1 << n)).step_by(2) {
                let idx_l = i * (1 << (depth - n));
                let idx_r = (i + 1) * (1 << (depth - n));
                let idx_sr = idx_l;

                let prev_l = tree_full.get_subtree_root(n, idx_l).unwrap();
                let prev_r = tree_full.get_subtree_root(n, idx_r).unwrap();
                let subroot = tree_full.get_subtree_root(n - 1, idx_sr).unwrap();

                // check intermediate nodes
                assert_eq!(Keccak256::hash_pair(prev_l, prev_r), subroot);
            }
        }

        let mut tree_opt = default_optimal_merkle_tree(depth);
        let _ = tree_opt.set_range(0, leaves.iter().cloned());

        for i in 0..leaf_count {
            // check leaves
            assert_eq!(
                tree_opt.get(i).unwrap(),
                tree_opt.get_subtree_root(depth, i).unwrap()
            );
            // check root
            assert_eq!(tree_opt.root(), tree_opt.get_subtree_root(0, i).unwrap());
        }

        // check intermediate nodes
        for n in (1..=depth).rev() {
            for i in (0..(1 << n)).step_by(2) {
                let idx_l = i * (1 << (depth - n));
                let idx_r = (i + 1) * (1 << (depth - n));
                let idx_sr = idx_l;

                let prev_l = tree_opt.get_subtree_root(n, idx_l).unwrap();
                let prev_r = tree_opt.get_subtree_root(n, idx_r).unwrap();
                let subroot = tree_opt.get_subtree_root(n - 1, idx_sr).unwrap();

                // check intermediate nodes
                assert_eq!(Keccak256::hash_pair(prev_l, prev_r), subroot);
            }
        }
    }

    #[test]
    fn test_proof() {
        let leaf_count = 4;
        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();

        // We test the FullMerkleTree implementation
        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        for i in 0..leaf_count {
            // We set the leaves
            tree_full.set(i, leaves[i]).unwrap();

            // We compute a merkle proof
            let proof = tree_full.proof(i).unwrap();

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree_full.verify(&leaves[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&leaves[i]), tree_full.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree_full
                .verify(&leaves[(i + 1) % leaf_count], &proof)
                .unwrap());
        }

        // We test the OptimalMerkleTree implementation
        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        for i in 0..leaf_count {
            // We set the leaves
            tree_opt.set(i, leaves[i]).unwrap();

            // We compute a merkle proof
            let proof = tree_opt.proof(i).unwrap();

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree_opt.verify(&leaves[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&leaves[i]), tree_opt.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree_opt
                .verify(&leaves[(i + 1) % leaf_count], &proof)
                .unwrap());
        }
    }

    #[test]
    fn test_proof_fail() {
        let tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);

        let invalid_leaf = TestFr::from(12345);

        let proof_full = tree_full.proof(0).unwrap();
        let proof_opt = tree_opt.proof(0).unwrap();

        // Should fail because no leaf was set
        assert!(!tree_full.verify(&invalid_leaf, &proof_full).unwrap());
        assert!(!tree_opt.verify(&invalid_leaf, &proof_opt).unwrap());
    }

    #[test]
    fn test_override_range_parallel_triggered() {
        let depth = 13;
        let leaf_count = 8192;

        // number of leaves larger than MIN_PARALLEL_NODES to trigger parallel hashing
        assert!(MIN_PARALLEL_NODES < leaf_count);

        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();
        let indices: Vec<usize> = (0..leaf_count).collect();

        let mut tree_full = default_full_merkle_tree(depth);

        tree_full
            .override_range(0, leaves.iter().cloned(), indices.iter().cloned())
            .unwrap();

        for (i, &leaf) in leaves.iter().enumerate() {
            assert_eq!(tree_full.get(i).unwrap(), leaf);
        }

        let mut tree_opt = default_optimal_merkle_tree(depth);

        tree_opt
            .override_range(0, leaves.iter().cloned(), indices.iter().cloned())
            .unwrap();

        for (i, &leaf) in leaves.iter().enumerate() {
            assert_eq!(tree_opt.get(i).unwrap(), leaf);
        }
    }

    #[test]
    fn test_proof_invalid_index() {
        let tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        let invalid_index = tree_full.capacity();

        assert!(matches!(
            tree_full.proof(invalid_index),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));
        assert!(matches!(
            tree_opt.proof(invalid_index),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));
    }

    #[test]
    fn test_verify_proof_length_mismatch() {
        let tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        let leaf = TestFr::from(1u32);
        let proof = tree_opt.proof(0).unwrap();
        let mut short_proof = proof.clone();
        short_proof.0.truncate(proof.length() - 1); // Shorten

        assert!(matches!(
            tree_opt.verify(&leaf, &short_proof),
            Err(ZerokitMerkleTreeError::InvalidMerkleProof)
        ));
    }

    #[test]
    fn test_verify_tampered_sibling() {
        let leaf_count = 4;
        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();

        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        tree_opt.set_range(0, leaves.iter().cloned()).unwrap();

        let index = 1;
        let leaf = leaves[index];
        let mut proof_opt = tree_opt.proof(index).unwrap();

        // Tamper first sibling
        proof_opt.0[0].0 = TestFr::from(999u32);

        assert!(!tree_opt.verify(&leaf, &proof_opt).unwrap());
    }

    #[test]
    fn test_verify_tampered_direction() {
        let leaf_count = 4;
        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();

        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        tree_opt.set_range(0, leaves.iter().cloned()).unwrap();

        let index = 1;
        let leaf = leaves[index];
        let mut proof_opt = tree_opt.proof(index).unwrap();

        // Flip first direction
        proof_opt.0[0].1 = 1 - proof_opt.0[0].1;

        assert!(!tree_opt.verify(&leaf, &proof_opt).unwrap());
    }

    #[test]
    fn test_verify_mismatched_root() {
        let leaf_count = 4;
        let leaves: Vec<TestFr> = (0..leaf_count as u32).map(TestFr::from).collect();

        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        tree_full.set_range(0, leaves.iter().cloned()).unwrap();
        tree_opt.set_range(0, leaves.iter().cloned()).unwrap();

        let index = 0;
        let leaf = leaves[index];
        let proof_full = tree_full.proof(index).unwrap();
        let proof_opt = tree_opt.proof(index).unwrap();

        // Modify another leaf to change root
        tree_full.set(1, TestFr::from(999u32)).unwrap();
        tree_opt.set(1, TestFr::from(999u32)).unwrap();

        assert!(!tree_full.verify(&leaf, &proof_full).unwrap());
        assert!(!tree_opt.verify(&leaf, &proof_opt).unwrap());
    }

    #[test]
    fn test_get_out_of_bounds() {
        let tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        let out_of_bounds = tree_full.capacity();
        assert!(matches!(
            tree_full.get(out_of_bounds),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));
        assert!(matches!(
            tree_opt.get(out_of_bounds),
            Err(ZerokitMerkleTreeError::InvalidLeaf)
        ));
    }

    #[test]
    fn test_set_out_of_bounds() {
        let mut tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let mut tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        let out_of_bounds = tree_full.capacity();
        assert!(tree_full.set(out_of_bounds, TestFr::from(1u32)).is_err());
        assert!(tree_opt.set(out_of_bounds, TestFr::from(1u32)).is_err());
    }

    #[test]
    fn test_get_subtree_root_out_of_bounds() {
        let tree_full = default_full_merkle_tree(DEFAULT_DEPTH);
        let tree_opt = default_optimal_merkle_tree(DEFAULT_DEPTH);
        let depth = tree_full.depth();
        let capacity = tree_full.capacity();
        // Level deeper than the tree.
        assert!(tree_full.get_subtree_root(depth + 1, 0).is_err());
        assert!(tree_opt.get_subtree_root(depth + 1, 0).is_err());
        // Index past capacity.
        assert!(tree_full.get_subtree_root(depth, capacity).is_err());
        assert!(tree_opt.get_subtree_root(depth, capacity).is_err());
    }

    #[test]
    fn test_update_next_past_capacity() {
        let depth = 2; // capacity 4
        let mut tree_full = default_full_merkle_tree(depth);
        let mut tree_opt = default_optimal_merkle_tree(depth);
        for i in 0..4u32 {
            tree_full.update_next(TestFr::from(i)).unwrap();
            tree_opt.update_next(TestFr::from(i)).unwrap();
        }
        assert_eq!(tree_full.leaves_set(), tree_full.capacity());
        assert!(tree_full.update_next(TestFr::from(99u32)).is_err());
        assert!(tree_opt.update_next(TestFr::from(99u32)).is_err());
    }

    #[test]
    fn test_full_optimal_root_and_proof_equivalence() {
        // The two in-memory backends must agree on the root and proof for the same set of leaves.
        let depth = 4;
        let leaves: Vec<TestFr> = (0..(1u32 << depth))
            .map(|i| TestFr::from(i * 3 + 1))
            .collect();

        let mut tree_full = default_full_merkle_tree(depth);
        let mut tree_opt = default_optimal_merkle_tree(depth);
        tree_full.set_range(0, leaves.iter().cloned()).unwrap();
        tree_opt.set_range(0, leaves.iter().cloned()).unwrap();

        assert_eq!(tree_full.root(), tree_opt.root());

        for (index, leaf) in leaves.iter().enumerate() {
            let proof_full = tree_full.proof(index).unwrap();
            let proof_opt = tree_opt.proof(index).unwrap();
            assert_eq!(
                proof_full.get_path_elements(),
                proof_opt.get_path_elements(),
                "path elements at {index}"
            );
            assert_eq!(
                proof_full.get_path_index(),
                proof_opt.get_path_index(),
                "path index at {index}"
            );
            assert_eq!(
                proof_full.compute_root_from(leaf),
                tree_full.root(),
                "recomputed root at {index}"
            );
        }
    }
}
