// Tests adapted from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
#[cfg(test)]
pub mod test {
    use hex_literal::hex;
    use std::{fmt::Display, str::FromStr};
    use tiny_keccak::{Hasher as _, Keccak};
    use zerokit_utils::{
        FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig, OptimalMerkleTree,
        ZerokitMerkleProof, ZerokitMerkleTree,
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

        fn hash(inputs: &[Self::Fr]) -> Self::Fr {
            let mut output = [0; 32];
            let mut hasher = Keccak::v256();
            for element in inputs {
                hasher.update(element.0.as_slice());
            }
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

        let nof_leaves = 4;
        let leaves: Vec<TestFr> = (1..=nof_leaves as u32).map(TestFr::from).collect();

        let mut tree = default_full_merkle_tree(DEFAULT_DEPTH);
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..nof_leaves {
            tree.set(i, leaves[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }

        let mut tree = default_optimal_merkle_tree(DEFAULT_DEPTH);
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..nof_leaves {
            tree.set(i, leaves[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }
    }

    #[test]
    fn test_get_empty_leaves_indices() {
        let depth = 4;
        let nof_leaves: usize = 1 << (depth - 1);
        let leaves: Vec<TestFr> = (0..nof_leaves as u32).map(TestFr::from).collect();
        let leaves_2: Vec<TestFr> = (0u32..2).map(TestFr::from).collect();
        let leaves_4: Vec<TestFr> = (0u32..4).map(TestFr::from).collect();

        let mut tree_full = default_full_merkle_tree(depth);
        let _ = tree_full.set_range(0, leaves.clone());
        assert!(tree_full.get_empty_leaves_indices().is_empty());

        let mut vec_idxs = Vec::new();
        for i in 0..nof_leaves {
            vec_idxs.push(i);
            let _ = tree_full.delete(i);
            assert_eq!(tree_full.get_empty_leaves_indices(), vec_idxs);
        }

        for i in (0..nof_leaves).rev() {
            vec_idxs.pop();
            let _ = tree_full.set(i, leaves[i]);
            assert_eq!(tree_full.get_empty_leaves_indices(), vec_idxs);
        }

        // Check situation when the number of items to insert is less than the number of items to delete
        tree_full
            .override_range(0, leaves_2.clone(), [0, 1, 2, 3])
            .unwrap();

        // check if the indexes for write and delete are the same
        tree_full
            .override_range(0, leaves_4.clone(), [0, 1, 2, 3])
            .unwrap();
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![]);

        // check if indexes for deletion are before indexes for overwriting
        tree_full
            .override_range(4, leaves_4.clone(), [0, 1, 2, 3])
            .unwrap();
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![0, 1, 2, 3]);

        // check if the indices for write and delete do not overlap completely
        tree_full
            .override_range(2, leaves_4.clone(), [0, 1, 2, 3])
            .unwrap();
        assert_eq!(tree_full.get_empty_leaves_indices(), vec![0, 1]);

        //// Optimal Merkle Tree Trest

        let mut tree_opt = default_optimal_merkle_tree(depth);
        let _ = tree_opt.set_range(0, leaves.clone());
        assert!(tree_opt.get_empty_leaves_indices().is_empty());

        let mut vec_idxs = Vec::new();
        for i in 0..nof_leaves {
            vec_idxs.push(i);
            let _ = tree_opt.delete(i);
            assert_eq!(tree_opt.get_empty_leaves_indices(), vec_idxs);
        }
        for i in (0..nof_leaves).rev() {
            vec_idxs.pop();
            let _ = tree_opt.set(i, leaves[i]);
            assert_eq!(tree_opt.get_empty_leaves_indices(), vec_idxs);
        }

        // Check situation when the number of items to insert is less than the number of items to delete
        tree_opt
            .override_range(0, leaves_2.clone(), [0, 1, 2, 3])
            .unwrap();

        // check if the indexes for write and delete are the same
        tree_opt
            .override_range(0, leaves_4.clone(), [0, 1, 2, 3])
            .unwrap();
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![]);

        // check if indexes for deletion are before indexes for overwriting
        tree_opt
            .override_range(4, leaves_4.clone(), [0, 1, 2, 3])
            .unwrap();
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![0, 1, 2, 3]);

        // check if the indices for write and delete do not overlap completely
        tree_opt
            .override_range(2, leaves_4.clone(), [0, 1, 2, 3])
            .unwrap();
        assert_eq!(tree_opt.get_empty_leaves_indices(), vec![0, 1]);
    }

    #[test]
    fn test_subtree_root() {
        let depth = 3;
        let nof_leaves: usize = 4;
        let leaves: Vec<TestFr> = (0..nof_leaves as u32).map(TestFr::from).collect();

        let mut tree_full = default_optimal_merkle_tree(depth);
        let _ = tree_full.set_range(0, leaves.iter().cloned());

        for i in 0..nof_leaves {
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
                assert_eq!(Keccak256::hash(&[prev_l, prev_r]), subroot);
            }
        }

        let mut tree_opt = default_full_merkle_tree(depth);
        let _ = tree_opt.set_range(0, leaves.iter().cloned());

        for i in 0..nof_leaves {
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
                assert_eq!(Keccak256::hash(&[prev_l, prev_r]), subroot);
            }
        }
    }

    #[test]
    fn test_proof() {
        let nof_leaves = 4;
        let leaves: Vec<TestFr> = (0..nof_leaves as u32).map(TestFr::from).collect();

        // We thest the FullMerkleTree implementation
        let mut tree = default_full_merkle_tree(DEFAULT_DEPTH);
        for i in 0..nof_leaves {
            // We set the leaves
            tree.set(i, leaves[i]).unwrap();

            // We compute a merkle proof
            let proof = tree.proof(i).expect("index should be set");

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree.verify(&leaves[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&leaves[i]), tree.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree.verify(&leaves[(i + 1) % nof_leaves], &proof).unwrap());
        }

        // We test the OptimalMerkleTree implementation
        let mut tree = default_optimal_merkle_tree(DEFAULT_DEPTH);
        for i in 0..nof_leaves {
            // We set the leaves
            tree.set(i, leaves[i]).unwrap();

            // We compute a merkle proof
            let proof = tree.proof(i).expect("index should be set");

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree.verify(&leaves[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&leaves[i]), tree.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree.verify(&leaves[(i + 1) % nof_leaves], &proof).unwrap());
        }
    }

    #[test]
    fn test_override_range() {
        let nof_leaves = 4;
        let leaves: Vec<TestFr> = (0..nof_leaves as u32).map(TestFr::from).collect();

        let mut tree = default_optimal_merkle_tree(DEFAULT_DEPTH);

        // We set the leaves
        tree.set_range(0, leaves.iter().cloned()).unwrap();

        let new_leaves = [
            hex!("0000000000000000000000000000000000000000000000000000000000000005"),
            hex!("0000000000000000000000000000000000000000000000000000000000000006"),
        ]
        .map(TestFr);

        let to_delete_indices: [usize; 2] = [0, 1];

        // We override the leaves
        tree.override_range(
            0, // start from the end of the initial leaves
            new_leaves.iter().cloned(),
            to_delete_indices.iter().cloned(),
        )
        .unwrap();

        // ensure that the leaves are set correctly
        for (i, &new_leaf) in new_leaves.iter().enumerate() {
            assert_eq!(tree.get_leaf(i), new_leaf);
        }
    }
}
