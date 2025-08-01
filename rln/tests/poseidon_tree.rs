////////////////////////////////////////////////////////////
// Tests
////////////////////////////////////////////////////////////

#![cfg(not(feature = "stateless"))]

#[cfg(test)]
mod test {
    use rln::hashers::{poseidon_hash, PoseidonHash};
    use rln::{
        circuit::{Fr, TEST_TREE_HEIGHT},
        poseidon_tree::PoseidonTree,
    };
    use utils::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    #[test]
    // The test checked correctness for `FullMerkleTree` and `OptimalMerkleTree` with Poseidon hash
    fn test_zerokit_merkle_implementations() {
        let sample_size = 100;
        let leaves: Vec<Fr> = (0..sample_size).map(Fr::from).collect();

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();

        for (i, leave) in leaves
            .into_iter()
            .enumerate()
            .take(sample_size.try_into().unwrap())
        {
            tree_full.set(i, leave).unwrap();
            let proof = tree_full.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            tree_opt.set(i, leave).unwrap();
            assert_eq!(tree_opt.root(), tree_full.root());
            let proof = tree_opt.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);
        }

        // We check all roots are the same
        let tree_full_root = tree_full.root();
        let tree_opt_root = tree_opt.root();

        assert_eq!(tree_full_root, tree_opt_root);
    }

    #[test]
    fn test_subtree_root() {
        const DEPTH: usize = 3;
        const LEAVES_LEN: usize = 8;

        let mut tree = PoseidonTree::default(DEPTH).unwrap();
        let leaves: Vec<Fr> = (0..LEAVES_LEN).map(|s| Fr::from(s as i32)).collect();
        let _ = tree.set_range(0, leaves.into_iter());

        for i in 0..LEAVES_LEN {
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

                assert_eq!(poseidon_hash(&[prev_l, prev_r]), subroot);
            }
        }
    }

    #[test]
    fn test_get_empty_leaves_indices() {
        let depth = 4;
        let nof_leaves: usize = 1 << (depth - 1);

        let mut tree = PoseidonTree::default(depth).unwrap();
        let leaves: Vec<Fr> = (0..nof_leaves).map(|s| Fr::from(s as i32)).collect();

        // check set_range
        let _ = tree.set_range(0, leaves.clone().into_iter());
        assert!(tree.get_empty_leaves_indices().is_empty());

        let mut vec_idxs = Vec::new();
        // check delete function
        for i in 0..nof_leaves {
            vec_idxs.push(i);
            let _ = tree.delete(i);
            assert_eq!(tree.get_empty_leaves_indices(), vec_idxs);
        }
        // check set function
        for i in (0..nof_leaves).rev() {
            vec_idxs.pop();
            let _ = tree.set(i, leaves[i]);
            assert_eq!(tree.get_empty_leaves_indices(), vec_idxs);
        }

        // check remove_indices_and_set_leaves inside override_range function
        assert!(tree.get_empty_leaves_indices().is_empty());
        let leaves_2: Vec<Fr> = (0..2).map(Fr::from).collect();
        tree.override_range(0, leaves_2.clone().into_iter(), [0, 1, 2, 3].into_iter())
            .unwrap();
        assert_eq!(tree.get_empty_leaves_indices(), vec![2, 3]);

        // check remove_indices inside override_range function
        tree.override_range(0, [].into_iter(), [0, 1].into_iter())
            .unwrap();
        assert_eq!(tree.get_empty_leaves_indices(), vec![0, 1, 2, 3]);

        // check set_range inside override_range function
        tree.override_range(0, leaves_2.clone().into_iter(), [].into_iter())
            .unwrap();
        assert_eq!(tree.get_empty_leaves_indices(), vec![2, 3]);

        let leaves_4: Vec<Fr> = (0..4).map(Fr::from).collect();
        // check if the indexes for write and delete are the same
        tree.override_range(0, leaves_4.clone().into_iter(), [0, 1, 2, 3].into_iter())
            .unwrap();
        assert!(tree.get_empty_leaves_indices().is_empty());

        // check if indexes for deletion are before indexes for overwriting
        tree.override_range(4, leaves_4.clone().into_iter(), [0, 1, 2, 3].into_iter())
            .unwrap();
        // The result will be like this, because in the set_range function in pmtree
        // the next_index value is increased not by the number of elements to insert,
        // but by the union of indices for deleting and inserting.
        assert_eq!(
            tree.get_empty_leaves_indices(),
            vec![0, 1, 2, 3, 8, 9, 10, 11]
        );

        // check if the indices for write and delete do not overlap completely
        tree.override_range(2, leaves_4.clone().into_iter(), [0, 1, 2, 3].into_iter())
            .unwrap();
        // The result will be like this, because in the set_range function in pmtree
        // the next_index value is increased not by the number of elements to insert,
        // but by the union of indices for deleting and inserting.
        // + we've already set to 6 and 7 in previous test
        assert_eq!(tree.get_empty_leaves_indices(), vec![0, 1, 8, 9, 10, 11]);
    }
}
