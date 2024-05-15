////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use rln::hashers::{poseidon_hash, PoseidonHash};
    use rln::{circuit::*, poseidon_tree::PoseidonTree};
    use utils::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    #[test]
    // The test is checked correctness for `FullMerkleTree` and `OptimalMerkleTree` with Poseidon hash
    fn test_zerokit_merkle_implementations() {
        let sample_size = 100;
        let leaves: Vec<Fr> = (0..sample_size).map(|s| Fr::from(s)).collect();

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(TEST_TREE_HEIGHT).unwrap();

        for i in 0..sample_size.try_into().unwrap() {
            tree_full.set(i, leaves[i]).unwrap();
            let proof = tree_full.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            tree_opt.set(i, leaves[i]).unwrap();
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
        const LEAVES_LEN: usize = 6;

        let mut tree = PoseidonTree::default(DEPTH).unwrap();
        let leaves: Vec<Fr> = (0..LEAVES_LEN).map(|s| Fr::from(s as i32)).collect();
        let _ = tree.set_range(0, leaves);

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
}
