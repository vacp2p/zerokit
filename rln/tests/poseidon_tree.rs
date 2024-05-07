////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use rln::circuit::*;
    use rln::hashers::PoseidonHash;
    use utils::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    #[test]
    /// The test is checked correctness for `FullMerkleTree` and `OptimalMerkleTree`
    fn test_zerokit_merkle_implementations() {
        let tree_height = TEST_TREE_HEIGHT;
        let sample_size = 100;

        let leaves: Vec<Fr> = (0..sample_size).map(|s| Fr::from(s)).collect();

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(tree_height).unwrap();
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(tree_height).unwrap();

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
}
