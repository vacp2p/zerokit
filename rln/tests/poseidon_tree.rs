////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use ark_ff::BigInt;
    use rln::hashers::PoseidonHash;
    use rln::{circuit::*, poseidon_tree::PoseidonTree};
    use std::collections::HashMap;
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

        let mut subtree_roots: HashMap<usize, Vec<BigInt<4>>> = HashMap::new();
        subtree_roots.insert(
            2,
            [
                BigInt([
                    8484649501445056094,
                    3908152073421837165,
                    14286393878319244193,
                    2004673807689619504,
                ]),
                BigInt([
                    8830935856278480119,
                    15903149851875271883,
                    6626214561898135521,
                    2739766119240381910,
                ]),
                BigInt([
                    16430608495275532835,
                    13648500920641681703,
                    2165397591442825021,
                    120532066163678629,
                ]),
                BigInt([
                    12121982123933845604,
                    15866503461060138275,
                    4389536233047581825,
                    2348897666712444587,
                ]),
            ]
            .to_vec(),
        );
        subtree_roots.insert(
            1,
            [
                BigInt([
                    11064476273128479404,
                    16304821460789921715,
                    8057432273803804138,
                    592728429436362662,
                ]),
                BigInt([
                    2175616416494454055,
                    4954579124750694725,
                    6762808005233931012,
                    1618934653165663716,
                ]),
            ]
            .to_vec(),
        );

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

        for n in 1..DEPTH {
            for i in 0..LEAVES_LEN {
                let subroot = tree.get_subtree_root(n, i).unwrap();
                // check intermediate nodes
                assert_eq!(subroot, subtree_roots[&n][i >> (DEPTH - n)].into());
            }
        }
    }
}
