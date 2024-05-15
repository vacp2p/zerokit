// Tests adapted from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
#[cfg(test)]
pub mod test {
    use hex_literal::hex;
    use lazy_static::lazy_static;
    use std::{collections::HashMap, fmt::Display, str::FromStr};
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

    lazy_static! {
        static ref LEAVES_D2: [TestFr; 4] = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        ]
        .map(TestFr);
        static ref LEAVES_D3: [TestFr; 6] = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
            hex!("0000000000000000000000000000000000000000000000000000000000000005"),
            hex!("0000000000000000000000000000000000000000000000000000000000000006"),
        ]
        .map(TestFr);
    }
    const DEPTH_2: usize = 2;
    const DEPTH_3: usize = 3;

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

        let mut tree = default_full_merkle_tree(DEPTH_2);
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..LEAVES_D2.len() {
            tree.set(i, LEAVES_D2[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }

        let mut tree = default_optimal_merkle_tree(DEPTH_2);
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..LEAVES_D2.len() {
            tree.set(i, LEAVES_D2[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }
    }

    #[test]
    fn test_subtree_root() {
        let mut subtree_roots: HashMap<usize, Vec<TestFr>> = HashMap::new();
        subtree_roots.insert(
            2,
            [
                hex!("e90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0"),
                hex!("2e174c10e159ea99b867ce3205125c24a42d128804e4070ed6fcc8cc98166aa0"),
                hex!("bfd358e93f18da3ed276c3afdbdba00b8f0b6008a03476a6a86bd6320ee6938b"),
                hex!("ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"),
            ]
            .map(TestFr)
            .to_vec(),
        );
        subtree_roots.insert(
            1,
            [
                hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36"),
                hex!("f00594ffc06155c440df3fabd328625cf94342eaed0ecb4fcdd05f54e942a4cf"),
            ]
            .map(TestFr)
            .to_vec(),
        );

        let mut tree_full = default_optimal_merkle_tree(DEPTH_3);
        let _ = tree_full.set_range(0, LEAVES_D3.iter().cloned());

        let mut tree_opt = default_full_merkle_tree(DEPTH_3);
        let _ = tree_opt.set_range(0, LEAVES_D3.iter().cloned());

        for i in 0..LEAVES_D3.len() {
            // check leaves
            assert_eq!(
                tree_full.get(i).unwrap(),
                tree_full.get_subtree_root(DEPTH_3, i).unwrap()
            );
            assert_eq!(
                tree_opt.get(i).unwrap(),
                tree_opt.get_subtree_root(DEPTH_3, i).unwrap()
            );
            // check root
            assert_eq!(tree_full.root(), tree_full.get_subtree_root(0, i).unwrap());
            assert_eq!(tree_opt.root(), tree_opt.get_subtree_root(0, i).unwrap());
        }

        // check intermediate nodes
        for n in 1..DEPTH_3 {
            for i in 0..LEAVES_D3.len() {
                let subroot_full = tree_full.get_subtree_root(n, i).unwrap();
                let subroot_opt = tree_opt.get_subtree_root(n, i).unwrap();
                assert_eq!(subroot_full, subroot_opt);
                assert_eq!(subroot_full, subtree_roots[&n][i >> (DEPTH_3 - n)]);
            }
        }
    }

    #[test]
    fn test_proof() {
        // We thest the FullMerkleTree implementation
        let mut tree = default_full_merkle_tree(DEPTH_2);
        for i in 0..LEAVES_D2.len() {
            // We set the leaves
            tree.set(i, LEAVES_D2[i]).unwrap();

            // We compute a merkle proof
            let proof = tree.proof(i).expect("index should be set");

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree.verify(&LEAVES_D2[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&LEAVES_D2[i]), tree.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree
                .verify(&LEAVES_D2[(i + 1) % LEAVES_D2.len()], &proof)
                .unwrap());
        }

        // We test the OptimalMerkleTree implementation
        let mut tree = default_optimal_merkle_tree(DEPTH_2);
        for i in 0..LEAVES_D2.len() {
            // We set the leaves
            tree.set(i, LEAVES_D2[i]).unwrap();

            // We compute a merkle proof
            let proof = tree.proof(i).expect("index should be set");

            // We verify if the merkle proof corresponds to the right leaf index
            assert_eq!(proof.leaf_index(), i);

            // We verify the proof
            assert!(tree.verify(&LEAVES_D2[i], &proof).unwrap());

            // We ensure that the Merkle proof and the leaf generate the same root as the tree
            assert_eq!(proof.compute_root_from(&LEAVES_D2[i]), tree.root());

            // We check that the proof is not valid for another leaf
            assert!(!tree
                .verify(&LEAVES_D2[(i + 1) % LEAVES_D2.len()], &proof)
                .unwrap());
        }
    }

    #[test]
    fn test_override_range() {
        let mut tree = default_optimal_merkle_tree(DEPTH_2);

        // We set the leaves
        tree.set_range(0, LEAVES_D2.iter().cloned()).unwrap();

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
