// Tests adapted from https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/merkle_tree.rs
#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use hex_literal::hex;
    use tiny_keccak::{Hasher as _, Keccak};
    use zerokit_utils::{
        FullMerkleConfig, FullMerkleTree, Hasher, OptimalMerkleConfig, OptimalMerkleTree,
        ZerokitMerkleProof, ZerokitMerkleTree, BatchOf,
    };
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Keccak256;

    impl Hasher for Keccak256 {
        type Fr = [u8; 32];

        fn default_leaf() -> Self::Fr {
            [0; 32]
        }

        fn hash(inputs: &[Self::Fr]) -> Self::Fr {
            let mut output = [0; 32];
            let mut hasher = Keccak::v256();
            for element in inputs {
                hasher.update(element);
            }
            hasher.finalize(&mut output);
            output
        }
    }

    #[test]
    fn test_root() {
        let leaves = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        ];

        let default_tree_root =
            hex!("b4c11951957c6f8f642c4af61cd6b24640fec6dc7fc607ee8206a99e92410d30");

        let roots = [
            hex!("c1ba1812ff680ce84c1d5b4f1087eeb08147a4d510f3496b2849df3a73f5af95"),
            hex!("893760ec5b5bee236f29e85aef64f17139c3c1b7ff24ce64eb6315fca0f2485b"),
            hex!("222ff5e0b5877792c2bc1670e2ccd0c2c97cd7bb1672a57d598db05092d3d72c"),
            hex!("a9bb8c3f1f12e9aa903a50c47f314b57610a3ab32f2d463293f58836def38d36"),
        ];

        let mut tree =
            FullMerkleTree::<Keccak256>::new(2, [0; 32], FullMerkleConfig::default()).unwrap();
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..leaves.len() {
            tree.set(i, leaves[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }

        let mut tree =
            OptimalMerkleTree::<Keccak256>::new(2, [0; 32], OptimalMerkleConfig::default())
                .unwrap();
        assert_eq!(tree.root(), default_tree_root);
        for i in 0..leaves.len() {
            tree.set(i, leaves[i]).unwrap();
            assert_eq!(tree.root(), roots[i]);
        }
    }

    #[test]
    fn test_proof() {
        let leaves = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        ];

        // We thest the FullMerkleTree implementation
        let mut tree =
            FullMerkleTree::<Keccak256>::new(2, [0; 32], FullMerkleConfig::default()).unwrap();
        for i in 0..leaves.len() {
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
            assert!(!tree
                .verify(&leaves[(i + 1) % leaves.len()], &proof)
                .unwrap());
        }

        // We test the OptimalMerkleTree implementation
        let mut tree =
            OptimalMerkleTree::<Keccak256>::new(2, [0; 32], OptimalMerkleConfig::default())
                .unwrap();
        for i in 0..leaves.len() {
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
            assert!(!tree
                .verify(&leaves[(i + 1) % leaves.len()], &proof)
                .unwrap());
        }
    }

    #[test]
    fn test_override_range() {
        let initial_leaves = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
            hex!("0000000000000000000000000000000000000000000000000000000000000004"),
        ];

        let mut tree =
            OptimalMerkleTree::<Keccak256>::new(2, [0; 32], OptimalMerkleConfig::default())
                .unwrap();

        // We set the leaves in a batch
        // Batch = Hashmap<index, leaf>
        let batch = initial_leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| (i, *leaf))
            .collect::<HashMap<_, _>>();
        tree.set_range(&batch).unwrap();

        let mut new_batch = BatchOf::<OptimalMerkleTree<Keccak256>>::new();
        new_batch.remove(&0);
        new_batch.remove(&1);
        new_batch.insert(tree.leaves_set() - 2, hex!("0000000000000000000000000000000000000000000000000000000000000005"));
        new_batch.insert(tree.leaves_set() - 1, hex!("0000000000000000000000000000000000000000000000000000000000000006"));

        // We override the leaves
        tree.set_range(&new_batch).unwrap();

        // ensure that the leaves are set correctly
        for (i, leaf) in new_batch {
            assert_eq!(tree.get_leaf(i), leaf);
        }
    }
}
