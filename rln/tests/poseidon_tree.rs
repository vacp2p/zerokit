////////////////////////////////////////////////////////////
/// Tests
////////////////////////////////////////////////////////////

#[cfg(test)]
mod test {
    use rln::circuit::*;
    use rln::poseidon_hash::PoseidonHash;
    use utils::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    #[test]
    /// A basic performance comparison between the two supported Merkle Tree implementations
    fn test_zerokit_merkle_implementations_performances() {
        use std::time::{Duration, Instant};

        let tree_height = 20;
        let sample_size = 100;

        let leaves: Vec<Fr> = (0..sample_size).map(|s| Fr::from(s)).collect();

        let mut gen_time_full: u128 = 0;
        let mut upd_time_full: u128 = 0;
        let mut gen_time_opt: u128 = 0;
        let mut upd_time_opt: u128 = 0;

        for _ in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            FullMerkleTree::<PoseidonHash>::default(tree_height).unwrap();
            gen_time_full += now.elapsed().as_nanos();

            let now = Instant::now();
            OptimalMerkleTree::<PoseidonHash>::default(tree_height).unwrap();
            gen_time_opt += now.elapsed().as_nanos();
        }

        let mut tree_full = FullMerkleTree::<PoseidonHash>::default(tree_height).unwrap();
        let mut tree_opt = OptimalMerkleTree::<PoseidonHash>::default(tree_height).unwrap();

        for i in 0..sample_size.try_into().unwrap() {
            let now = Instant::now();
            tree_full.set(i, leaves[i]).unwrap();
            upd_time_full += now.elapsed().as_nanos();
            let proof = tree_full.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);

            let now = Instant::now();
            tree_opt.set(i, leaves[i]).unwrap();
            upd_time_opt += now.elapsed().as_nanos();
            let proof = tree_opt.proof(i).expect("index should be set");
            assert_eq!(proof.leaf_index(), i);
        }

        // We check all roots are the same
        let tree_full_root = tree_full.root();
        let tree_opt_root = tree_opt.root();

        assert_eq!(tree_full_root, tree_opt_root);

        println!(" Average tree generation time:");
        println!(
            "   - Full Merkle Tree:  {:?}",
            Duration::from_nanos((gen_time_full / sample_size).try_into().unwrap())
        );
        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((gen_time_opt / sample_size).try_into().unwrap())
        );

        println!(" Average update_next execution time:");
        println!(
            "   - Full Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_full / sample_size).try_into().unwrap())
        );

        println!(
            "   - Optimal Merkle Tree: {:?}",
            Duration::from_nanos((upd_time_opt / sample_size).try_into().unwrap())
        );
    }
}
