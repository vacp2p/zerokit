// Proof for finding 20261125T042849-bc16c5/3.
//
// Spec (Type-Level Configuration / Parallelization):
//   "`parallel` (`rln`, `zerokit_utils`, `rln-wasm`) enables rayon-based parallel computation
//    for proof generation and tree operations."
//   "For server-side proof services handling multiple concurrent requests, this flag SHOULD be
//    disabled and applications SHOULD use dedicated worker threads per proof instead."
//
// `FullMerkleTree` and `OptimalMerkleTree` call rayon's `into_par_iter` unconditionally: with
// the `parallel` feature OFF, a batch tree operation still hashes on rayon's global pool.
//
// Run WITHOUT the feature: `cargo test --release -p zerokit_utils --test bork_20261125T042849_bc16c5_3`

use std::{
    collections::HashSet,
    sync::Mutex,
    thread::{self, ThreadId},
};

use zerokit_utils::merkle_tree::{
    FullMerkleTree, OptimalMerkleTree, ZerokitHasher, ZerokitMerkleTree,
};

static HASH_THREADS: Mutex<Option<HashSet<ThreadId>>> = Mutex::new(None);

/// A hasher that records the thread every hash is computed on.
#[derive(Clone, Copy, PartialEq)]
struct RecordingHash;

impl ZerokitHasher for RecordingHash {
    type Scalar = u64;

    fn hash(input: &[Self::Scalar]) -> Self::Scalar {
        if let Some(set) = HASH_THREADS.lock().unwrap().as_mut() {
            set.insert(thread::current().id());
        }
        input
            .iter()
            .fold(0xcbf29ce484222325u64, |acc, v| {
                (acc ^ v).wrapping_mul(0x100000001b3)
            })
    }
}

fn foreign_hash_threads(run: impl FnOnce()) -> usize {
    *HASH_THREADS.lock().unwrap() = Some(HashSet::new());
    run();
    let threads = HASH_THREADS.lock().unwrap().take().unwrap();
    assert!(!threads.is_empty(), "the tree operation hashed nothing");
    let me = thread::current().id();
    threads.iter().filter(|id| **id != me).count()
}

#[test]
fn tree_operations_stay_on_caller_thread_without_parallel_feature() {
    if cfg!(feature = "parallel") {
        // With the flag on, rayon is the documented behaviour: nothing to prove.
        return;
    }

    let leaves: Vec<u64> = (1..=256).collect();

    let mut full = FullMerkleTree::<RecordingHash>::default(10).unwrap();
    let full_foreign =
        foreign_hash_threads(|| full.set_range(0, leaves.clone().into_iter()).unwrap());

    let mut optimal = OptimalMerkleTree::<RecordingHash>::default(10).unwrap();
    let optimal_foreign =
        foreign_hash_threads(|| optimal.set_range(0, leaves.clone().into_iter()).unwrap());

    assert_eq!(
        (full_foreign, optimal_foreign),
        (0, 0),
        "`parallel` feature is disabled, yet set_range hashed on {full_foreign} (FullMerkleTree) \
         and {optimal_foreign} (OptimalMerkleTree) threads other than the caller: rayon is used \
         regardless of the flag"
    );
}
