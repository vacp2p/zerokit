// Finding 20261125T233601-3a2c47/9
// Spec (Security/Privacy Considerations): "Zerokit handles secrets defensively in-process:
// all secret field elements are carried as `SecretFr`, which zeroizes its memory on drop".
//
// The test installs a probing allocator that, while armed, inspects every heap block at the
// moment it is freed and records the blocks that still hold the identity secret's in-memory
// representation. A secret carried only as `SecretFr` (or wiped before release) leaves none.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use rand::thread_rng;
use rln::prelude::*;

const FR_SIZE: usize = 32;
const MAX_RECORDED: usize = 8;

static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static HIT_SIZES: [AtomicUsize; MAX_RECORDED] = [const { AtomicUsize::new(0) }; MAX_RECORDED];
static mut NEEDLE: [u8; FR_SIZE] = [0u8; FR_SIZE];

struct Probe;

unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::Relaxed) && layout.size() >= FR_SIZE {
            let block = std::slice::from_raw_parts(ptr, layout.size());
            let needle = &*std::ptr::addr_of!(NEEDLE);
            // Field elements are 8-byte aligned inside any buffer that holds them.
            let mut off = 0;
            while off + FR_SIZE <= block.len() {
                if &block[off..off + FR_SIZE] == needle {
                    let n = HITS.fetch_add(1, Ordering::Relaxed);
                    if n < MAX_RECORDED {
                        HIT_SIZES[n].store(layout.size(), Ordering::Relaxed);
                    }
                    break;
                }
                off += 8;
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static GLOBAL: Probe = Probe;

/// Runs `f` with the probe armed; returns its output and the sizes of the freed blocks that
/// still contained the secret.
fn observe<T>(f: impl FnOnce() -> T) -> (T, Vec<usize>) {
    HITS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let out = f();
    ARMED.store(false, Ordering::SeqCst);
    let n = HITS.load(Ordering::SeqCst).min(MAX_RECORDED);
    let sizes = HIT_SIZES[..n]
        .iter()
        .map(|s| s.load(Ordering::SeqCst))
        .collect();
    (out, sizes)
}

#[test]
fn proof_generation_frees_no_heap_block_still_holding_the_identity_secret() {
    assert_eq!(std::mem::size_of::<Fr>(), FR_SIZE);

    let rln = RLNBuilder::stateless().build();
    let secret = SecretFr::rand(&mut thread_rng());
    // The in-memory (Montgomery) representation of the secret field element.
    unsafe {
        let raw: [u8; FR_SIZE] = std::mem::transmute::<Fr, [u8; FR_SIZE]>(*secret);
        *std::ptr::addr_of_mut!(NEEDLE) = raw;
    }

    // Control: a heap-allocated `SecretFr` is wiped before its block is released.
    let boxed = Box::new(secret.clone());
    let ((), control) = observe(move || drop(boxed));
    assert!(control.is_empty(), "control: SecretFr zeroizes before free");

    let witness = RLNWitnessInput::new_single()
        .identity_secret(secret)
        .user_message_limit(Fr::from(10u64))
        .merkle_proof(RLNMerkleProof::new(
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            vec![0u8; DEFAULT_TREE_DEPTH],
        ))
        .x(Fr::from(7u64))
        .external_nullifier(Fr::from(9u64))
        .message_id(Fr::from(3u64))
        .build()
        .unwrap();

    // Size of the full circuit assignment (`Vec<Fr>`, one element per wire) that
    // `generate_proof` owns and drops.
    let matrices = &default_zkey_single().1;
    let assignment_bytes =
        (matrices.num_instance_variables + matrices.num_witness_variables) * FR_SIZE;

    let (result, sizes) = observe(|| rln.generate_proof(&witness));
    result.unwrap();
    assert!(
        sizes.is_empty(),
        "generate_proof freed heap blocks that still held the plaintext identity secret \
         (block sizes in bytes: {sizes:?}; the full witness assignment is {assignment_bytes} \
         bytes): the secret was carried as a plain Fr and released without being zeroized"
    );
}
