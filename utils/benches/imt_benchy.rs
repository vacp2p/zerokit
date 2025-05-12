use light_poseidon::{PoseidonBytesHasher, PoseidonHasher};
use rln::{circuit::Fr, utils::fr_to_bytes_le};
use zerokit_utils::Poseidon;
use zk_kit_lean_imt::{hashed_tree::{HashedLeanIMT, LeanIMTHasher}, lean_imt::*};


const ROUND_PARAMS: [(usize, usize, usize, usize); 8] = [
    (2, 8, 56, 0),
    (3, 8, 57, 0),
    (4, 8, 56, 0),
    (5, 8, 60, 0),
    (6, 8, 60, 0),
    (7, 8, 63, 0),
    (8, 8, 64, 0),
    (9, 8, 63, 0),
];


struct BenchyIFTHasher;
struct BenchyLightPosHasher;

impl<const N: usize> LeanIMTHasher<N> for BenchyIFTHasher {
    fn hash(input: &[u8]) -> [u8; N] {
        let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
        let input_as_frs: Vec<_> = input.chunks(N).map(|ch| rln::utils::bytes_le_to_fr(ch).0).collect();
        let res = hasher.hash(&input_as_frs).unwrap();
        let byte_vec: Vec<u8> = fr_to_bytes_le(&res);
        let mut res = [0; N];
        if byte_vec.len() >= N {
            res.copy_from_slice(&byte_vec[..N]);
        } else {
            res.copy_from_slice(&byte_vec);
        };
        res
    }
}
impl LeanIMTHasher<32> for BenchyLightPosHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let mut hasher = light_poseidon::Poseidon::<Fr>::new_circom(1).unwrap();
        let chunks: Vec< &[u8] > = input.chunks(32).collect();
        hasher.hash_bytes_le(&chunks).unwrap()
    }
}
fn benchy_prototype_code() {
    let mut tree = HashedLeanIMT::<32, BenchyIFTHasher>::new(&[], BenchyIFTHasher).unwrap();
    tree.insert(&[1; 32]);
    tree.insert(&[2; 32]);
    tree.insert_many(&[[4; 32], [4; 32], [5; 32]]).unwrap();

    println!("Tree root: {:?}", tree.root().unwrap());
    println!("Tree depth: {}", tree.depth());

    let proof = tree.generate_proof(3).unwrap();
    assert!(HashedLeanIMT::<32, BenchyIFTHasher>::verify_proof(&proof));
}
