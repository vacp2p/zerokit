use rln::prelude::{Fr, Hasher, PoseidonHash, RLNMerkleProof};
use zerokit_utils::merkle_tree::{FullMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

struct BooleanPathProof;

impl ZerokitMerkleProof for BooleanPathProof {
    type Index = bool;
    type Hasher = PoseidonHash;

    fn length(&self) -> usize {
        1
    }

    fn leaf_index(&self) -> usize {
        1
    }

    fn get_path_elements(&self) -> Vec<Fr> {
        vec![Fr::from(3)]
    }

    fn get_path_index(&self) -> Vec<bool> {
        vec![true]
    }

    fn compute_root_from(&self, leaf: &Fr) -> Fr {
        Hasher::<PoseidonHash>::hash_pair(Fr::from(3), *leaf)
    }
}

struct ConversionProbe<P>(P);

trait CanonicalConversion {
    fn convert(self) -> Option<RLNMerkleProof>;
}

// Method lookup falls back to this receiver when the From bound is absent.
impl<P> CanonicalConversion for &ConversionProbe<P> {
    fn convert(self) -> Option<RLNMerkleProof> {
        None
    }
}

impl<P> CanonicalConversion for &&ConversionProbe<P>
where
    for<'a> RLNMerkleProof: From<&'a P>,
{
    fn convert(self) -> Option<RLNMerkleProof> {
        Some(RLNMerkleProof::from(&self.0))
    }
}

#[test]
fn test_canonical_merkle_proof_accepts_boolean_directions() {
    let tree = FullMerkleTree::<PoseidonHash>::default(1).unwrap();
    let built_in = ConversionProbe(tree.proof(1).unwrap());
    let built_in = (&&built_in).convert().expect("built-in proof must convert");
    assert_eq!(built_in.identity_path_index(), &[1]);

    let probe = ConversionProbe(BooleanPathProof);
    let fallback_receiver = &probe;
    let preferred_receiver = &fallback_receiver;
    let canonical = preferred_receiver
        .convert()
        .expect("blanket conversion is missing for a valid boolean-direction proof");
    assert_eq!(canonical.path_elements(), &[Fr::from(3)]);
    assert_eq!(canonical.identity_path_index(), &[1]);
}
