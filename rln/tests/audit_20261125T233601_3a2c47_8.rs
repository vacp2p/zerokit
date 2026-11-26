// Finding 20261125T233601-3a2c47/8
// Spec (Key Generation): "The returned key types are the same for both hashes; only the
// commitment value differs." and "the same secret yields a different commitment under each
// hash".
use rand_chacha::ChaCha20Rng;
use rln::prelude::*;

#[test]
fn seeded_extended_keys_differ_only_in_the_commitment_across_hashes() {
    let seed = b"extended identity test fixture";

    // Control: for the plain keypair the sentence holds.
    let k1 = IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed);
    let k2 = IdentityKeys::generate_seeded::<Poseidon2Hash, ChaCha20Rng>(seed);
    assert!(k1.identity_secret() == k2.identity_secret(), "control");
    assert_ne!(k1.id_commitment(), k2.id_commitment(), "control");

    let poseidon = ExtendedIdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed);
    let poseidon2 = ExtendedIdentityKeys::generate_seeded::<Poseidon2Hash, ChaCha20Rng>(seed);
    assert!(poseidon.identity_trapdoor() == poseidon2.identity_trapdoor());
    assert!(poseidon.identity_nullifier() == poseidon2.identity_nullifier());
    assert_ne!(poseidon.id_commitment(), poseidon2.id_commitment());
    assert!(
        poseidon.identity_secret() == poseidon2.identity_secret(),
        "only the commitment value may differ across hashes, but the extended identity_secret \
         differs too"
    );
}
