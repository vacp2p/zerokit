// Finding 20261125T233601-3a2c47/11
// Spec (Serialization): "Usage is uniform across types; endianness is chosen by the trait used"
// and the LE / BE trait pairs are described as differing in byte order only.
//
// For the Single witness the two encodings also differ in FIELD ORDER: the LE layout ends with
// `message_id`, the BE layout carries it third (right after `user_message_limit`).
use rand::thread_rng;
use rln::prelude::*;

fn le(fr: Fr) -> Vec<u8> {
    let mut out = Vec::new();
    fr.serialize_compressed(&mut out).unwrap();
    out
}

fn be(fr: Fr) -> Vec<u8> {
    let mut out = Vec::new();
    CanonicalSerializeBE::serialize(&fr, &mut out).unwrap();
    out
}

/// Byte offset of the 32-byte encoding `needle` inside `buf`.
fn offset(buf: &[u8], needle: &[u8]) -> usize {
    buf.windows(needle.len())
        .position(|w| w == needle)
        .expect("field is present in the encoding")
}

fn merkle_proof() -> RLNMerkleProof {
    RLNMerkleProof::new(
        vec![Fr::from(0xA1A1u64), Fr::from(0xA2A2u64)],
        vec![0u8, 1u8],
    )
}

#[test]
fn le_and_be_witness_layouts_differ_only_in_endianness() {
    let limit = Fr::from(0xBBBB_0001u64);
    let x = Fr::from(0xCCCC_0002u64);
    let ext = Fr::from(0xDDDD_0003u64);
    let id = Fr::from(0xEE04u64);
    let id2 = Fr::from(0xEE05u64);

    // Control: the Multi witness has the same field offsets in both encodings.
    let multi = RLNWitnessInput::new_multi()
        .identity_secret(SecretFr::rand(&mut thread_rng()))
        .user_message_limit(limit)
        .merkle_proof(merkle_proof())
        .x(x)
        .external_nullifier(ext)
        .message_ids(vec![id, id2])
        .selector_used(vec![true, true])
        .build()
        .unwrap();
    let (mut m_le, mut m_be) = (Vec::new(), Vec::new());
    multi.serialize_compressed(&mut m_le).unwrap();
    CanonicalSerializeBE::serialize(&multi, &mut m_be).unwrap();
    assert_eq!(m_le.len(), m_be.len(), "control: Multi sizes match");
    let multi_fields = [
        ("limit", limit),
        ("x", x),
        ("ext", ext),
        ("id", id),
        ("id2", id2),
    ];
    for (name, f) in multi_fields {
        assert_eq!(
            offset(&m_le, &le(f)),
            offset(&m_be, &be(f)),
            "control: Multi field `{name}` sits at the same offset in LE and BE"
        );
    }

    let single = RLNWitnessInput::new_single()
        .identity_secret(SecretFr::rand(&mut thread_rng()))
        .user_message_limit(limit)
        .merkle_proof(merkle_proof())
        .x(x)
        .external_nullifier(ext)
        .message_id(id)
        .build()
        .unwrap();
    let (mut s_le, mut s_be) = (Vec::new(), Vec::new());
    single.serialize_compressed(&mut s_le).unwrap();
    CanonicalSerializeBE::serialize(&single, &mut s_be).unwrap();
    assert_eq!(s_le.len(), s_be.len(), "control: Single sizes match");

    let single_fields = [
        ("limit", limit),
        ("x", x),
        ("ext", ext),
        ("message_id", id),
    ];
    let le_layout = single_fields.map(|(name, f)| (name, offset(&s_le, &le(f))));
    let be_layout = single_fields.map(|(name, f)| (name, offset(&s_be, &be(f))));
    assert_eq!(
        le_layout, be_layout,
        "the Single witness LE and BE encodings place their fields at different offsets: the \
         two traits differ in field order, not only in endianness"
    );
}
