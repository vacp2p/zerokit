use crate::error::ProtocolError;

/// Size in bytes of the version prefix.
pub const VERSION_BYTE_SIZE: usize = 1;

/// Wire-format version tag for serialized RLN structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SerializationVersion {
    /// Original single message-id format (RLN v2).
    ///
    /// RLNWitnessInput:
    /// `[ 0x00 | identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<var> | identity_path_index<32> | x<32> | external_nullifier<32> ]`
    ///
    /// RLNProofValues:
    /// `[ 0x00 | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]`
    ///
    /// RLNProof:
    /// `[ 0x00 | proof<128> | RLNProofValues(0x00) ]`
    ///
    /// Encoding conventions:
    /// - `<32>`  = canonical 32-byte encoding of [`ark_bn254::Fr`](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/bn254/src/fields/fr.rs#L9).
    /// - `<var>` = length-prefixed list of `Fr`, except `identity_path_index`, which is a length-prefixed `Vec<u8>`.
    /// - `proof<128>` is an
    ///   [`ark_groth16::Proof`](https://github.com/arkworks-rs/groth16/blob/9ba21ceab723d6b515a813e17846a0c0ec830c0d/src/data_structures.rs#L9)
    ///   instantiated over
    ///   [`ark_bn254::Bn254`](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/bn254/src/curves/mod.rs#L44),
    ///   serialized into a fixed 128-byte canonical form in little-endian format (arkworks behavior).
    ///
    /// Spec: <https://lip.logos.co/ift-ts/raw/rln-v2>
    #[cfg(not(feature = "multi-message-id"))]
    SingleV1 = 0x00,

    /// Multi message-id format (RLN v2 extension).
    ///
    /// RLNWitnessInput:
    /// `[ 0x01 | identity_secret<32> | user_message_limit<32> | path_elements<var> | identity_path_index<32> | x<32> | external_nullifier<32> | message_ids<var> | selector_used<var> ]`
    ///
    /// RLNProofValues:
    /// `[ 0x01 | root<32> | external_nullifier<32> | x<32> | ys<var> | nullifiers<var> | selector_used<var> ]`
    ///
    /// RLNProof:
    /// `[ 0x01 | proof<128> | RLNProofValues(0x01) ]`
    ///
    /// Encoding conventions:
    /// - `<32>`  = canonical 32-byte encoding of [`ark_bn254::Fr`](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/bn254/src/fields/fr.rs#L9).
    /// - `<var>` = length-prefixed list of `Fr`, except `identity_path_index`, which is a length-prefixed `Vec<u8>`.
    /// - `proof<128>` is an
    ///   [`ark_groth16::Proof`](https://github.com/arkworks-rs/groth16/blob/9ba21ceab723d6b515a813e17846a0c0ec830c0d/src/data_structures.rs#L9)
    ///   instantiated over
    ///   [`ark_bn254::Bn254`](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/bn254/src/curves/mod.rs#L44),
    ///   serialized into a fixed 128-byte canonical form in little-endian format (arkworks behavior).
    ///
    /// Spec: <https://lip.logos.co/ift-ts/raw/multi-message_id-burn-rln>
    #[cfg(feature = "multi-message-id")]
    MultiV1 = 0x01,
}

impl From<SerializationVersion> for u8 {
    #[inline]
    fn from(v: SerializationVersion) -> u8 {
        v as u8
    }
}

impl TryFrom<u8> for SerializationVersion {
    type Error = ProtocolError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            #[cfg(not(feature = "multi-message-id"))]
            0x00 => Ok(Self::SingleV1),
            #[cfg(feature = "multi-message-id")]
            0x01 => Ok(Self::MultiV1),
            other => Err(ProtocolError::UnknownSerializationVersion(other)),
        }
    }
}
