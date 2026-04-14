use std::fmt;

#[cfg(not(target_arch = "wasm32"))]
use crate::circuit::Graph;
use crate::{error::ProtocolError, protocol::witness::RLNMessageInputs};

/// Size in bytes of the version prefix prepended to every serialized RLN structure.
pub const VERSION_BYTE_SIZE: usize = 1;

/// Wire-format version and runtime message mode for RLN protocol types.
///
/// Each variant encodes both the **wire byte** written at the start of every serialized
/// RLN structure and the **runtime behaviour** (how many message-id slots exist per proof).
///
/// ### Wire layout
///
/// Every serialized type starts with a single version byte:
///
/// | Variant    | Byte   | Spec |
/// |------------|--------|------|
/// | `SingleV1` | `0x00` | <https://lip.logos.co/ift-ts/raw/rln-v2> |
/// | `MultiV1`  | `0x01` | <https://lip.logos.co/ift-ts/raw/multi-message_id-burn-rln> |
///
/// ### Wire layouts per type
///
/// **`RLNWitnessInput`**
/// ```text
/// SingleV1: [ 0x00 | identity_secret<32> | user_message_limit<32> | message_id<32>
///                  | path_elements<var> | identity_path_index<var> | x<32> | external_nullifier<32> ]
/// MultiV1:  [ 0x01 | identity_secret<32> | user_message_limit<32>
///                  | path_elements<var> | identity_path_index<var> | x<32> | external_nullifier<32>
///                  | message_ids<var> | selector_used<var> ]
/// ```
///
/// **`RLNPartialWitnessInput`**
/// ```text
/// SingleV1: [ 0x00 | identity_secret<32> | user_message_limit<32>
///                  | path_elements<var> | identity_path_index<var> ]
/// MultiV1:  [ 0x01 | identity_secret<32> | user_message_limit<32>
///                  | path_elements<var> | identity_path_index<var> ]
/// ```
///
/// **`RLNProofValues`**
/// ```text
/// SingleV1: [ 0x00 | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
/// MultiV1:  [ 0x01 | root<32> | external_nullifier<32> | x<32> | ys<var> | nullifiers<var>
///                  | selector_used<var> ]
/// ```
///
/// **`RLNProof`**
/// ```text
/// SingleV1: [ 0x00 | proof<128> | RLNProofValues(0x00) ]
/// MultiV1:  [ 0x01 | proof<128> | RLNProofValues(0x01) ]
/// ```
///
/// **`PartialProof`**
/// ```text
/// SingleV1: [ 0x00 | partial_proof<var> ]
/// MultiV1:  [ 0x01 | partial_proof<var> ]
/// ```
///
/// ### Encoding conventions
/// - `<32>` - canonical 32-byte little-endian encoding of
///   [`ark_bn254::Fr`](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/bn254/src/fields/fr.rs#L9).
/// - `<var>` - length-prefixed list of `Fr`, except `identity_path_index` which is a
///   length-prefixed `Vec<u8>`.
/// - `proof<128>` - an
///   [`ark_groth16::Proof`](https://github.com/arkworks-rs/groth16/blob/9ba21ceab723d6b515a813e17846a0c0ec830c0d/src/data_structures.rs#L9)
///   over
///   [`ark_bn254::Bn254`](https://github.com/arkworks-rs/algebra/blob/7ad88c46e859a94ab8e0b19fd8a217c3dc472f1c/curves/bn254/src/curves/mod.rs#L44),
///   serialized as a fixed 128-byte little-endian canonical form (arkworks default).
/// - `partial_proof<var>` - variable-length little-endian canonical form (arkworks default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageMode {
    /// Single message-id mode (RLN v2, wire byte `0x00`).
    ///
    /// Each proof covers exactly one message slot (`max_out = 1`).
    SingleV1,

    /// Multi message-id mode (RLN v2 extension, wire byte `0x01`).
    ///
    /// Each proof covers up to `max_out` message slots.
    MultiV1 { max_out: usize },
}

impl MessageMode {
    /// Returns the wire-format version byte for this mode.
    pub fn version_byte(&self) -> u8 {
        match self {
            MessageMode::SingleV1 => 0x00,
            MessageMode::MultiV1 { .. } => 0x01,
        }
    }

    /// Returns the maximum number of message-id slots for this mode.
    ///
    /// Returns `1` for [`MessageMode::SingleV1`] and `max_out` for [`MessageMode::MultiV1`].
    pub fn max_out(&self) -> usize {
        match self {
            MessageMode::SingleV1 => 1,
            MessageMode::MultiV1 { max_out } => *max_out,
        }
    }
}

impl fmt::Display for MessageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageMode::SingleV1 => write!(f, "SingleV1"),
            MessageMode::MultiV1 { max_out } => write!(f, "MultiV1(max_out={max_out})"),
        }
    }
}

/// Parses a version byte into a [`MessageMode`] discriminant for deserialization dispatch.
///
/// For [`MessageMode::MultiV1`] the `max_out` field is set to `0` - it is a placeholder only.
impl TryFrom<u8> for MessageMode {
    type Error = ProtocolError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x00 => Ok(MessageMode::SingleV1),
            0x01 => Ok(MessageMode::MultiV1 { max_out: 0 }),
            other => Err(ProtocolError::UnknownMessageModeVersionByte(other)),
        }
    }
}

impl From<&RLNMessageInputs> for MessageMode {
    /// Determines the [`MessageMode`] from the type of the provided message inputs.
    fn from(inputs: &RLNMessageInputs) -> Self {
        match inputs {
            RLNMessageInputs::SingleV1 { .. } => MessageMode::SingleV1,
            RLNMessageInputs::MultiV1 { message_ids, .. } => MessageMode::MultiV1 {
                max_out: message_ids.len(),
            },
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<&Graph> for MessageMode {
    /// Determines the [`MessageMode`] from the graph's `max_out` value.
    fn from(graph: &Graph) -> Self {
        if graph.max_out <= 1 {
            MessageMode::SingleV1
        } else {
            MessageMode::MultiV1 {
                max_out: graph.max_out,
            }
        }
    }
}

pub struct SingleMessage;

pub struct MultiMessage;
