use std::fmt;

use crate::circuit::Graph;
use crate::protocol::witness::RLNMessageInputs;

/// Runtime message mode for the RLN circuit.
///
/// Replaces the `multi-message-id` compile-time feature flag for business logic.
/// Use [`MessageMode::Single`] for the original RLN v2 single message-id format,
/// and [`MessageMode::Multi`] for the multi message-id extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageMode {
    /// Single message-id mode (RLN v2). Each proof covers exactly one message slot.
    Single,
    /// Multi message-id mode with `max_out` slots per proof.
    Multi { max_out: usize },
}

impl MessageMode {
    /// Returns the maximum number of message ID slots for this mode.
    ///
    /// Returns `1` for [`MessageMode::Single`] and `max_out` for [`MessageMode::Multi`].
    pub fn max_out(&self) -> usize {
        match self {
            MessageMode::Single => 1,
            MessageMode::Multi { max_out } => *max_out,
        }
    }
}

impl fmt::Display for MessageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageMode::Single => write!(f, "single"),
            MessageMode::Multi { max_out } => write!(f, "multi(max_out={max_out})"),
        }
    }
}

impl From<usize> for MessageMode {
    /// Converts a `max_out` value to a [`MessageMode`].
    ///
    /// `max_out <= 1` maps to [`MessageMode::Single`]; anything larger maps to [`MessageMode::Multi`].
    fn from(max_out: usize) -> Self {
        if max_out <= 1 {
            MessageMode::Single
        } else {
            MessageMode::Multi { max_out }
        }
    }
}

impl From<&RLNMessageInputs> for MessageMode {
    fn from(inputs: &RLNMessageInputs) -> Self {
        match inputs {
            RLNMessageInputs::SingleV1 { .. } => MessageMode::Single,
            RLNMessageInputs::MultiV1 { message_ids, .. } => MessageMode::Multi {
                max_out: message_ids.len(),
            },
        }
    }
}

impl From<&Graph> for MessageMode {
    /// Determines the [`MessageMode`] based on the graph's `max_out` value.
    ///
    /// Delegates to [`MessageMode::from(usize)`].
    fn from(graph: &Graph) -> Self {
        MessageMode::from(graph.max_out)
    }
}
