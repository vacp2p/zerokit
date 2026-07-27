#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, LazyLock};

use super::{
    error::GraphReadError,
    iden3calc::{graph::Node, storage::deserialize_witnesscalc_graph, InputSignalsInfo},
};
#[cfg(not(target_arch = "wasm32"))]
use super::{DEFAULT_MAX_OUT, DEFAULT_TREE_DEPTH};

#[cfg(not(target_arch = "wasm32"))]
const GRAPH_BYTES_SINGLE: &[u8] = include_bytes!("../../resources/tree_depth_20/graph.bin");

#[cfg(not(target_arch = "wasm32"))]
const GRAPH_BYTES_MULTI: &[u8] =
    include_bytes!("../../resources/tree_depth_20/multi_message_id/max_out_4/graph.bin");

#[cfg(not(target_arch = "wasm32"))]
static GRAPH_SINGLE: LazyLock<Arc<Graph>> = LazyLock::new(|| {
    Arc::new(
        graph_from_raw(GRAPH_BYTES_SINGLE, Some(DEFAULT_TREE_DEPTH), None)
            .expect("Default Single graph must be valid"),
    )
});

#[cfg(not(target_arch = "wasm32"))]
static GRAPH_MULTI: LazyLock<Arc<Graph>> = LazyLock::new(|| {
    Arc::new(
        graph_from_raw(
            GRAPH_BYTES_MULTI,
            Some(DEFAULT_TREE_DEPTH),
            Some(DEFAULT_MAX_OUT),
        )
        .expect("Default Multi graph must be valid"),
    )
});

/// Witness calculator graph.
///
/// Contains the deserialized computation graph used for witness calculation.
/// Parsing this once and reusing it avoids repeated deserialization overhead.
#[derive(Debug, Clone)]
pub struct Graph {
    pub(crate) nodes: Vec<Node>,
    pub(crate) signals: Vec<usize>,
    pub(crate) input_mapping: InputSignalsInfo,
    pub(crate) tree_depth: usize,
    pub(crate) max_out: usize,
}

/// Parses the witness calculator graph from raw bytes
pub fn graph_from_raw(
    graph_data: &[u8],
    expected_tree_depth: Option<usize>,
    expected_max_out: Option<usize>,
) -> Result<Graph, GraphReadError> {
    if graph_data.is_empty() {
        return Err(GraphReadError::EmptyBytes);
    }

    let (nodes, signals, input_mapping) =
        deserialize_witnesscalc_graph(std::io::Cursor::new(graph_data))?;

    let tree_depth = {
        let (_, depth) = input_mapping
            .get("pathElements")
            .ok_or_else(|| GraphReadError::MissingSignal("pathElements".to_string()))?;

        if let Some(expected) = expected_tree_depth {
            if expected != *depth {
                return Err(GraphReadError::TreeDepthMismatch {
                    expected,
                    actual: *depth,
                });
            }
        }

        *depth
    };

    let max_out = {
        let (_, count) = input_mapping
            .get("messageId")
            .ok_or_else(|| GraphReadError::MissingSignal("messageId".to_string()))?;

        if let Some(expected) = expected_max_out {
            if expected != *count {
                return Err(GraphReadError::MaxOutMismatch {
                    expected,
                    actual: *count,
                });
            }
        }

        *count
    };

    Ok(Graph {
        nodes,
        signals,
        input_mapping,
        tree_depth,
        max_out,
    })
}

/// Loads default Single graph
#[cfg(not(target_arch = "wasm32"))]
pub fn default_graph_single() -> &'static Arc<Graph> {
    &GRAPH_SINGLE
}

/// Loads default Multi graph
#[cfg(not(target_arch = "wasm32"))]
pub fn default_graph_multi() -> &'static Arc<Graph> {
    &GRAPH_MULTI
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_empty_graph() {
        let err = graph_from_raw(&[], None, None).err().unwrap();
        assert!(matches!(err, GraphReadError::EmptyBytes));
    }

    #[test]
    fn test_tree_depth_mismatch() {
        let err = graph_from_raw(GRAPH_BYTES_SINGLE, Some(DEFAULT_TREE_DEPTH + 1), None)
            .err()
            .unwrap();
        assert!(matches!(err, GraphReadError::TreeDepthMismatch { .. }));
    }

    #[test]
    fn test_max_out_mismatch() {
        let err = graph_from_raw(
            GRAPH_BYTES_MULTI,
            Some(DEFAULT_TREE_DEPTH),
            Some(DEFAULT_MAX_OUT + 1),
        )
        .err()
        .unwrap();
        assert!(matches!(err, GraphReadError::MaxOutMismatch { .. }));
    }

    #[test]
    fn test_missing_signal_rejected() {
        let single = graph_from_raw(GRAPH_BYTES_SINGLE, None, None).unwrap();
        assert!(single.input_mapping.contains_key("pathElements"));
        assert!(single.input_mapping.contains_key("messageId"));

        let multi = graph_from_raw(GRAPH_BYTES_MULTI, None, None).unwrap();
        assert!(multi.input_mapping.contains_key("pathElements"));
        assert!(multi.input_mapping.contains_key("messageId"));
    }
}
