use super::error::ZerokitMerkleTreeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideRangeValidation {
    pub indices: Vec<usize>,
    pub max_index: Option<usize>,
    pub min_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyIndicesPolicy {
    Allow,
    Reject,
}

/// Validates and normalizes `override_range` inputs.
///
/// `start + leaves_len` is checked with `checked_add` to prevent overflow and
/// all indices are normalized (sorted and deduplicated) before use.
pub fn validate_override_range_inputs(
    start: usize,
    leaves_len: usize,
    mut indices: Vec<usize>,
    capacity: usize,
    empty_indices_policy: EmptyIndicesPolicy,
) -> Result<OverrideRangeValidation, ZerokitMerkleTreeError> {
    if matches!(empty_indices_policy, EmptyIndicesPolicy::Reject) && indices.is_empty() {
        return Err(ZerokitMerkleTreeError::InvalidIndices);
    }

    if indices.iter().any(|&i| i >= capacity) {
        return Err(ZerokitMerkleTreeError::InvalidIndices);
    }

    indices.sort_unstable();
    indices.dedup();

    let min_index = indices.first().copied();

    let max_index = if leaves_len == 0 {
        None
    } else {
        let end = start
            .checked_add(leaves_len)
            .ok_or(ZerokitMerkleTreeError::TooManySet)?;
        if end > capacity {
            return Err(ZerokitMerkleTreeError::TooManySet);
        }
        Some(end)
    };

    if let (Some(min_idx), Some(end)) = (min_index, max_index) {
        // Current override implementations build offsets with `start - min_index`,
        // so indices that begin after `start` are invalid for this flow.
        if min_idx > start || min_idx >= end {
            return Err(ZerokitMerkleTreeError::InvalidIndices);
        }
    }

    Ok(OverrideRangeValidation {
        indices,
        max_index,
        min_index,
    })
}

#[cfg(test)]
mod test {
    use super::{validate_override_range_inputs, EmptyIndicesPolicy};
    use crate::merkle_tree::ZerokitMerkleTreeError;

    #[test]
    fn test_validate_override_range_inputs_accepts_valid_inputs() {
        // indices [0,1] are before start=2, leaves cover [2..=4] (indices 2,3,4), all within capacity
        let validated = validate_override_range_inputs(
            2,
            3,
            vec![1, 0],
            1usize << 20,
            EmptyIndicesPolicy::Allow,
        )
        .unwrap();
        assert_eq!(validated.min_index, Some(0));
        assert_eq!(validated.max_index, Some(5)); // start + leaves_len
        assert_eq!(validated.indices, vec![0, 1]); // sorted
    }

    #[test]
    fn test_validate_override_range_inputs_rejects_start_add_overflow() {
        let err = validate_override_range_inputs(
            usize::MAX,
            1,
            vec![0],
            1usize << 20,
            EmptyIndicesPolicy::Allow,
        )
        .unwrap_err();
        assert!(matches!(err, ZerokitMerkleTreeError::TooManySet));
    }

    #[test]
    fn test_validate_override_range_inputs_rejects_incompatible_mixed_offsets() {
        let err =
            validate_override_range_inputs(0, 2, vec![1], 1usize << 20, EmptyIndicesPolicy::Allow)
                .unwrap_err();
        assert!(matches!(err, ZerokitMerkleTreeError::InvalidIndices));
    }

    #[test]
    fn test_validate_override_range_inputs_rejects_empty_indices_when_required() {
        let err =
            validate_override_range_inputs(0, 1, vec![], 1usize << 20, EmptyIndicesPolicy::Reject)
                .unwrap_err();
        assert!(matches!(err, ZerokitMerkleTreeError::InvalidIndices));
    }
}
