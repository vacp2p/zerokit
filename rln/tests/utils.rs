#[cfg(test)]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rln::{
        prelude::*,
        utils::{
            bytes_be_to_vec_bool, bytes_le_to_vec_bool, vec_bool_to_bytes_be, vec_bool_to_bytes_le,
        },
    };

    #[test]
    fn test_normalize_usize_le() {
        // Test basic cases
        assert_eq!(normalize_usize_le(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalize_usize_le(1), [1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalize_usize_le(255), [255, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalize_usize_le(256), [0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalize_usize_le(65535), [255, 255, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalize_usize_le(65536), [0, 0, 1, 0, 0, 0, 0, 0]);

        // Test 32-bit boundary
        assert_eq!(
            normalize_usize_le(4294967295),
            [255, 255, 255, 255, 0, 0, 0, 0]
        );
        assert_eq!(normalize_usize_le(4294967296), [0, 0, 0, 0, 1, 0, 0, 0]);

        // Test maximum value
        assert_eq!(
            normalize_usize_le(usize::MAX),
            [255, 255, 255, 255, 255, 255, 255, 255]
        );

        // Test that result is always 8 bytes
        assert_eq!(normalize_usize_le(0).len(), 8);
        assert_eq!(normalize_usize_le(usize::MAX).len(), 8);
    }

    #[test]
    fn test_normalize_usize_be() {
        // Test basic cases
        assert_eq!(normalize_usize_be(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalize_usize_be(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(normalize_usize_be(255), [0, 0, 0, 0, 0, 0, 0, 255]);
        assert_eq!(normalize_usize_be(256), [0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(normalize_usize_be(65535), [0, 0, 0, 0, 0, 0, 255, 255]);
        assert_eq!(normalize_usize_be(65536), [0, 0, 0, 0, 0, 1, 0, 0]);

        // Test 32-bit boundary
        assert_eq!(
            normalize_usize_be(4294967295),
            [0, 0, 0, 0, 255, 255, 255, 255]
        );
        assert_eq!(normalize_usize_be(4294967296), [0, 0, 0, 1, 0, 0, 0, 0]);

        // Test maximum value
        assert_eq!(
            normalize_usize_be(usize::MAX),
            [255, 255, 255, 255, 255, 255, 255, 255]
        );

        // Test that result is always 8 bytes
        assert_eq!(normalize_usize_be(0).len(), 8);
        assert_eq!(normalize_usize_be(usize::MAX).len(), 8);
    }

    #[test]
    fn test_normalize_usize_endianness() {
        // Test that little-endian and big-endian produce different results for non-zero values
        let test_values = vec![1, 255, 256, 65535, 65536, 4294967295, 4294967296];

        for &value in &test_values {
            let le_result = normalize_usize_le(value);
            let be_result = normalize_usize_be(value);

            // For non-zero values, LE and BE should be different
            assert_ne!(
                le_result, be_result,
                "LE and BE should differ for value {value}"
            );

            // Both should be 8 bytes
            assert_eq!(le_result.len(), 8);
            assert_eq!(be_result.len(), 8);
        }

        // Zero should be the same in both endianness
        assert_eq!(normalize_usize_le(0), normalize_usize_be(0));
    }

    #[test]
    fn test_normalize_usize_roundtrip() {
        // Test that we can reconstruct the original value from the normalized bytes
        let test_values = vec![
            0,
            1,
            255,
            256,
            65535,
            65536,
            4294967295,
            4294967296,
            usize::MAX,
        ];

        for &value in &test_values {
            let le_bytes = normalize_usize_le(value);
            let be_bytes = normalize_usize_be(value);

            // Reconstruct from little-endian bytes
            let reconstructed_le = usize::from_le_bytes(le_bytes);
            assert_eq!(
                reconstructed_le, value,
                "LE roundtrip failed for value {value}"
            );

            // Reconstruct from big-endian bytes
            let reconstructed_be = usize::from_be_bytes(be_bytes);
            assert_eq!(
                reconstructed_be, value,
                "BE roundtrip failed for value {value}"
            );
        }
    }

    #[test]
    fn test_normalize_usize_edge_cases() {
        // Test edge cases and boundary values
        let edge_cases = vec![
            0,
            1,
            255,
            256,
            65535,
            65536,
            16777215,          // 2^24 - 1
            16777216,          // 2^24
            4294967295,        // 2^32 - 1
            4294967296,        // 2^32
            1099511627775,     // 2^40 - 1
            1099511627776,     // 2^40
            281474976710655,   // 2^48 - 1
            281474976710656,   // 2^48
            72057594037927935, // 2^56 - 1
            72057594037927936, // 2^56
            usize::MAX,
        ];

        for &value in &edge_cases {
            let le_result = normalize_usize_le(value);
            let be_result = normalize_usize_be(value);

            // Both should be 8 bytes
            assert_eq!(le_result.len(), 8);
            assert_eq!(be_result.len(), 8);

            // Roundtrip should work
            assert_eq!(usize::from_le_bytes(le_result), value);
            assert_eq!(usize::from_be_bytes(be_result), value);
        }
    }

    #[test]
    fn test_normalize_usize_architecture_independence() {
        // Test that the functions work consistently regardless of the underlying architecture
        // This test ensures that the functions provide consistent 8-byte output
        // even on 32-bit systems where usize might be 4 bytes

        let test_values = vec![0, 1, 255, 256, 65535, 65536, 4294967295, 4294967296];

        for &value in &test_values {
            let le_result = normalize_usize_le(value);
            let be_result = normalize_usize_be(value);

            // Always 8 bytes regardless of architecture
            assert_eq!(le_result.len(), 8);
            assert_eq!(be_result.len(), 8);

            // The result should be consistent with the original value
            assert_eq!(usize::from_le_bytes(le_result), value);
            assert_eq!(usize::from_be_bytes(be_result), value);
        }
    }

    #[test]
    fn test_fr_serialization_roundtrip() {
        let mut rng = thread_rng();

        // Test multiple random Fr values
        for _ in 0..10 {
            let fr = Fr::rand(&mut rng);

            // Test little-endian roundtrip
            let le_bytes = fr_to_bytes_le(&fr);
            let (reconstructed_le, _) = bytes_le_to_fr(&le_bytes).unwrap();
            assert_eq!(fr, reconstructed_le);

            // Test big-endian roundtrip
            let be_bytes = fr_to_bytes_be(&fr);
            let (reconstructed_be, _) = bytes_be_to_fr(&be_bytes).unwrap();
            assert_eq!(fr, reconstructed_be);
        }
    }

    #[test]
    fn test_vec_fr_serialization_roundtrip() {
        let mut rng = thread_rng();

        // Test with different vector sizes
        for size in [0, 1, 5, 10] {
            let fr_vec: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();

            // Test little-endian roundtrip
            let le_bytes = vec_fr_to_bytes_le(&fr_vec);
            let (reconstructed_le, _) = bytes_le_to_vec_fr(&le_bytes).unwrap();
            assert_eq!(fr_vec, reconstructed_le);

            // Test big-endian roundtrip
            let be_bytes = vec_fr_to_bytes_be(&fr_vec);
            let (reconstructed_be, _) = bytes_be_to_vec_fr(&be_bytes).unwrap();
            assert_eq!(fr_vec, reconstructed_be);
        }
    }

    #[test]
    fn test_vec_u8_serialization_roundtrip() {
        // Test with different vector sizes and content
        let test_cases = vec![
            vec![],
            vec![0],
            vec![255],
            vec![1, 2, 3, 4, 5],
            vec![0, 255, 128, 64, 32, 16, 8, 4, 2, 1],
            (0..100).collect::<Vec<u8>>(),
        ];

        for test_case in test_cases {
            // Test little-endian roundtrip
            let le_bytes = vec_u8_to_bytes_le(&test_case);
            let (reconstructed_le, _) = bytes_le_to_vec_u8(&le_bytes).unwrap();
            assert_eq!(test_case, reconstructed_le);

            // Test big-endian roundtrip
            let be_bytes = vec_u8_to_bytes_be(&test_case);
            let (reconstructed_be, _) = bytes_be_to_vec_u8(&be_bytes).unwrap();
            assert_eq!(test_case, reconstructed_be);
        }
    }

    #[test]
    fn test_vec_usize_serialization_roundtrip() {
        // Test with different vector sizes and content
        let test_cases = vec![
            vec![],
            vec![0],
            vec![usize::MAX],
            vec![1, 2, 3, 4, 5],
            vec![0, 255, 65535, 4294967295, usize::MAX],
            (0..10).collect::<Vec<usize>>(),
        ];

        for test_case in test_cases {
            // Test little-endian roundtrip
            let le_bytes = {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&normalize_usize_le(test_case.len()));
                for &value in &test_case {
                    bytes.extend_from_slice(&normalize_usize_le(value));
                }
                bytes
            };
            let reconstructed_le = bytes_le_to_vec_usize(&le_bytes).unwrap();
            assert_eq!(test_case, reconstructed_le);

            // Test big-endian roundtrip
            let be_bytes = {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&normalize_usize_be(test_case.len()));
                for &value in &test_case {
                    bytes.extend_from_slice(&normalize_usize_be(value));
                }
                bytes
            };
            let reconstructed_be = bytes_be_to_vec_usize(&be_bytes).unwrap();
            assert_eq!(test_case, reconstructed_be);
        }
    }

    #[test]
    fn test_vec_bool_serialization_roundtrip() {
        // Test with different vector sizes and content
        let test_cases = vec![
            vec![],
            vec![true],
            vec![false],
            vec![true, false, true, false, true],
            vec![true; 50],
            (0..50).map(|i| i % 2 == 0).collect::<Vec<bool>>(),
        ];

        for test_case in test_cases {
            // Test little-endian roundtrip
            let le_bytes = vec_bool_to_bytes_le(&test_case);
            let (reconstructed_le, _) = bytes_le_to_vec_bool(&le_bytes).unwrap();
            assert_eq!(test_case, reconstructed_le);

            // Test big-endian roundtrip
            let be_bytes = vec_bool_to_bytes_be(&test_case);
            let (reconstructed_be, _) = bytes_be_to_vec_bool(&be_bytes).unwrap();
            assert_eq!(test_case, reconstructed_be);
        }
    }

    #[test]
    fn test_str_to_fr() {
        // Test valid hex strings
        let test_cases = vec![
            ("0x0", 16, Fr::from(0u64)),
            ("0x1", 16, Fr::from(1u64)),
            ("0xff", 16, Fr::from(255u64)),
            ("0x100", 16, Fr::from(256u64)),
        ];

        for (input, radix, expected) in test_cases {
            let result = str_to_fr(input, radix).unwrap();
            assert_eq!(result, expected);
        }

        // Test invalid inputs
        assert!(str_to_fr("invalid", 16).is_err());
        assert!(str_to_fr("0x", 16).is_err());
    }

    #[test]
    fn test_endianness_differences() {
        let mut rng = thread_rng();
        let fr = Fr::rand(&mut rng);

        // Test that LE and BE produce different byte representations
        let le_bytes = fr_to_bytes_le(&fr);
        let be_bytes = fr_to_bytes_be(&fr);

        // They should be different (unless the value is symmetric)
        if le_bytes != be_bytes {
            // Verify they can both be reconstructed correctly
            let (reconstructed_le, _) = bytes_le_to_fr(&le_bytes).unwrap();
            let (reconstructed_be, _) = bytes_be_to_fr(&be_bytes).unwrap();
            assert_eq!(fr, reconstructed_le);
            assert_eq!(fr, reconstructed_be);
        }
    }

    #[test]
    fn test_error_handling() {
        // Test bytes_le_to_fr and bytes_be_to_fr with insufficient data
        let short_bytes = vec![0u8; 10]; // Less than FR_BYTE_SIZE (32 bytes)
        assert!(bytes_le_to_fr(&short_bytes).is_err());
        assert!(bytes_be_to_fr(&short_bytes).is_err());

        // Test with empty bytes
        let empty_bytes = vec![];
        assert!(bytes_le_to_fr(&empty_bytes).is_err());
        assert!(bytes_be_to_fr(&empty_bytes).is_err());

        // Test with exact size - should succeed
        let exact_bytes = vec![0u8; FR_BYTE_SIZE];
        assert!(bytes_le_to_fr(&exact_bytes).is_ok());
        assert!(bytes_be_to_fr(&exact_bytes).is_ok());

        // Test with more than enough data - should succeed
        let extra_bytes = vec![0u8; FR_BYTE_SIZE + 10];
        assert!(bytes_le_to_fr(&extra_bytes).is_ok());
        assert!(bytes_be_to_fr(&extra_bytes).is_ok());

        // Test with valid length but insufficient data for vector deserialization
        let valid_length_invalid_data = vec![0u8; 8]; // Length 0, but no data
        assert!(bytes_le_to_vec_u8(&valid_length_invalid_data).is_ok());
        assert!(bytes_be_to_vec_u8(&valid_length_invalid_data).is_ok());
        assert!(bytes_le_to_vec_fr(&valid_length_invalid_data).is_ok());
        assert!(bytes_be_to_vec_fr(&valid_length_invalid_data).is_ok());
        assert!(bytes_le_to_vec_usize(&valid_length_invalid_data).is_ok());
        assert!(bytes_be_to_vec_usize(&valid_length_invalid_data).is_ok());

        // Test with reasonable length but insufficient data for vector deserialization
        let reasonable_length = {
            let mut bytes = vec![0u8; 8];
            bytes[0] = 1; // Length 1
            bytes
        };
        // This should fail because we don't have enough data for the vector elements
        assert!(bytes_le_to_vec_u8(&reasonable_length).is_err());
        assert!(bytes_be_to_vec_u8(&reasonable_length).is_err());
        assert!(bytes_le_to_vec_fr(&reasonable_length).is_err());
        assert!(bytes_be_to_vec_fr(&reasonable_length).is_err());
        assert!(bytes_le_to_vec_usize(&reasonable_length).is_err());
        assert!(bytes_be_to_vec_usize(&reasonable_length).is_err());

        // Test with valid data for u8 vector
        let valid_u8_data_le = {
            let mut bytes = vec![0u8; 9];
            bytes[..8].copy_from_slice(&(1u64.to_le_bytes())); // Length 1, little-endian
            bytes[8] = 42; // One byte of data
            bytes
        };
        let valid_u8_data_be = {
            let mut bytes = vec![0u8; 9];
            bytes[..8].copy_from_slice(&(1u64.to_be_bytes())); // Length 1, big-endian
            bytes[8] = 42; // One byte of data
            bytes
        };
        assert!(bytes_le_to_vec_u8(&valid_u8_data_le).is_ok());
        assert!(bytes_be_to_vec_u8(&valid_u8_data_be).is_ok());
    }

    #[test]
    fn test_empty_vectors() {
        // Test empty vector serialization/deserialization
        let empty_fr: Vec<Fr> = vec![];
        let empty_u8: Vec<u8> = vec![];
        let empty_usize: Vec<usize> = vec![];

        // Test Fr vectors
        let le_fr_bytes = vec_fr_to_bytes_le(&empty_fr);
        let be_fr_bytes = vec_fr_to_bytes_be(&empty_fr);
        let (reconstructed_le_fr, _) = bytes_le_to_vec_fr(&le_fr_bytes).unwrap();
        let (reconstructed_be_fr, _) = bytes_be_to_vec_fr(&be_fr_bytes).unwrap();
        assert_eq!(empty_fr, reconstructed_le_fr);
        assert_eq!(empty_fr, reconstructed_be_fr);

        // Test u8 vectors
        let le_u8_bytes = vec_u8_to_bytes_le(&empty_u8);
        let be_u8_bytes = vec_u8_to_bytes_be(&empty_u8);
        let (reconstructed_le_u8, _) = bytes_le_to_vec_u8(&le_u8_bytes).unwrap();
        let (reconstructed_be_u8, _) = bytes_be_to_vec_u8(&be_u8_bytes).unwrap();
        assert_eq!(empty_u8, reconstructed_le_u8);
        assert_eq!(empty_u8, reconstructed_be_u8);

        // Test usize vectors
        let le_usize_bytes = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&normalize_usize_le(0));
            bytes
        };
        let be_usize_bytes = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&normalize_usize_be(0));
            bytes
        };
        let reconstructed_le_usize = bytes_le_to_vec_usize(&le_usize_bytes).unwrap();
        let reconstructed_be_usize = bytes_be_to_vec_usize(&be_usize_bytes).unwrap();
        assert_eq!(empty_usize, reconstructed_le_usize);
        assert_eq!(empty_usize, reconstructed_be_usize);
    }
}
