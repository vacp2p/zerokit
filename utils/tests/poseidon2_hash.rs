#[cfg(test)]
mod test {
    use std::{collections::HashMap, str::FromStr};

    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use zerokit_utils::poseidon::{
        Poseidon2, Poseidon2Error, Poseidon2WidthParams, POSEIDON2_ROUND_PARAMS,
    };

    #[test]
    fn test_poseidon2_hash() {
        // Single-input hashes
        let map = HashMap::from([
            (
                Fr::from(0u64),
                Fr::from_str(
                    "15621590199821056450610068202457788725601603091791048810523422053872049975191",
                )
                .unwrap(),
            ),
            (
                Fr::from(1u64),
                Fr::from_str(
                    "4220003009428892662276135118827607177546592752204629865937061707152838643028",
                )
                .unwrap(),
            ),
            (
                Fr::from(255),
                Fr::from_str(
                    "7937592598302844367143957950787178083748031376888694434084595044260720218467",
                )
                .unwrap(),
            ),
            (
                Fr::from(u16::MAX),
                Fr::from_str(
                    "15144885022207861076975692545298152863620279331910469187366075934905411803582",
                )
                .unwrap(),
            ),
            (
                Fr::from(u64::MAX),
                Fr::from_str(
                    "15745394491476960256433614367563035606443377230400924584852976859987459789057",
                )
                .unwrap(),
            ),
        ]);

        // map (key: what to hash, value: expected value)
        for (k, v) in map.into_iter() {
            let hasher = Poseidon2::from(&POSEIDON2_ROUND_PARAMS);
            let h = hasher.hash(&[k]);
            assert_eq!(h.unwrap(), v);
        }

        // Pair hashes done in a merkle tree (with leaves: [0, 1, 2, 3, 4, 5, 6, 7])

        // ~ leaves
        let fr_0 = Fr::from(0u64);
        let fr_1 = Fr::from(1u64);
        let fr_2 = Fr::from(2);
        let fr_3 = Fr::from(3);
        let fr_4 = Fr::from(4);
        let fr_5 = Fr::from(5);
        let fr_6 = Fr::from(6);
        let fr_7 = Fr::from(7);

        let fr_0_1 = Fr::from_str(
            "15449469107951025862283679587511638593643295575495923463032662929748907033596",
        )
        .unwrap();
        let fr_2_3 = Fr::from_str(
            "13678041337867290960266589384941800187924358149049520961450373685492213436635",
        )
        .unwrap();
        let fr_4_5 = Fr::from_str(
            "12967899758829441258496619254405154049367642696363068138582908761846511895006",
        )
        .unwrap();
        let fr_6_7 = Fr::from_str(
            "13603868525628594813447043942302024511017783773825520791750427244433455802726",
        )
        .unwrap();

        let fr_0_3 = Fr::from_str(
            "5476320322365262847878617742145562929524278479015588672960105546182802345070",
        )
        .unwrap();
        let fr_4_7 = Fr::from_str(
            "20575574818974962866877942019998248116994898167440890151560447843733955050575",
        )
        .unwrap();

        // ~ root
        let fr_0_7 = Fr::from_str(
            "17986296490892665003455635643488428436357366224970037388333164168095932361406",
        )
        .unwrap();

        // map (key: what to hash, value: expected value)
        let map = HashMap::from([
            ((fr_0, fr_1), fr_0_1),
            ((fr_2, fr_3), fr_2_3),
            ((fr_4, fr_5), fr_4_5),
            ((fr_6, fr_7), fr_6_7),
            ((fr_0_1, fr_2_3), fr_0_3),
            ((fr_4_5, fr_6_7), fr_4_7),
            ((fr_0_3, fr_4_7), fr_0_7),
        ]);

        for (k, v) in map.into_iter() {
            let hasher = Poseidon2::from(&POSEIDON2_ROUND_PARAMS);
            let h = hasher.hash(&[k.0, k.1]);
            assert_eq!(h.unwrap(), v);
        }
    }

    #[test]
    fn test_poseidon2_hash_against_references() {
        // One-shot outputs pinned against independent sources outside this crate, one group
        // per source below; all of them use the HorizenLabs constant set and this crate's
        // compression layout [inputs.., 0] with the capacity zero last.
        let hasher = Poseidon2::<Fr>::from(&POSEIDON2_ROUND_PARAMS);

        // Source: the official Nomos compression-mode test vectors, published in the
        // "Common Cryptographic Components" specification
        // https://nomos-tech.notion.site/1-0-2-Common-Cryptographic-Components-1fd261aa09df81ac8ebbe0111e2c2d84
        // and pinned as the big-endian hex the spec prints (its hash-mode vectors use the
        // sponge construction and do not apply here).
        let fr_from_be_hex = |hex: &str| {
            let hex = hex.trim_start_matches("0x");
            let bytes = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect::<Vec<u8>>();
            Fr::from_be_bytes_mod_order(&bytes)
        };
        let nomos_compression_vectors = [
            (
                [Fr::from(0u64), Fr::from(0u64)],
                "0x2ed1da00b14d635bd35b88ab49390d5c13c90da7e9e3a5f1ea69cd87a0aa3e82",
            ),
            (
                [Fr::from(1u64), Fr::from(0u64)],
                "0x063c4e8cac9a858304f0035b069255b069288c2af698ececf362cd8ec8c96665",
            ),
            (
                [Fr::from(0u64), Fr::from(1u64)],
                "0x222816f2669279d4c256ed2f196e8b0d54df83d35d61811bac36ea4e858483fc",
            ),
            (
                [Fr::from(1u64), Fr::from(1u64)],
                "0x277530b5f2b87dfe4535f43bb1998eda77736b4b05d15d983503566743c88031",
            ),
        ];
        for (input, expected_hex) in nomos_compression_vectors {
            assert_eq!(
                hasher.hash(&input).unwrap(),
                fr_from_be_hex(expected_hex),
                "Poseidon2 hash mismatch against the Nomos compression vector for {input:?}"
            );
        }

        // Source: the compress/hash functions of
        // https://github.com/logos-storage/rust-poseidon-bn254-pure, the Logos reference
        // implementation, whose t = 2..4 tables were generated independently of this crate;
        // each value was generated by running the crate directly
        // (new::hash1 / new::hash2 / new::hash3 over these exact inputs), covering every
        // width and the inputs the published vectors do not: p - 1 and a 254-bit element.
        let real_logos_storage_outputs = [
            (
                vec![Fr::from(1u64)],
                "4220003009428892662276135118827607177546592752204629865937061707152838643028",
            ),
            (
                vec![Fr::from(1u64), Fr::from(2u64)],
                "19440202363237281411582519622441422429699333916864112080167601237210978582482",
            ),
            (
                vec![Fr::from(3u64), Fr::from(4u64)],
                "6841465511530398863060979759285255211138061951621999722672958394106152792555",
            ),
            (
                vec![Fr::from(123456789u64), Fr::from(987654321u64)],
                "9009407154000298779772606758330192725127596677845856717883134607702775218298",
            ),
            (
                vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
                "17987529774510619908913366712228014240324707442444135579896039517815896575124",
            ),
            (
                vec![-Fr::from(1u64)],
                "9294971039725959602331275756280672770500152342309238745956501791342167982753",
            ),
            (
                vec![
                    -Fr::from(1u64),
                    Fr::from_str(
                        "8234104122482341265464879917108375546727594542924256086433795385182002072797",
                    )
                    .unwrap(),
                ],
                "5310548586399853854391108285211914361529358458221582994215274462864116450920",
            ),
            (
                vec![-Fr::from(1u64), -Fr::from(1u64), -Fr::from(1u64)],
                "4433769735955410370525159795790712404476733300548172692666348652860643522637",
            ),
        ];
        for (input, expected) in real_logos_storage_outputs {
            assert_eq!(
                hasher.hash(&input).unwrap(),
                Fr::from_str(expected).unwrap(),
                "Poseidon2 hash mismatch for input length {}",
                input.len()
            );
        }
    }

    #[test]
    fn test_poseidon2_input_errors() {
        // Test that the Poseidon2 hash rejects empty input and input lengths for which no parameters exist.
        let hasher = Poseidon2::<Fr>::from(&POSEIDON2_ROUND_PARAMS);
        assert!(matches!(hasher.hash(&[]), Err(Poseidon2Error::EmptyInput)));
        assert!(matches!(
            hasher.hash(&[Fr::from(1u64); 4]),
            Err(Poseidon2Error::NoParametersForInputLength(4))
        ));

        // A custom parameter set can carry a width the permutation implements no external
        // matrix for; hashing must reject it instead of mixing wrongly.
        let custom_params = [Poseidon2WidthParams {
            t: 5,
            n_rounds_f: 8,
            n_rounds_p: 56,
            mat_internal_diag_m_1: &[],
        }];
        let custom_hasher = Poseidon2::<Fr>::from(&custom_params);
        assert!(matches!(
            custom_hasher.hash(&[Fr::from(1u64); 4]),
            Err(Poseidon2Error::UnsupportedStateWidth(5))
        ));
    }
}
