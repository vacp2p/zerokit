#[cfg(test)]
mod test {
    use std::{collections::HashMap, str::FromStr};

    use ark_bn254::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use zerokit_utils::poseidon::{
        Poseidon2, Poseidon2Error, Poseidon2WidthParams, POSEIDON2_ROUND_PARAMS,
    };

    #[test]
    fn test_poseidon2_hash_basic() {
        let map = HashMap::from([
            (
                Fr::ZERO,
                Fr::from_str(
                    "15621590199821056450610068202457788725601603091791048810523422053872049975191",
                )
                .unwrap(),
            ),
            (
                Fr::ONE,
                Fr::from_str(
                    "13120422956170837922441672802975889424559262309139960702680326932494325745547",
                )
                .unwrap(),
            ),
            (
                Fr::from(255),
                Fr::from_str(
                    "20164375962684386123184471741727914395592212958912681122921637814631578005770",
                )
                .unwrap(),
            ),
            (
                Fr::from(u16::MAX),
                Fr::from_str(
                    "20786937162325990941610728850250782863083359858375836410315986476065042467397",
                )
                .unwrap(),
            ),
            (
                Fr::from(u64::MAX),
                Fr::from_str(
                    "8852172321376536403599241842676595368030228730970102917351025223452538462137",
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
    }

    #[test]
    fn test_poseidon2_hash_multi() {
        // All hashes done in a merkle tree (with leaves: [0, 1, 2, 3, 4, 5, 6, 7])

        // ~ leaves
        let fr_0 = Fr::ZERO;
        let fr_1 = Fr::ONE;
        let fr_2 = Fr::from(2);
        let fr_3 = Fr::from(3);
        let fr_4 = Fr::from(4);
        let fr_5 = Fr::from(5);
        let fr_6 = Fr::from(6);
        let fr_7 = Fr::from(7);

        let fr_0_1 = Fr::from_str(
            "13982872467079619220468508446544201124198598940814873056959250432766629877655",
        )
        .unwrap();
        let fr_2_3 = Fr::from_str(
            "4560515820078769238863109254947859292154412044368084171399163422357773136047",
        )
        .unwrap();
        let fr_4_5 = Fr::from_str(
            "15955938786932144214698075833053801401874467133389938293241740893507636287994",
        )
        .unwrap();
        let fr_6_7 = Fr::from_str(
            "17543959821215159941977433276292793147022558886439966597703805589956611578063",
        )
        .unwrap();

        let fr_0_3 = Fr::from_str(
            "9893707565777985206877165512719758173582291272941296536779908438426556837694",
        )
        .unwrap();
        let fr_4_7 = Fr::from_str(
            "2503441547207612778839996127925294870760543545866574345743087179961194789659",
        )
        .unwrap();

        // ~ root
        let fr_0_7 = Fr::from_str(
            "9235502947043929558071357888203674993177766578980264764434575014477187521463",
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
        // Externally verified one-shot outputs, from the two independent sources sharing the
        // HorizenLabs constant set:
        // - the pairs were computed with jf-poseidon2 (EspressoSystems/jellyfish); the (1, 2)
        //   case equals state[0] of the HorizenLabs known-answer test for permute([0, 1, 2]) in
        //   https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2.rs
        // - the single and the triple were computed by the evaluator of the HorizenLabs
        //   generation script poseidon2_rust_params.sage (it evaluates
        //   poseidon2([0, 1, .., t-1]), exactly the one-shot state of these inputs); the
        //   widths t = 2 and t = 4 have no published instance, this evaluator is their only
        //   independent check.
        let hasher = Poseidon2::<Fr>::from(&POSEIDON2_ROUND_PARAMS);
        let real_reference_outputs = [
            (
                vec![Fr::from(1u64)],
                "13120422956170837922441672802975889424559262309139960702680326932494325745547",
            ),
            (
                vec![Fr::from(1u64), Fr::from(2u64)],
                "5297208644449048816064511434384511824916970985131888684874823260532015509555",
            ),
            (
                vec![Fr::ZERO, Fr::ZERO],
                "21177166670744647784289648293577786481357446166129397094207318338605633126018",
            ),
            (
                vec![Fr::ONE, Fr::ONE],
                "6244710744212918225541182980747176473975170934996674195251555650524813642975",
            ),
            (
                vec![Fr::from(3u64), Fr::from(4u64)],
                "17876044324362893302450557747690880223450114576345709251654422037230086863116",
            ),
            (
                vec![Fr::from(123456789u64), Fr::from(987654321u64)],
                "7948274567296627520074104938313042724061892674643171639138083556112484336070",
            ),
            (
                vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
                "786823568102245344938517132468097745676732687098822989626730198331658606391",
            ),
        ];
        for (input, expected) in real_reference_outputs {
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
