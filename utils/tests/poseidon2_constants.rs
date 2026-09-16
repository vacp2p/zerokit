#[cfg(test)]
mod test {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use zerokit_utils::poseidon::{
        poseidon2_constants::find_poseidon2_round_constants, Poseidon2, POSEIDON2_ROUND_PARAMS,
    };

    const ROUND_PARAMS: [(usize, usize, usize); 3] = [(2, 8, 56), (3, 8, 56), (4, 8, 56)];

    // The following constants were generated with the HorizenLabs generation script
    // https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage
    // for the Bn254 scalar field with T in [2, 3, 4], RF = 8 and RP = 56.
    // The T = 3 output matches the published HorizenLabs instance
    // https://github.com/HorizenLabs/poseidon2/blob/main/plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs
    // bit-for-bit; T = 2 and T = 4 have no published instance and were cross-validated
    // against the script's own evaluator.
    // Per width: the first external round constant, the first internal round constant, the
    // last external round constant (the last pin catches any drift in the Grain draw order:
    // external rounds draw T constants, internal rounds draw exactly ONE) and the
    // internal-matrix diagonal minus one.
    const REFERENCE_CONSTANTS: [(&str, &str, &str, &[&str]); 3] = [
        (
            "4417881134626180770308697923359573201005643519861877412381846989312604493735",
            "1050793453380762984940163090920066886770841063557081906093018330633089036729",
            "6422235064906823218421386871122109085799298052314922856340127798647926126490",
            &["1", "2"],
        ),
        (
            "13128406282895484157369354038809433636203389051939936481821261911791933663254",
            "11811415718957691261673974625780511541635150909919309658375768251762566747317",
            "7126990412157463341897179572979760225771626877677162088926546182321369054630",
            &["1", "1", "2"],
        ),
        (
            "11633431549750490989983886834189948010834808234699737327785600195936805266405",
            "5624865188680173294191042415227598609140934495743721047183803859030618890703",
            "10582332261829184460912611488470654685922576576939233092337240630493625631748",
            &[
                "7626475329478847982857743246276194948757851985510858890691733676098590062311",
                "5498568565063849786384470689962419967523752476452646391422913716315471115275",
                "148936322117705719734052984176402258788283488576388928671173547788498414613",
                "15456385653678559339152734484033356164266089951521103188900320352052358038155",
            ],
        ),
    ];

    #[test]
    // This test checks if the generated constants correspond to the expected hardcoded ones
    // for the Bn254 scalar field
    fn test_poseidon2_constants_generation() {
        let poseidon2 = Poseidon2::<Fr>::from(&POSEIDON2_ROUND_PARAMS);

        for ((t, n_rounds_f, n_rounds_p), (rc_first, rc_first_internal, rc_last, diag)) in
            ROUND_PARAMS.into_iter().zip(REFERENCE_CONSTANTS)
        {
            // The direct derivation must produce the pinned reference constants.
            let (rc_external, rc_internal) =
                find_poseidon2_round_constants::<Fr>(t, n_rounds_f, n_rounds_p);
            assert_eq!(rc_external.len(), n_rounds_f);
            assert_eq!(rc_internal.len(), n_rounds_p);
            assert_eq!(rc_external[0][0], Fr::from_str(rc_first).unwrap());
            assert_eq!(rc_internal[0], Fr::from_str(rc_first_internal).unwrap());
            assert_eq!(
                *rc_external.last().unwrap().last().unwrap(),
                Fr::from_str(rc_last).unwrap()
            );

            // The instance built from the width configurations must agree with the direct
            // derivation and carry the pinned internal-matrix diagonal.
            let params = poseidon2
                .get_parameters()
                .iter()
                .find(|el| el.t == t)
                .unwrap();
            assert_eq!(params.n_rounds_f, n_rounds_f);
            assert_eq!(params.n_rounds_p, n_rounds_p);
            assert_eq!(params.rc_external, rc_external);
            assert_eq!(params.rc_internal, rc_internal);
            let expected_diag: Vec<Fr> = diag.iter().map(|d| Fr::from_str(d).unwrap()).collect();
            assert_eq!(params.mat_internal_diag_m_1, expected_diag);
        }
    }
}
