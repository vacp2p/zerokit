#[cfg(test)]
mod test {
    use std::{collections::HashMap, str::FromStr};

    use ark_bn254::Fr;
    use ark_ff::{AdditiveGroup, Field};
    use zerokit_utils::poseidon::Poseidon;

    const ROUND_PARAMS: [(usize, usize, usize, usize); 8] = [
        (2, 8, 56, 0),
        (3, 8, 57, 0),
        (4, 8, 56, 0),
        (5, 8, 60, 0),
        (6, 8, 60, 0),
        (7, 8, 63, 0),
        (8, 8, 64, 0),
        (9, 8, 63, 0),
    ];

    #[test]
    fn test_poseidon_hash_basic() {
        let map = HashMap::from([
            (
                Fr::ZERO,
                Fr::from_str(
                    "19014214495641488759237505126948346942972912379615652741039992445865937985820",
                )
                .unwrap(),
            ),
            (
                Fr::ONE,
                Fr::from_str(
                    "18586133768512220936620570745912940619677854269274689475585506675881198879027",
                )
                .unwrap(),
            ),
            (
                Fr::from(255),
                Fr::from_str(
                    "20026131459732984724454933360292530547665726761019872861025481903072111625788",
                )
                .unwrap(),
            ),
            (
                Fr::from(u16::MAX),
                Fr::from_str(
                    "12358868638722666642632413418981275677998688723398440898957566982787708451243",
                )
                .unwrap(),
            ),
            (
                Fr::from(u64::MAX),
                Fr::from_str(
                    "17449307747295017006142981453320720946812828330895590310359634430146721583189",
                )
                .unwrap(),
            ),
        ]);

        // map (key: what to hash, value: expected value)
        for (k, v) in map.into_iter() {
            let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
            let h = hasher.hash(&[k]);
            assert_eq!(h.unwrap(), v);
        }
    }

    #[test]
    fn test_poseidon_hash_multi() {
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
            "12583541437132735734108669866114103169564651237895298778035846191048104863326",
        )
        .unwrap();
        let fr_2_3 = Fr::from_str(
            "17197790661637433027297685226742709599380837544520340689137581733613433332983",
        )
        .unwrap();
        let fr_4_5 = Fr::from_str(
            "756592041685769348226045093946546956867261766023639881791475046640232555043",
        )
        .unwrap();
        let fr_6_7 = Fr::from_str(
            "5558359459771725727593826278265342308584225092343962757289948761260561575479",
        )
        .unwrap();

        let fr_0_3 = Fr::from_str(
            "3720616653028013822312861221679392249031832781774563366107458835261883914924",
        )
        .unwrap();
        let fr_4_7 = Fr::from_str(
            "7960741062684589801276390367952372418815534638314682948141519164356522829957",
        )
        .unwrap();

        // ~ root
        let fr_0_7 = Fr::from_str(
            "11780650233517635876913804110234352847867393797952240856403268682492028497284",
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
            let hasher = Poseidon::<Fr>::from(&ROUND_PARAMS);
            let h = hasher.hash(&[k.0, k.1]);
            assert_eq!(h.unwrap(), v);
        }
    }
}
