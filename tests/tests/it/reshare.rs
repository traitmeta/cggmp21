use generic_ec::Point;
use rand::Rng;

use crate::keygen::validate_keygen_output;
use cggmp24::{key_share::Validate, ExecutionId, IncompleteKeyShare};
use cggmp24_key_refresh::reshare::{run_reshare, ReshareConfig};

cggmp24_tests::test_suite! {
    test: threshold_reshare_works,
    generics: all_curves,
    suites: {
        threshold_refresh_same_roster: (3, Some(2), 3, 2, 3, 3, false),
        threshold_reshare_replace_all: (3, Some(2), 3, 2, 2, 0, false),
        threshold_reshare_retains_one: (3, Some(2), 3, 2, 2, 1, false),
        threshold_reshare_expands_roster: (3, Some(2), 5, 3, 2, 0, false),
        threshold_reshare_overdetermined_dealers: (5, Some(3), 4, 3, 4, 0, false),
        additive_to_threshold_reshare: (3, None, 3, 2, 3, 0, false),
        threshold_reshare_reliable_broadcast: (3, Some(2), 3, 2, 2, 1, true),
    }
}

enum ParticipantSetup<E: generic_ec::Curve> {
    Dealer(IncompleteKeyShare<E>),
    Receiver,
}

fn threshold_reshare_works<E>(
    old_n: u16,
    old_threshold: Option<u16>,
    new_n: u16,
    new_threshold: u16,
    dealer_count: u16,
    retained_count: u16,
    reliable_broadcast: bool,
) where
    E: generic_ec::Curve + cggmp24_tests::CurveParams,
    Point<E>: generic_ec::coords::HasAffineX<E>,
    cggmp24_tests::PrecomputedKeyShares:
        cggmp24_tests::HasAuxOfLevel<<E as cggmp24_tests::CurveParams>::SecurityLevel>,
{
    assert!(dealer_count <= old_n);
    assert!(retained_count <= dealer_count);
    assert!(retained_count <= new_n);

    let source_shares = cggmp24_tests::cached::SHARES
        .get_shares::<E>(old_threshold, old_n, false)
        .into_iter()
        .map(|share| share.core.clone().validate().unwrap())
        .collect::<Vec<_>>();
    let source_public_key = source_shares[0].shared_public_key;

    let old_parties = (0..dealer_count).collect::<Vec<_>>();
    let old_share_indices = (0..dealer_count).collect::<Vec<_>>();
    let new_parties = (0..retained_count)
        .chain(dealer_count..dealer_count + (new_n - retained_count))
        .collect::<Vec<_>>();
    let config = ReshareConfig::new(
        old_parties,
        old_share_indices,
        new_parties.clone(),
        new_threshold,
        source_public_key,
    )
    .expect("valid reshare topology");

    let total_parties = dealer_count + (new_n - retained_count);
    let setups = (0..total_parties)
        .map(|protocol_index| {
            if protocol_index < dealer_count {
                ParticipantSetup::Dealer(source_shares[usize::from(protocol_index)].clone())
            } else {
                ParticipantSetup::Receiver
            }
        })
        .collect::<Vec<_>>();

    let mut rng = rand_dev::DevRng::new();
    let execution_id: [u8; 32] = rng.gen();
    let execution_id = ExecutionId::new(&execution_id);
    let results = round_based::sim::run_with_setup(setups, |protocol_index, party, setup| {
        let party = cggmp24_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let config = config.clone();
        async move {
            let old_share = match &setup {
                ParticipantSetup::Dealer(share) => Some(share),
                ParticipantSetup::Receiver => None,
            };
            run_reshare::<E, _, _, E::SecurityLevel, E::Digest>(
                &mut party_rng,
                party,
                execution_id,
                protocol_index,
                config,
                old_share,
                None,
                reliable_broadcast,
            )
            .await
        }
    })
    .expect("run reshare simulation")
    .expect_ok()
    .into_vec();

    let new_shares = results.into_iter().flatten().collect::<Vec<_>>();
    assert_eq!(new_shares.len(), usize::from(new_n));
    assert_eq!(new_shares[0].shared_public_key, source_public_key);
    assert_eq!(new_shares[0].min_signers(), new_threshold);
    assert!(new_shares.iter().all(|share| share.vss_setup.is_some()));
    validate_keygen_output::<E, cggmp24_tests::HdDisabled>(&mut rng, &new_shares);

    for (position, share) in new_shares.iter().enumerate() {
        assert_eq!(share.i, u16::try_from(position).unwrap());
        assert_eq!(share.shared_public_key, source_public_key);
        assert_eq!(share.min_signers(), new_threshold);
    }
}
