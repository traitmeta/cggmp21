use generic_ec::Point;
use rand::Rng;
use sha2::Sha256;

use cggmp21::key_refresh::dynamic::{reshare, ReshareConfig};
use cggmp21::key_refresh::PregeneratedPrimes;
use cggmp21::{security_level::SecurityLevel128, ExecutionId, KeyShare};

cggmp21_tests::test_suite! {
    test: dynamic_reshare_works,
    generics: all_curves,
    suites: {
        // Existing: additive (n-of-n) reshare
        n3_replace_all: (3, 3, false, 0, None, None, None),
        n3_overlap_1: (3, 3, false, 1, None, None, None),
        n2_to_n3: (2, 3, false, 0, None, None, None),
        // Threshold reshare: same group size
        t2n3_to_t2n3: (3, 3, false, 0, Some(2), Some(2), None),
        t2n3_to_n3: (3, 3, false, 0, Some(2), None, None),
        n3_to_t2n3: (3, 3, false, 0, None, Some(2), None),
        // Threshold reshare: expand group
        t2n3_to_t2n4: (3, 4, false, 0, Some(2), Some(2), None),
        // Threshold reshare: shrink group
        t2n3_to_t2n2: (3, 2, false, 0, Some(2), Some(2), None),
        // More than t old parties participating (overdetermined Lagrange)
        t3n5_4_old_to_t3n5: (5, 5, false, 0, Some(3), Some(3), Some(4)),
    }
}

/// Setup data for a party in the reshare simulation
enum PartySetup<E: generic_ec::Curve + Unpin> {
    Dealer {
        old_share: KeyShare<E, SecurityLevel128>,
        primes: Option<PregeneratedPrimes<SecurityLevel128>>,
    },
    Receiver {
        my_new_index: u16,
        primes: PregeneratedPrimes<SecurityLevel128>,
    },
}

fn dynamic_reshare_works<E: generic_ec::Curve + Unpin>(
    n_old: u16,
    n_new: u16,
    reliable_broadcast: bool,
    _overlap_count: u16,
    old_threshold: Option<u16>,
    new_threshold: Option<u16>,
    old_participants: Option<u16>,
) where
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    // 1. Get initial shares for old parties
    // If old_threshold is set, fetch threshold shares; otherwise fetch additive shares
    let old_shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(old_threshold, n_old, true)
        .expect("retrieve cached shares");

    // Determine how many old parties participate:
    // - old_participants overrides (for testing overdetermined Lagrange)
    // - otherwise old_threshold (exactly t parties)
    // - otherwise n_old (all parties, for additive shares)
    let participating_count = old_participants
        .or(old_threshold)
        .unwrap_or(n_old);
    let old_parties: Vec<u16> = (0..participating_count).collect();

    // New parties MUST use consecutive indices starting from 0
    // This is a requirement of cggmp21's VSS design
    let new_parties: Vec<u16> = (0..n_new).collect();

    // shared_public_key is already NonZero<Point<E>>
    let shared_public_key = old_shares[0].core.shared_public_key;
    let config = if let Some(nt) = new_threshold {
        ReshareConfig::with_new_threshold(
            old_parties.clone(),
            new_parties.clone(),
            shared_public_key,
            nt,
        )
    } else {
        ReshareConfig::new(old_parties.clone(), new_parties.clone(), shared_public_key)
    };

    let mut primes = cggmp21_tests::CACHED_PRIMES.iter::<SecurityLevel128>();

    // Create setup for all parties
    let mut party_setups: Vec<PartySetup<E>> = Vec::new();

    // Old parties (dealers) — only the participating ones
    for &old_idx in &old_parties {
        let share = old_shares[old_idx as usize].clone();
        let primes = if new_parties.contains(&old_idx) {
            Some(
                primes
                    .next()
                    .expect("Can't fetch primes for retained party"),
            )
        } else {
            None
        };
        party_setups.push(PartySetup::Dealer {
            old_share: share,
            primes,
        });
    }

    // New parties (receivers)
    for new_idx in &new_parties {
        // If new_idx is also an old party, skip creating a separate Receiver setup
        // because the Dealer setup for that index will handle both roles (Retained Party logic).
        if old_parties.contains(new_idx) {
            continue;
        }
        party_setups.push(PartySetup::Receiver {
            my_new_index: *new_idx,
            primes: primes.next().expect("Can't fetch primes"),
        });
    }

    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    // 2. Run Reshare
    let results: Vec<Option<KeyShare<E, SecurityLevel128>>> =
        round_based::sim::run_with_setup(party_setups, |_i, party, setup| {
            let party = cggmp21_tests::buffer_outgoing(party);
            let mut party_rng = rng.fork();
            let config = config.clone();

            async move {
                let (i, old_share, primes) = match setup {
                    PartySetup::Dealer { old_share, primes } => {
                        (old_share.core.i, Some(old_share), primes)
                    }
                    PartySetup::Receiver {
                        my_new_index,
                        primes,
                    } => (my_new_index, None, Some(primes)),
                };

                let mut builder = reshare::<E, SecurityLevel128, Sha256>(eid, i, config);
                if let Some(share) = &old_share {
                    builder = builder.set_old_share(share);
                }
                if let Some(primes) = primes {
                    builder = builder.set_pregenerated_primes(primes);
                }
                builder
                    .enforce_reliable_broadcast(reliable_broadcast)
                    .start(&mut party_rng, party)
                    .await
                    .unwrap()
            }
        })
        .unwrap()
        .into_vec();

    // Filter out None results (from pure dealers)
    let new_key_shares: Vec<_> = results.into_iter().filter_map(|x| x).collect();

    assert_eq!(new_key_shares.len(), n_new as usize);

    // 3. Verify new shares
    for (idx, key_share) in new_key_shares.iter().enumerate() {
        assert_eq!(key_share.core.shared_public_key, shared_public_key);
        // Verify index matches (idx in new_key_shares corresponds to order in new_parties, but key_share.i is absolute)
        // new_parties[idx] should be key_share.i
        assert_eq!(new_parties[idx], key_share.core.i);
    }

    // 4. Verify signing with new shares
    // If new_threshold is set, only use t' signers; otherwise use all
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);

    let signing_count = new_threshold.unwrap_or(n_new);
    let signers: Vec<u16> = new_parties.iter().take(signing_count as usize).cloned().collect();
    let signing_shares: Vec<_> = new_key_shares
        .iter()
        .filter(|s| signers.contains(&s.core.i))
        .collect();

    let sig = round_based::sim::run_with_setup(&signing_shares, |_, party, share| {
        let party = cggmp21_tests::buffer_outgoing(party);
        let mut party_rng = rng.fork();
        let signers = signers.clone();
        async move {
            cggmp21::signing(eid, share.core.i, &signers, share)
                .enforce_reliable_broadcast(reliable_broadcast)
                .sign(&mut party_rng, party, message_to_sign)
                .await
        }
    })
    .unwrap()
    .expect_ok()
    .expect_eq();

    sig.verify(&shared_public_key, &message_to_sign)
        .expect("signature is not valid");
}
