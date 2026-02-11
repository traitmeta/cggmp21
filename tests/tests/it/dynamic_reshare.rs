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
        n3_replace_all: (3, 3, false, 0),
        n3_overlap_1: (3, 3, false, 1),
        n2_to_n3: (2, 3, false, 0),
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
) where
    Point<E>: generic_ec::coords::HasAffineX<E>,
{
    let mut rng = rand_dev::DevRng::new();

    // 1. Get initial shares for old parties
    let old_shares = cggmp21_tests::CACHED_SHARES
        .get_shares::<E, SecurityLevel128>(None, n_old, true)
        .expect("retrieve cached shares");

    let old_parties: Vec<u16> = (0..n_old).collect();
    // New parties MUST use consecutive indices starting from 0
    // This is a requirement of cggmp21's VSS design
    let new_parties: Vec<u16> = (0..n_new).collect();

    // shared_public_key is already NonZero<Point<E>>
    let shared_public_key = old_shares[0].core.shared_public_key;
    let config = ReshareConfig::new(old_parties.clone(), new_parties.clone(), shared_public_key);

    let mut primes = cggmp21_tests::CACHED_PRIMES.iter::<SecurityLevel128>();

    // Create setup for all parties
    let mut party_setups: Vec<PartySetup<E>> = Vec::new();

    // Old parties (dealers)
    for (_i, share) in old_shares.iter().enumerate() {
        let old_id = share.core.i;
        let primes = if new_parties.contains(&old_id) {
            Some(
                primes
                    .next()
                    .expect("Can't fetch primes for retained party"),
            )
        } else {
            None
        };
        party_setups.push(PartySetup::Dealer {
            old_share: share.clone(),
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
    let eid: [u8; 32] = rng.gen();
    let eid = ExecutionId::new(&eid);

    let message_to_sign = cggmp21::signing::DataToSign::digest::<Sha256>(&[42; 100]);

    let signers = new_parties.clone();

    let sig = round_based::sim::run_with_setup(&new_key_shares, |_, party, share| {
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
