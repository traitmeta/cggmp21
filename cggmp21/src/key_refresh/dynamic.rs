//! Dynamic reshare protocol for participant replacement
//!
//! This module implements a protocol for resharing keys to a new set of participants
//! while maintaining the same shared public key.
//!
//! ## Protocol Overview
//!
//! Old participants (dealers) redistribute their shares to new participants (receivers)
//! using Feldman VSS. New participants generate Paillier keys and ZK proofs.

use digest::Digest;
use futures::SinkExt;
use generic_ec::{serde::CurveName, Curve, NonZero, Point, Scalar, SecretScalar};

use generic_ec_zkp::schnorr_pok;

use paillier_zk::{
    no_small_factor::non_interactive as π_fac,
    paillier_blum_modulus as π_mod,
    rug::{Complete, Integer},
    IntegerExt,
};
use rand_core::{CryptoRng, RngCore};
use round_based::rounds_router::{simple_store, MessagesStore, RoundsRouter};
use round_based::ProtocolMessage;
use round_based::{Delivery, Incoming, Mpc, MpcParty, MsgId, Outgoing, PartyIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::{Bug, KeyRefreshError, PregeneratedPrimes};

/// A `MessagesStore` that expects messages from a specific subset of parties.
///
/// Unlike `RoundInput`, this store does not assume receiving from `0..n`.
/// It only waits for messages from `expected_senders`.
pub struct SubsetRoundInput<M> {
    expected_senders: HashSet<PartyIndex>,
    received: HashMap<PartyIndex, (M, MsgId)>,
}

impl<M> SubsetRoundInput<M> {
    /// constructing a new `SubsetRoundInput` that expects messages from `expected` parties.
    /// `my_index` is removed from expectations if present.
    pub fn new(expected: impl IntoIterator<Item = PartyIndex>, my_index: PartyIndex) -> Self {
        let mut expected_senders: HashSet<_> = expected.into_iter().collect();
        expected_senders.remove(&my_index);
        Self {
            expected_senders,
            received: Default::default(),
        }
    }
}

impl<M: 'static> MessagesStore for SubsetRoundInput<M> {
    type Msg = M;
    type Output = HashMap<PartyIndex, M>;
    type Error = simple_store::RoundInputError;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if self.expected_senders.contains(&msg.sender) {
            if let Some((_, old_id)) = self.received.get(&msg.sender) {
                return Err(
                    simple_store::RoundInputError::AttemptToOverwriteReceivedMsg {
                        msgs_ids: [*old_id, msg.id],
                        sender: msg.sender,
                    },
                );
            }
            self.received.insert(msg.sender, (msg.msg, msg.id));
        } else {
            // Ignore messages from unexpected senders (or report error)
            // Report error to be safe matching explicit allow list
            return Err(simple_store::RoundInputError::SenderIndexOutOfRange {
                msg_id: msg.id,
                sender: msg.sender,
                n: 0,
            });
        }
        Ok(())
    }

    fn wants_more(&self) -> bool {
        self.received.len() < self.expected_senders.len()
    }

    fn output(self) -> Result<Self::Output, Self> {
        if self.wants_more() {
            Err(self)
        } else {
            Ok(self
                .received
                .into_iter()
                .map(|(k, (v, _))| (k, v))
                .collect())
        }
    }
}
use crate::{
    errors::IoError,
    key_share::{
        AnyKeyShare, DirtyAuxInfo, DirtyIncompleteKeyShare, DirtyKeyInfo, KeyShare, PartyAux,
        Validate,
    },
    progress::Tracer,
    security_level::{SecurityLevel, M},
    utils,
    zk::ring_pedersen_parameters as π_prm,
    ExecutionId,
};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp21.dynamic_reshare.", $name)
    };
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for dynamic reshare protocol
#[derive(Clone, Debug)]
pub struct ReshareConfig<E: Curve> {
    /// Indices of old participants (dealers) — protocol-local positions in the union
    pub old_parties: Vec<u16>,
    /// Indices of new participants (receivers) — protocol-local positions in the union
    pub new_parties: Vec<u16>,
    /// The shared public key (for verification)
    pub shared_public_key: NonZero<Point<E>>,
    /// New threshold for the output shares. None = n_new-of-n_new (all must sign)
    pub new_threshold: Option<u16>,
    /// Stored KeyShare core.i values for each old party, in same order as `old_parties`.
    /// Used for Lagrange x-coordinate lookup: vss_setup.I[old_core_indices[k]].
    /// When old_parties are protocol-local positions that differ from stored core.i,
    /// this field bridges the coordinate space for correct interpolation.
    /// If empty, falls back to using old_parties values directly (backward compatible).
    pub old_core_indices: Vec<u16>,
}

impl<E: Curve> ReshareConfig<E> {
    /// Create a new reshare configuration
    pub fn new(
        old_parties: Vec<u16>,
        new_parties: Vec<u16>,
        shared_public_key: NonZero<Point<E>>,
    ) -> Self {
        Self {
            old_parties,
            new_parties,
            shared_public_key,
            new_threshold: None,
            old_core_indices: Vec::new(),
        }
    }

    /// Create a new reshare configuration with a specific new threshold
    ///
    /// # Panics
    /// Panics if `new_threshold < 2` or `new_threshold > new_parties.len()`
    pub fn with_new_threshold(
        old_parties: Vec<u16>,
        new_parties: Vec<u16>,
        shared_public_key: NonZero<Point<E>>,
        new_threshold: u16,
    ) -> Self {
        assert!(
            new_threshold >= 2,
            "new_threshold must be >= 2, got {}",
            new_threshold
        );
        assert!(
            new_threshold <= new_parties.len() as u16,
            "new_threshold ({}) must be <= n_new ({})",
            new_threshold,
            new_parties.len()
        );
        Self {
            old_parties,
            new_parties,
            shared_public_key,
            new_threshold: Some(new_threshold),
            old_core_indices: Vec::new(),
        }
    }

    /// Effective new threshold: new_threshold if set, otherwise n_new (all must sign)
    pub fn effective_new_threshold(&self) -> u16 {
        self.new_threshold.unwrap_or(self.n_new())
    }

    /// Number of old participants
    pub fn n_old(&self) -> u16 {
        self.old_parties.len() as u16
    }

    /// Number of new participants
    pub fn n_new(&self) -> u16 {
        self.new_parties.len() as u16
    }

    /// Check if a party is an old participant
    pub fn is_old_party(&self, index: u16) -> bool {
        self.old_parties.contains(&index)
    }

    /// Check if a party is a new participant
    pub fn is_new_party(&self, index: u16) -> bool {
        self.new_parties.contains(&index)
    }

    /// Get old party's position in the old_parties list
    pub fn old_party_position(&self, index: u16) -> Option<usize> {
        self.old_parties.iter().position(|&x| x == index)
    }

    /// Get new party's position in the new_parties list
    pub fn new_party_position(&self, index: u16) -> Option<usize> {
        self.new_parties.iter().position(|&x| x == index)
    }
}

// ============================================================================
// Protocol Messages
// ============================================================================

/// Message of dynamic reshare protocol
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
#[allow(clippy::large_enum_variant)]
pub enum Msg<E: Curve, D: Digest, L: SecurityLevel> {
    /// Phase 2 Round 2: Feldman commitment from old parties
    FeldmanCommitment(MsgFeldmanCommitment<E>),
    /// Phase 2 Round 3: Share distribution (P2P from old to new)
    ShareDistribution(MsgShareDistribution<E>),
    /// Phase 2 Round 4: New party auxiliary info
    AuxInfo(MsgAuxInfo<E, L>),
    /// Phase 2 Round 5: Final proofs
    FinalProofs(MsgFinalProofs<E>),
    /// Reliability check message (optional)
    ReliabilityCheck(MsgReliabilityCheck<D>),
}

/// Phase 2 Round 2: Feldman commitment from old parties
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = prefixed!("feldman_commitment"))]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgFeldmanCommitment<E: Curve> {
    /// Feldman commitment: [g^{a_0}, g^{a_1}, ..., g^{a_{n-1}}]
    /// where a_0 = x'_i (refreshed share)
    pub commitment: Vec<Point<E>>,
}

/// Phase 2 Round 3: Share distribution (P2P)
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgShareDistribution<E: Curve> {
    /// Share value s_ij = f_i(j+1)
    pub share: Scalar<E>,
    /// Schnorr proof that share matches commitment
    pub schnorr_proof: schnorr_pok::Proof<E>,
    /// Schnorr commitment
    pub schnorr_commit: schnorr_pok::Commit<E>,
}

/// Phase 2 Round 4: New party auxiliary info
#[derive(Clone, Serialize, Deserialize, udigest::Digestable)]
#[udigest(tag = prefixed!("aux_info"))]
#[udigest(bound = "")]
#[serde(bound = "")]
pub struct MsgAuxInfo<E: Curve, L: SecurityLevel> {
    /// Paillier modulus N = p*q
    #[udigest(as = utils::encoding::Integer)]
    pub N: Integer,
    /// Ring Pedersen parameter s
    #[udigest(as = utils::encoding::Integer)]
    pub s: Integer,
    /// Ring Pedersen parameter t
    #[udigest(as = utils::encoding::Integer)]
    pub t: Integer,
    /// π_prm proof
    pub psi_prm: π_prm::Proof<{ M }>,
    /// Random bytes for collective randomness
    #[serde(with = "hex")]
    #[udigest(as_bytes)]
    pub rho_bytes: L::Rid,
    /// Phantom data for generic E
    pub _phantom: std::marker::PhantomData<E>,
}

/// Phase 2 Round 5: Final proofs
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgFinalProofs<E: Curve> {
    /// π_mod proof
    pub psi_mod: (π_mod::Commitment, π_mod::Proof<{ M }>),
    /// π_fac proof
    pub phi_fac: π_fac::Proof,
    /// New public share Y_j = g^{y_j}
    pub public_share: Point<E>,
    /// Schnorr commitment
    pub schnorr_commit: schnorr_pok::Commit<E>,
    /// Schnorr proof for the new share
    pub schnorr_proof: schnorr_pok::Proof<E>,
}

/// Reliability check message
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliabilityCheck<D: Digest>(pub digest::Output<D>);

// ============================================================================
// Reshare Builder (Unified API)
// ============================================================================

/// Builder for dynamic reshare protocol
pub struct ReshareBuilder<'a, E: Curve, L: SecurityLevel, D: Digest> {
    eid: ExecutionId<'a>,
    i: u16,
    config: ReshareConfig<E>,
    tracer: Option<&'a mut dyn Tracer>,
    reliable_broadcast: bool,
    old_share: Option<&'a KeyShare<E, L>>,
    primes: Option<PregeneratedPrimes<L>>,
    _phantom: std::marker::PhantomData<D>,
}

/// Entry point for dynamic reshare protocol
pub fn reshare<'a, E, L, D>(
    eid: ExecutionId<'a>,
    i: u16,
    config: ReshareConfig<E>,
) -> ReshareBuilder<'a, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    ReshareBuilder::new(eid, i, config)
}

impl<'a, E, L, D> ReshareBuilder<'a, E, L, D>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    /// Create a new reshare builder
    pub fn new(eid: ExecutionId<'a>, i: u16, config: ReshareConfig<E>) -> Self {
        Self {
            eid,
            i,
            config,
            tracer: None,
            reliable_broadcast: true,
            old_share: None,
            primes: None,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set the old key share (Required if you are an Old Participant / Dealer)
    pub fn set_old_share(mut self, share: &'a KeyShare<E, L>) -> Self {
        self.old_share = Some(share);
        self
    }

    /// Set pregenerated primes (Required if you are a New Participant / Receiver)
    pub fn set_pregenerated_primes(mut self, primes: PregeneratedPrimes<L>) -> Self {
        self.primes = Some(primes);
        self
    }

    /// Set progress tracer
    pub fn set_progress_tracer(mut self, tracer: &'a mut dyn Tracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    /// Enforce reliable broadcast (Default: true)
    pub fn enforce_reliable_broadcast(mut self, enforce: bool) -> Self {
        self.reliable_broadcast = enforce;
        self
    }

    /// Start the protocol
    pub async fn start<R, M>(
        mut self,
        rng: &mut R,
        party: M,
    ) -> Result<Option<KeyShare<E, L>>, DynamicReshareError>
    where
        R: RngCore + CryptoRng,
        M: Mpc<ProtocolMessage = Msg<E, D, L>>,
    {
        let is_dealer = self.config.is_old_party(self.i);
        let is_receiver = self.config.is_new_party(self.i);
        let primes = self.primes.take();

        if is_dealer {
            // Dealer role
            let old_share = self
                .old_share
                .ok_or(DynamicReshareError::MissingOldShare(self.i))?;

            run_reshare_as_dealer(
                rng,
                party,
                self.eid,
                old_share,
                self.i,
                self.config,
                primes,
                self.tracer,
                self.reliable_broadcast,
            )
            .await
        } else if is_receiver {
            // Receiver role (New Party only)
            let primes = primes.ok_or(DynamicReshareError::MissingPrimes(self.i))?;

            run_reshare_as_receiver(
                rng,
                party,
                self.eid,
                self.i,
                self.config,
                primes,
                self.tracer,
                self.reliable_broadcast,
            )
            .await
            .map(Some)
        } else {
            Err(DynamicReshareError::InvalidParticipantIndex(self.i))
        }
    }
}

// ============================================================================
// Unambiguous message tags for hashing
// ============================================================================

mod unambiguous {
    use generic_ec::Curve;

    use crate::ExecutionId;

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_prm"))]
    pub struct ProofPrm<'a> {
        pub sid: ExecutionId<'a>,
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_mod"))]
    pub struct ProofMod<'a> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("schnorr_challenge"))]
    pub struct SchnorrChallenge<'a> {
        pub sid: ExecutionId<'a>,
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("proof_fac"))]
    #[udigest(bound = "")]
    pub struct ProofFac<'a> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub rho: &'a [u8],
        pub prover: u16,
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("share_proof"))]
    #[udigest(bound = "")]
    pub struct ShareProof<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub dealer: u16,
        pub receiver: u16,
        pub expected_public_share: generic_ec::Point<E>,
    }
    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("hash_commitment"))]
    #[udigest(bound = "")]
    pub struct HashCommitment<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub party_index: u16,
        pub commitment: &'a [generic_ec::Point<E>],
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Error type for dynamic reshare protocol
#[derive(Debug, thiserror::Error)]
pub enum DynamicReshareError {
    /// configuration mismatch between parties
    #[error("configuration mismatch between parties")]
    ConfigurationMismatch,
    /// invalid Feldman commitment from party
    #[error("invalid Feldman commitment from party {0}")]
    InvalidFeldmanCommitment(u16),
    /// invalid share from dealer
    #[error("invalid share from dealer {0}")]
    InvalidShare(u16),
    /// public key changed after reshare
    #[error("public key changed after reshare")]
    PublicKeyMismatch,
    /// key refresh error
    #[error("key refresh error: {0}")]
    KeyRefreshError(#[source] KeyRefreshError),
    /// i/o error
    #[error("i/o error")]
    IoError(#[source] IoError),
    /// internal bug
    #[error("internal error")]
    InternalError(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// missing old share for dealer
    #[error("missing old share for dealer {0}")]
    MissingOldShare(u16),
    /// missing pregenerated primes for receiver
    #[error("missing pregenerated primes for receiver {0}")]
    MissingPrimes(u16),
    /// invalid participant index
    #[error("invalid participant index {0}")]
    InvalidParticipantIndex(u16),
}

impl From<KeyRefreshError> for DynamicReshareError {
    fn from(err: KeyRefreshError) -> Self {
        DynamicReshareError::KeyRefreshError(err)
    }
}
impl From<IoError> for DynamicReshareError {
    fn from(err: IoError) -> Self {
        DynamicReshareError::IoError(err)
    }
}
impl From<Bug> for DynamicReshareError {
    fn from(err: Bug) -> Self {
        DynamicReshareError::InternalError(Box::new(err))
    }
}

// ============================================================================
// Polynomial utilities
// ============================================================================

struct Polynomial<E: Curve> {
    coefficients: Vec<SecretScalar<E>>,
}

impl<E: Curve> Polynomial<E> {
    fn new_with_secret<R: RngCore + CryptoRng>(
        rng: &mut R,
        secret: &SecretScalar<E>,
        degree: usize,
    ) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(secret.clone());
        for _ in 0..degree {
            coefficients.push(SecretScalar::random(rng));
        }
        Self { coefficients }
    }

    fn evaluate(&self, x: &Scalar<E>) -> Scalar<E> {
        let mut result = Scalar::<E>::zero();
        let mut x_power = Scalar::<E>::one();
        for coeff in &self.coefficients {
            result = result + x_power * coeff.as_ref();
            x_power = x_power * x;
        }
        result
    }

    fn feldman_commit(&self) -> Vec<Point<E>> {
        self.coefficients
            .iter()
            .map(|c| Point::generator() * c.as_ref())
            .collect()
    }
}

fn verify_share_against_commitment<E: Curve>(
    share: &Scalar<E>,
    commitment: &[Point<E>],
    receiver_index: u16,
) -> bool {
    let x = Scalar::<E>::from(receiver_index + 1);
    let mut expected = Point::<E>::zero();
    let mut x_power = Scalar::<E>::one();
    for c in commitment {
        expected = expected + *c * x_power;
        x_power = x_power * x;
    }
    Point::generator() * share == expected
}

// ============================================================================
// Main protocol implementation
// ============================================================================

/// Run dynamic reshare as an old participant (dealer)
///
/// Returns `Some(KeyShare)` if this dealer is also a new participant (retained),
/// otherwise returns `None`.
///
/// # Coordinate spaces
/// - `i_local`: protocol-level index (position in union), used for messaging and role detection
/// - `old_core.i`: stored KeyShare index, used ONLY for vss_setup.I lookup in Lagrange
/// - `config.old_parties` / `config.new_parties`: protocol-local positions
/// - `config.old_core_indices`: maps each old_parties entry to its stored core.i
pub async fn run_reshare_as_dealer<R, M, E, L, D>(
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    old_share: &impl AnyKeyShare<E>,
    i_local: u16,
    config: ReshareConfig<E>,
    pregenerated: Option<PregeneratedPrimes<L>>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
) -> Result<Option<KeyShare<E, L>>, DynamicReshareError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D, L>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    tracer.protocol_begins();

    let old_core = old_share.as_ref();
    let my_core_i = old_core.i; // Only used for vss_setup.I[core.i] lookup

    // Retained detection: use i_local (protocol space) to check new_parties (protocol space)
    // No coordinate bridging needed — both are in the same space.
    let is_retained = config.new_parties.contains(&i_local);

    tracer.stage("Setup networking");
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    // --- Compute Lagrange coefficient (shared by both retained and non-retained paths) ---
    // Position: find ourselves in old_core_indices by matching our stored core.i
    // X-coordinates: vss_setup.I[core_i] for each old party
    let lambda = if let Some(ref vss_setup) = old_core.key_info.vss_setup {
        let core_indices = if !config.old_core_indices.is_empty() {
            &config.old_core_indices
        } else {
            // Backward compat: old_parties values ARE core.i (only true when they match)
            &config.old_parties
        };
        let my_pos = core_indices.iter().position(|&ci| ci == my_core_i);
        if let Some(pos) = my_pos {
            let active_x_coords: Vec<Scalar<E>> = core_indices
                .iter()
                .map(|&ci| {
                    vss_setup
                        .I
                        .get(usize::from(ci))
                        .map(|s| s.into_inner())
                        .unwrap_or_else(|| Scalar::<E>::from(ci + 1))
                })
                .collect();
            generic_ec_zkp::polynomial::lagrange_coefficient_at_zero(pos, &active_x_coords)
                .ok_or(Bug::PartyIndexOutOfBounds)?
                .into_inner()
        } else {
            Scalar::zero()
        }
    } else {
        Scalar::one()
    };

    let secret_ref: &Scalar<E> = old_core.x.as_ref();
    let mut share_scalar = lambda * secret_ref;
    let refreshed_share = SecretScalar::new(&mut share_scalar);

    if !is_retained {
        // Non-retained (leaving) dealer: distribute shares and exit
        tracer.stage("Phase 2: VSS Distribution");
        perform_vss_distribution(
            rng,
            &mut outgoings,
            sid,
            i_local,
            &config,
            refreshed_share,
            None,
            (config.effective_new_threshold() - 1) as usize,
        )
        .await?;

        tracer.protocol_ends();
        return Ok(None);
    }

    // --- Retained party: deal shares AND receive new share ---
    tracer.stage("Phase 2: VSS Distribution");
    let (self_commitment, self_share_msg) = perform_vss_distribution(
        rng,
        &mut outgoings,
        sid,
        i_local,
        &config,
        refreshed_share,
        Some(i_local),
        (config.effective_new_threshold() - 1) as usize,
    )
    .await?;

    let key_share = run_reshare_core(
        rng,
        incomings,
        outgoings,
        sid,
        i_local,
        config,
        pregenerated.ok_or(Bug::PaillierKeyError)?,
        tracer,
        self_share_msg.map(|msg| (i_local, msg)),
        Some(self_commitment),
        reliable_broadcast_enforced,
    )
    .await?;

    Ok(Some(key_share))
}

async fn perform_vss_distribution<R, S, E, L, D, ESend>(
    rng: &mut R,
    outgoings: &mut S,
    sid: ExecutionId<'_>,
    my_old_index: u16,
    config: &ReshareConfig<E>,
    secret: SecretScalar<E>,
    my_new_index_if_retained: Option<u16>,
    polynomial_degree: usize,
) -> Result<(MsgFeldmanCommitment<E>, Option<MsgShareDistribution<E>>), DynamicReshareError>
where
    R: RngCore + CryptoRng,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    S: futures::Sink<Outgoing<Msg<E, D, L>>, Error = ESend> + Unpin,
    ESend: std::error::Error + Send + Sync + 'static,
{
    // Implementation of Polynomial generation and broadcast
    let polynomial = Polynomial::new_with_secret(rng, &secret, polynomial_degree);

    let commitment = polynomial.feldman_commit();
    let msg_commitment = MsgFeldmanCommitment {
        commitment: commitment.clone(),
    };

    outgoings
        .send(Outgoing::broadcast(Msg::FeldmanCommitment(
            msg_commitment.clone(),
        )))
        .await
        .map_err(IoError::send_message)?;

    let mut self_share = None;

    for new_party_idx in &config.new_parties {
        let eval_point = Scalar::<E>::from(new_party_idx + 1);
        let share_value = polynomial.evaluate(&eval_point);

        let (tau, schnorr_commit) = schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);
        let challenge = Scalar::from_hash::<D>(&unambiguous::ShareProof {
            sid,
            dealer: my_old_index,
            receiver: *new_party_idx,
            expected_public_share: Point::generator() * &share_value,
        });
        let challenge = schnorr_pok::Challenge { nonce: challenge };
        let secret_scalar = SecretScalar::<E>::new(&mut share_value.clone());
        let schnorr_proof = schnorr_pok::prove(&tau, &challenge, &secret_scalar);
        let msg = MsgShareDistribution {
            share: share_value,
            schnorr_proof,
            schnorr_commit,
        };

        // Local Loopback Optimization
        // 本地回环优化：如果目标接收者就是我们自己（Retained Party），
        // 我们不通过网络发送，而是直接把份额保存在 self_share 中返回。
        // 这避免了网络死锁和不必要的序列化开销。
        if my_new_index_if_retained == Some(*new_party_idx) {
            self_share = Some(msg);
            continue;
        }

        outgoings
            .feed(Outgoing::p2p(*new_party_idx, Msg::ShareDistribution(msg)))
            .await
            .map_err(IoError::send_message)?;
    }
    outgoings.flush().await.map_err(IoError::send_message)?;

    Ok((msg_commitment, self_share))
}

/// Run dynamic reshare as a new participant (receiver)
pub async fn run_reshare_as_receiver<R, M, E, L, D>(
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    my_new_index: u16,
    config: ReshareConfig<E>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
) -> Result<KeyShare<E, L>, DynamicReshareError>
where
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D, L>>,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
{
    tracer.protocol_begins();
    tracer.stage("Setup networking");

    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, outgoings) = delivery.split();

    run_reshare_core(
        rng,
        incomings,
        outgoings,
        sid,
        my_new_index,
        config,
        pregenerated,
        tracer,
        None,
        None, // No self_commitment for a pure receiver
        reliable_broadcast_enforced,
    )
    .await
}

/// Core receiver logic: Orchestrates the modular phases
async fn run_reshare_core<R, S, I, E, L, D, ESend, ERecv>(
    rng: &mut R,
    incomings: I,
    mut outgoings: S,
    sid: ExecutionId<'_>,
    my_new_index: u16,
    config: ReshareConfig<E>,
    pregenerated: PregeneratedPrimes<L>,
    mut tracer: Option<&mut dyn Tracer>,
    preloaded_share: Option<(u16, MsgShareDistribution<E>)>,
    self_commitment: Option<MsgFeldmanCommitment<E>>,
    reliable_broadcast: bool,
) -> Result<KeyShare<E, L>, DynamicReshareError>
// 核心接收者逻辑：协调模块化的各个阶段
// 1. Setup Rounds (消息路由)
// 2. Phase 1: Aux Setup (Paillier 密钥)
// 3. Phase 2: VSS Reshare (接收分片)
// 4. Phase 3: Final Proofs (最终证明)
// 5. Assemble KeyShare (组装密钥)
where
    R: RngCore + CryptoRng,
    E: Curve,
    L: SecurityLevel,
    D: Digest<OutputSize = digest::typenum::U32> + Clone + 'static,
    S: futures::Sink<Outgoing<Msg<E, D, L>>, Error = ESend> + Unpin,
    I: futures::Stream<Item = Result<round_based::Incoming<Msg<E, D, L>>, ERecv>> + Unpin,
    ESend: std::error::Error + Send + Sync + 'static,
    ERecv: std::error::Error + Send + Sync + 'static,
{
    // Setup rounds
    let mut rounds = RoundsRouter::<Msg<E, D, L>>::builder();

    // We allow receiving from any party for simplicity in this refactor
    let commitment_round = rounds.add_round(SubsetRoundInput::<MsgFeldmanCommitment<E>>::new(
        config.old_parties.iter().copied(),
        my_new_index,
    ));
    let share_round = if let Some((dealer_idx, _)) = preloaded_share {
        let mut expected: HashSet<_> = config.old_parties.iter().copied().collect();
        expected.remove(&dealer_idx);
        rounds.add_round(SubsetRoundInput::<MsgShareDistribution<E>>::new(
            expected,
            my_new_index,
        ))
    } else {
        rounds.add_round(SubsetRoundInput::<MsgShareDistribution<E>>::new(
            config.old_parties.iter().copied(),
            my_new_index,
        ))
    };
    let aux_round = rounds.add_round(SubsetRoundInput::<MsgAuxInfo<E, L>>::new(
        config.new_parties.iter().copied(),
        my_new_index,
    ));
    let proofs_round = rounds.add_round(SubsetRoundInput::<MsgFinalProofs<E>>::new(
        config.new_parties.iter().copied(),
        my_new_index,
    ));
    // reliability check round
    let reliability_round = rounds.add_round(SubsetRoundInput::<MsgReliabilityCheck<D>>::new(
        config.new_parties.iter().copied(),
        my_new_index,
    ));

    let mut rounds = rounds.listen(incomings);

    tracer.stage("Phase 1: Aux Setup");

    // 1. Prepare Aux Info (Paillier keys)
    // 阶段 1：辅助信息建立
    // 新参与者生成 Paillier 密钥 (N, p, q) 和 Ring-Pedersen 参数 (s, t)。
    // 这些参数用于后续的签名协议中的同态加密和零知识证明。
    let PregeneratedPrimes { p, q, .. } = &pregenerated;
    let N = (p * q).complete();
    let phi_N = (p - 1u8).complete() * (q - 1u8).complete();

    let r = Integer::gen_invertible(&N, rng);
    let lambda: Integer = phi_N
        .random_below_ref(&mut utils::external_rand(rng))
        .into();
    let t = r.square().modulo(&N);
    let s = t.pow_mod_ref(&lambda, &N).ok_or(Bug::PowMod)?.into();

    let proof_prm = π_prm::prove::<{ M }, D>(
        &unambiguous::ProofPrm {
            sid,
            prover: my_new_index,
        },
        rng,
        π_prm::Data {
            N: &N,
            s: &s,
            t: &t,
        },
        &phi_N,
        &lambda,
    )
    .map_err(|e| Bug::PiPrm(e))?;

    let mut rho_bytes = L::Rid::default();
    rng.fill_bytes(rho_bytes.as_mut());

    // 2. Broadcast own Aux Info
    let msg = MsgAuxInfo {
        N: N.clone(),
        s: s.clone(),
        t: t.clone(),
        psi_prm: proof_prm,
        rho_bytes: rho_bytes.clone(),
        _phantom: std::marker::PhantomData,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::AuxInfo(msg)))
        .await
        .map_err(IoError::send_message)?;

    // 3. Receive others' Aux Info
    let aux_msgs = rounds
        .complete(aux_round)
        .await
        .map_err(IoError::receive_message)?;

    // 4. Verification
    let mut party_auxes = Vec::new();
    let mut other_rho_bytes = Vec::new();

    for &party_idx in &config.new_parties {
        let aux = if party_idx == my_new_index {
            PartyAux {
                N: N.clone(),
                s: s.clone(),
                t: t.clone(),
                multiexp: None,
                crt: None,
            }
        } else {
            let msg = aux_msgs
                .get(&party_idx)
                .ok_or(DynamicReshareError::InvalidShare(party_idx))?;

            // Verify π_prm
            let data = π_prm::Data {
                N: &msg.N,
                s: &msg.s,
                t: &msg.t,
            };
            π_prm::verify::<{ M }, D>(
                &unambiguous::ProofPrm {
                    sid,
                    prover: party_idx,
                },
                data,
                &msg.psi_prm,
            )
            .map_err(|_| DynamicReshareError::InvalidShare(party_idx))?;

            other_rho_bytes.push(msg.rho_bytes.clone());

            PartyAux {
                N: msg.N.clone(),
                s: msg.s.clone(),
                t: msg.t.clone(),
                multiexp: None,
                crt: None,
            }
        };
        party_auxes.push(aux);
    }
    let mut combined_rho = rho_bytes;
    for other in other_rho_bytes {
        combined_rho = utils::xor_array(combined_rho, &other);
    }
    let verified_auxes = party_auxes;
    let rho_bytes = combined_rho;

    tracer.stage("Phase 2: VSS Reshare");

    let mut commitments = rounds
        .complete(commitment_round)
        .await
        .map_err(IoError::receive_message)?;

    if let (Some(commitment), Some((dealer_index, _))) = (&self_commitment, &preloaded_share) {
        commitments.insert(*dealer_index, commitment.clone());
    }

    // Reliability Check (if enforced)
    if reliable_broadcast {
        tracer.stage("Reliability Check");
        // Hash received commitments
        let h_i = udigest::hash_iter::<D>(commitments.iter().map(|(pid, c)| {
            unambiguous::HashCommitment {
                sid,
                party_index: *pid,
                commitment: &c.commitment,
            }
        }));

        // Broadcast hash
        outgoings
            .send(Outgoing::broadcast(Msg::ReliabilityCheck(
                MsgReliabilityCheck(h_i.clone()),
            )))
            .await
            .map_err(IoError::send_message)?;

        // Receive hashes
        let hashes = rounds
            .complete(reliability_round)
            .await
            .map_err(IoError::receive_message)?;

        // Verify matches
        let parties_have_different_hashes: Vec<_> = hashes
            .iter()
            .filter(|(_pid, msg)| msg.0 != h_i)
            .map(|(pid, _)| *pid)
            .collect();

        if !parties_have_different_hashes.is_empty() {
            return Err(DynamicReshareError::ConfigurationMismatch); // Reuse mismatch for now or add explicit error
        }
    }

    let mut share_msgs = rounds
        .complete(share_round)
        .await
        .map_err(IoError::receive_message)?;

    if let Some((dealer_idx, share)) = preloaded_share {
        // Retained Party 逻辑：手动插入自己的 share。
        share_msgs.insert(dealer_idx, share);
    }

    // Compute the new shared public key from the commitments
    // The shared public key = sum of constant terms (evaluation at x=0)
    let mut computed_public_key = Point::<E>::zero();
    for c in commitments.values() {
        computed_public_key = computed_public_key + c.commitment[0];
    }
    // 验证计算出的公钥是否与配置的共享公钥一致。
    // 这一步确保了所有 Dealer 的常数项之和确实等于原私钥（对应的公钥）。

    if computed_public_key != config.shared_public_key.into_inner() {
        return Err(DynamicReshareError::PublicKeyMismatch);
    }

    // Verify Shares
    for (dealer_idx, share) in &share_msgs {
        let commitment = commitments
            .get(dealer_idx)
            .ok_or(DynamicReshareError::InvalidShare(*dealer_idx))?;

        if !verify_share_against_commitment(&share.share, &commitment.commitment, my_new_index) {
            return Err(DynamicReshareError::InvalidShare(*dealer_idx));
        }
    }

    // Sum Shares
    // 核心步骤：将验证通过的所有份额相加。
    // x_new = sum(s_ji) for all dealers j
    // 由于是加法秘密共享的再共享，所有分片的和即为新的私钥 x_new。
    let new_share: Scalar<E> = share_msgs.values().map(|m| m.share).sum();

    // Compute Public Shares (Y_j) for actual new participants only
    // 只为实际的新参与者计算 public_shares，不填充
    let new_public_shares: Vec<NonZero<Point<E>>> = config
        .new_parties
        .iter()
        .map(|&j| {
            let x = Scalar::<E>::from(j + 1);
            let mut public_share = Point::<E>::zero();

            for c in commitments.values() {
                let mut dealer_contribution = Point::<E>::zero();
                let mut x_power = Scalar::<E>::one();
                for coeff in &c.commitment {
                    dealer_contribution = dealer_contribution + *coeff * x_power;
                    x_power = x_power * x;
                }
                public_share = public_share + dealer_contribution;
            }
            NonZero::from_point(public_share).ok_or(Bug::ZeroShare)
        })
        .collect::<Result<Vec<_>, _>>()?;

    // 使用位置索引访问 public_shares
    let my_position = config
        .new_party_position(my_new_index)
        .ok_or(DynamicReshareError::ConfigurationMismatch)?;
    let my_public_share = *new_public_shares[my_position];
    let secret_share = SecretScalar::new(&mut new_share.clone());
    let public_shares = new_public_shares;

    tracer.stage("Phase 3: Final Proofs");
    // 阶段 3：最终证明
    // 证明我们生成的私钥 x_new 与我们的 Paillier 密钥 N 绑定，
    // 且我们确实知道 x_new 的离散对数。
    let my_aux = &verified_auxes[my_position];
    let N = &my_aux.N;
    let s = &my_aux.s;
    let t = &my_aux.t;

    // Compute π_mod
    let (psi_mod_comm, psi_mod_proof) = π_mod::non_interactive::prove::<{ M }, D>(
        &unambiguous::ProofMod {
            sid,
            rho: rho_bytes.as_ref(),
            prover: my_new_index,
        },
        &π_mod::Data { n: N.clone() },
        &π_mod::PrivateData {
            p: p.clone(),
            q: q.clone(),
        },
        rng,
    )
    .map_err(|e| Bug::PiMod(e))?;

    // Compute π_fac
    let π_fac_security = π_fac::SecurityParams {
        l: L::ELL,
        epsilon: L::EPSILON,
        q: L::q(),
    };
    let n_sqrt = utils::sqrt(&N);
    let phi_fac_proof = π_fac::prove::<D>(
        &unambiguous::ProofFac {
            sid,
            rho: rho_bytes.as_ref(),
            prover: my_new_index,
        },
        &π_fac::Aux {
            s: s.clone(),
            t: t.clone(),
            rsa_modulo: N.clone(),
            multiexp: None,
            crt: None,
        },
        π_fac::Data {
            n: &N,
            n_root: &n_sqrt,
        },
        π_fac::PrivateData { p: &p, q: &q },
        &π_fac_security,
        rng,
    )
    .map_err(|e| Bug::PiFac(e))?;

    // Schnorr Proof
    let (schnorr_secret, schnorr_commit) =
        schnorr_pok::prover_commits_ephemeral_secret::<E, _>(rng);

    let schnorr_challenge = Scalar::<E>::from_hash::<D>(&unambiguous::SchnorrChallenge {
        sid,
        rho: rho_bytes.as_ref(),
        prover: my_new_index,
    });

    let schnorr_proof = schnorr_pok::prove(
        &schnorr_secret,
        &schnorr_pok::Challenge {
            nonce: schnorr_challenge,
        },
        &secret_share, // Proving knowledge of secret share
    );

    // Broadcast Final Proofs (Including public share and commit)
    let msg = MsgFinalProofs {
        psi_mod: (psi_mod_comm, psi_mod_proof),
        phi_fac: phi_fac_proof,
        public_share: my_public_share,
        schnorr_commit,
        schnorr_proof,
    };
    outgoings
        .send(Outgoing::broadcast(Msg::FinalProofs(msg)))
        .await
        .map_err(IoError::send_message)?;

    // Receive and verify final proofs
    let final_msgs = rounds
        .complete(proofs_round)
        .await
        .map_err(IoError::receive_message)?;

    // Verify others
    for (i, party_idx) in config.new_parties.iter().enumerate() {
        if *party_idx == my_new_index {
            continue;
        }

        let msg = final_msgs
            .get(party_idx)
            .ok_or(DynamicReshareError::InvalidShare(*party_idx))?;
        let aux = &verified_auxes[i];

        // Verify π_mod
        π_mod::non_interactive::verify::<{ M }, D>(
            &unambiguous::ProofMod {
                sid,
                rho: rho_bytes.as_ref(),
                prover: *party_idx,
            },
            &π_mod::Data { n: aux.N.clone() },
            &msg.psi_mod.0,
            &msg.psi_mod.1,
        )
        .map_err(|_| DynamicReshareError::InvalidShare(*party_idx))?;

        // Verify π_fac
        let phi_common_aux = π_fac::Aux {
            s: aux.s.clone(),
            t: aux.t.clone(),
            rsa_modulo: aux.N.clone(),
            multiexp: None,
            crt: None,
        };
        π_fac::verify::<D>(
            &unambiguous::ProofFac {
                sid,
                rho: rho_bytes.as_ref(),
                prover: *party_idx,
            },
            &phi_common_aux,
            π_fac::Data {
                n: &aux.N,
                n_root: &utils::sqrt(&aux.N),
            },
            &π_fac_security,
            &msg.phi_fac,
        )
        .map_err(|_| DynamicReshareError::InvalidShare(*party_idx))?;

        // Verify Schnorr
        // Use position-based access since public_shares is not padded
        let party_position = config
            .new_party_position(*party_idx)
            .ok_or(DynamicReshareError::ConfigurationMismatch)?;
        if msg.public_share != public_shares[party_position].into_inner() {
            return Err(DynamicReshareError::InvalidShare(*party_idx));
        }

        let schnorr_challenge = Scalar::<E>::from_hash::<D>(&unambiguous::SchnorrChallenge {
            sid,
            rho: rho_bytes.as_ref(),
            prover: *party_idx,
        });

        if msg
            .schnorr_proof
            .verify(
                &msg.schnorr_commit,
                &schnorr_pok::Challenge {
                    nonce: schnorr_challenge,
                },
                &msg.public_share,
            )
            .is_err()
        {
            return Err(DynamicReshareError::InvalidShare(*party_idx));
        }
    }

    // Assemble KeyShare
    // 组装最终的 KeyShare 结构体
    // 包含：新私钥、共享公钥、所有人的验证参数 (VssSetup) 和这一轮确定的 AuxInfo。
    //
    // 关键设计（position-based）：
    // - i: 使用 my_position（在 new_parties 中的位置索引，0-based），
    //   而非 my_new_index（协议层的 party ID），确保 0 <= i < public_shares.len()
    // - public_shares: 只包含实际参与者，按 new_parties 顺序排列（长度 = n_new）
    // - vss_setup.I: 存储求值点 Scalar(party_id+1)，用于 Lagrange 插值（长度 = n_new）
    // - aux.parties: 按 new_parties 顺序排列（长度 = n_new）
    // - 注意：new_parties 必须是从 0 开始的连续索引（签名协议要求 S[j] < n）
    let new_core_share = DirtyIncompleteKeyShare {
        i: my_position as u16,
        key_info: DirtyKeyInfo {
            curve: CurveName::new(),
            shared_public_key: config.shared_public_key,
            public_shares,
            vss_setup: Some(crate::key_share::VssSetup {
                min_signers: config.effective_new_threshold(),
                // 只包含实际参与者的索引，不填充
                // I 和 public_shares 通过 zip 一一对应
                I: config
                    .new_parties
                    .iter()
                    .map(|&i| NonZero::from_scalar(Scalar::from(i + 1)).expect("non-zero"))
                    .collect(),
            }),
            #[cfg(feature = "hd-wallet")]
            chain_code: None,
        },
        x: NonZero::from_secret_scalar(secret_share).ok_or(Bug::ZeroShare)?,
    }
    .validate()
    .map_err(|err| Bug::InvalidShareGenerated(err.into_error().into()))?;

    // 直接使用 verified_auxes（已按 new_parties 顺序排列），
    // aux.parties[i] 对应位置索引为 i 的参与者
    let final_auxes = verified_auxes;

    let aux = DirtyAuxInfo {
        p: p.clone(),
        q: q.clone(),
        parties: final_auxes,
        security_level: std::marker::PhantomData,
    }
    .validate()
    .map_err(|err| Bug::InvalidShareGenerated(err.into_error()))?;

    let key_share = KeyShare::from_parts((new_core_share, aux))
        .map_err(|err| Bug::InvalidShareGenerated(err.into_error()))?;
    Ok(key_share)
}
