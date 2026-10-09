//! Threshold share reshare and same-roster refresh.
//!
//! The protocol keeps the joint public key unchanged while replacing the
//! polynomial sharing and, optionally, the participant roster or threshold.
//! A threshold refresh is the special case where the old and new rosters are
//! identical.

#![allow(non_snake_case)]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use digest::Digest;
use futures_util::SinkExt;
use generic_ec::{serde::CurveName, Curve, NonZero, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInputError, MessagesStore, RoundsRouter},
    Delivery, Incoming, MessageType, Mpc, MpcParty, MsgId, Outgoing, PartyIndex, ProtocolMessage,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    errors::IoError,
    progress::Tracer,
    security_level::SecurityLevel,
    utils::{self, AbortBlame},
    Bug, DirtyIncompleteKeyShare, DirtyKeyInfo, ExecutionId, IncompleteKeyShare, InvalidArgs,
    KeyRefreshError, ProtocolAborted, Validate,
};

macro_rules! prefixed {
    ($name:tt) => {
        concat!("dfns.cggmp24.reshare.", $name)
    };
}

mod unambiguous {
    use digest::Digest;
    use generic_ec::{Curve, Point};

    use crate::ExecutionId;

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("commitment_view"))]
    #[udigest(bound = "")]
    pub struct CommitmentView<'a, E: Curve> {
        pub sid: ExecutionId<'a>,
        pub dealer: u16,
        pub coefficients: &'a [Point<E>],
    }

    #[derive(udigest::Digestable)]
    #[udigest(tag = prefixed!("reliability"))]
    #[udigest(bound = "")]
    pub struct Reliability<'a, D: Digest> {
        pub sid: ExecutionId<'a>,
        #[udigest(as_bytes)]
        pub commitments_hash: &'a digest::Output<D>,
    }
}

/// A validated mapping between the old dealers, the new receivers, and their
/// protocol-local indexes.
#[derive(Clone, Debug)]
pub struct ReshareConfig<E: Curve> {
    old_parties: Vec<u16>,
    old_share_indices: Vec<u16>,
    new_parties: Vec<u16>,
    new_threshold: u16,
    shared_public_key: NonZero<Point<E>>,
    total_parties: u16,
    #[cfg(feature = "hd-wallet")]
    chain_code: Option<hd_wallet::ChainCode>,
}

impl<E: Curve> ReshareConfig<E> {
    /// Constructs and validates a reshare topology.
    ///
    /// `old_parties` and `new_parties` are indexes in the union transport
    /// roster. `old_share_indices[k]` is the stored key-share index owned by
    /// `old_parties[k]`. The union of both rosters must be exactly `0..n`.
    pub fn new(
        old_parties: Vec<u16>,
        old_share_indices: Vec<u16>,
        new_parties: Vec<u16>,
        new_threshold: u16,
        shared_public_key: NonZero<Point<E>>,
    ) -> Result<Self, KeyRefreshError> {
        if old_parties.len() != old_share_indices.len() {
            return Err(InvalidArgs::OldRosterMappingLength.into());
        }
        if old_parties.is_empty() || new_parties.len() < 2 {
            return Err(InvalidArgs::InvalidReshareRoster.into());
        }
        if new_threshold < 2 || usize::from(new_threshold) > new_parties.len() {
            return Err(InvalidArgs::InvalidNewThreshold.into());
        }

        let old_set = old_parties.iter().copied().collect::<BTreeSet<_>>();
        let old_share_set = old_share_indices.iter().copied().collect::<BTreeSet<_>>();
        let new_set = new_parties.iter().copied().collect::<BTreeSet<_>>();
        if old_set.len() != old_parties.len()
            || old_share_set.len() != old_share_indices.len()
            || new_set.len() != new_parties.len()
        {
            return Err(InvalidArgs::DuplicateReshareIndex.into());
        }

        let union = old_set.union(&new_set).copied().collect::<BTreeSet<_>>();
        let total_parties = union
            .iter()
            .next_back()
            .and_then(|max| max.checked_add(1))
            .ok_or(InvalidArgs::InvalidReshareRoster)?;
        if union.len() != usize::from(total_parties) || union.iter().copied().ne(0..total_parties) {
            return Err(InvalidArgs::NonContiguousTransportRoster.into());
        }

        Ok(Self {
            old_parties,
            old_share_indices,
            new_parties,
            new_threshold,
            shared_public_key,
            total_parties,
            #[cfg(feature = "hd-wallet")]
            chain_code: None,
        })
    }

    /// Constructs a same-roster refresh configuration from an existing share.
    pub fn same_roster(share: &IncompleteKeyShare<E>) -> Result<Self, KeyRefreshError> {
        let parties = (0..share.n()).collect::<Vec<_>>();
        #[allow(unused_mut)]
        let mut config = Self::new(
            parties.clone(),
            parties.clone(),
            parties,
            share.min_signers(),
            share.shared_public_key,
        )?;
        #[cfg(feature = "hd-wallet")]
        {
            config.chain_code = share.chain_code;
        }
        Ok(config)
    }

    /// Associates the public HD-wallet chain code with the output sharing.
    #[cfg(feature = "hd-wallet")]
    pub fn with_chain_code(mut self, chain_code: Option<hd_wallet::ChainCode>) -> Self {
        self.chain_code = chain_code;
        self
    }

    fn is_old_party(&self, i: u16) -> bool {
        self.old_parties.contains(&i)
    }

    fn is_new_party(&self, i: u16) -> bool {
        self.new_parties.contains(&i)
    }

    fn old_share_index(&self, i: u16) -> Option<u16> {
        self.old_parties
            .iter()
            .position(|party| *party == i)
            .map(|position| self.old_share_indices[position])
    }

    fn new_position(&self, i: u16) -> Option<u16> {
        self.new_parties
            .iter()
            .position(|party| *party == i)
            .and_then(|position| position.try_into().ok())
    }
}

/// Message of the threshold reshare protocol.
#[derive(ProtocolMessage, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub enum Msg<E: Curve, D: Digest> {
    /// Feldman polynomial commitment broadcast by an old dealer.
    Commitment(MsgCommitment<E>),
    /// Private polynomial evaluation sent from an old dealer to a new receiver.
    Share(MsgShare<E>),
    /// Echo hash used to detect inconsistent broadcast views.
    Reliability(MsgReliability<D>),
}

/// Feldman commitment to one dealer's resharing polynomial.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgCommitment<E: Curve> {
    /// Public coefficient commitments, from constant term upward.
    pub coefficients: Vec<Point<E>>,
}

/// Private polynomial evaluation for one receiver.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgShare<E: Curve> {
    /// Scalar evaluation of the dealer polynomial at the receiver's new VSS point.
    pub value: Scalar<E>,
}

/// Reliability-check message exchanged by the new roster.
#[serde_as]
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct MsgReliability<D: Digest> {
    /// Hash of the ordered dealer commitment view.
    #[serde_as(as = "utils::HexOrBin")]
    pub hash: digest::Output<D>,
}

struct SubsetRoundInput<M> {
    expected_senders: BTreeSet<PartyIndex>,
    received: BTreeMap<PartyIndex, (MsgId, M)>,
    expected_type: MessageType,
    total_parties: u16,
}

impl<M> SubsetRoundInput<M> {
    fn new(
        expected: impl IntoIterator<Item = PartyIndex>,
        my_index: PartyIndex,
        expected_type: MessageType,
        total_parties: u16,
    ) -> Self {
        let mut expected_senders = expected.into_iter().collect::<BTreeSet<_>>();
        expected_senders.remove(&my_index);
        Self {
            expected_senders,
            received: BTreeMap::new(),
            expected_type,
            total_parties,
        }
    }
}

impl<M: 'static> MessagesStore for SubsetRoundInput<M> {
    type Msg = M;
    type Output = BTreeMap<PartyIndex, (MsgId, M)>;
    type Error = RoundInputError;

    fn add_message(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Self::Error> {
        if msg.msg_type != self.expected_type {
            return Err(RoundInputError::MismatchedMessageType {
                msg_id: msg.id,
                expected: self.expected_type,
                actual: msg.msg_type,
            });
        }
        if !self.expected_senders.contains(&msg.sender) {
            return Err(RoundInputError::SenderIndexOutOfRange {
                msg_id: msg.id,
                sender: msg.sender,
                n: self.total_parties,
            });
        }
        if let Some((old_id, _)) = self.received.get(&msg.sender) {
            return Err(RoundInputError::AttemptToOverwriteReceivedMsg {
                msgs_ids: [*old_id, msg.id],
                sender: msg.sender,
            });
        }
        self.received.insert(msg.sender, (msg.id, msg.msg));
        Ok(())
    }

    fn wants_more(&self) -> bool {
        self.received.len() < self.expected_senders.len()
    }

    fn output(self) -> Result<Self::Output, Self> {
        if self.wants_more() {
            Err(self)
        } else {
            Ok(self.received)
        }
    }
}

struct Polynomial<E: Curve> {
    coefficients: Vec<SecretScalar<E>>,
}

impl<E: Curve> Polynomial<E> {
    fn random_with_constant<R: RngCore + CryptoRng>(
        rng: &mut R,
        constant: SecretScalar<E>,
        degree: usize,
    ) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(constant);
        coefficients.extend((0..degree).map(|_| SecretScalar::random(rng)));
        Self { coefficients }
    }

    fn evaluate(&self, x: Scalar<E>) -> Scalar<E> {
        let mut value = Scalar::zero();
        let mut x_power = Scalar::one();
        for coefficient in &self.coefficients {
            value += coefficient.as_ref() * x_power;
            x_power *= x;
        }
        value
    }

    fn commitment(&self) -> MsgCommitment<E> {
        MsgCommitment {
            coefficients: self
                .coefficients
                .iter()
                .map(|coefficient| Point::generator() * coefficient)
                .collect(),
        }
    }
}

fn validate_local_share<E: Curve>(
    i: u16,
    config: &ReshareConfig<E>,
    old_share: Option<&IncompleteKeyShare<E>>,
) -> Result<(), KeyRefreshError> {
    if !config.is_old_party(i) {
        if old_share.is_some() {
            return Err(InvalidArgs::UnexpectedOldShare.into());
        }
        return Ok(());
    }

    let share = old_share.ok_or(InvalidArgs::MissingOldShare)?;
    if share.shared_public_key != config.shared_public_key {
        return Err(InvalidArgs::SharedPublicKeyMismatch.into());
    }
    if config.old_share_index(i) != Some(share.i) {
        return Err(InvalidArgs::OldShareIndexMismatch.into());
    }
    if config.old_share_indices.len() < usize::from(share.min_signers())
        || config
            .old_share_indices
            .iter()
            .any(|share_index| *share_index >= share.n())
    {
        return Err(InvalidArgs::InsufficientOldDealers.into());
    }
    if share.vss_setup.is_none()
        && (config.old_share_indices.len() != usize::from(share.n())
            || config.old_share_indices.iter().copied().ne(0..share.n()))
    {
        return Err(InvalidArgs::AdditiveShareRequiresFullRoster.into());
    }
    #[cfg(feature = "hd-wallet")]
    if share.chain_code != config.chain_code {
        return Err(InvalidArgs::ChainCodeMismatch.into());
    }
    Ok(())
}

fn dealer_constant<E: Curve>(
    share: &IncompleteKeyShare<E>,
    selected_share_indices: &[u16],
) -> Result<SecretScalar<E>, KeyRefreshError> {
    let coefficient = if let Some(vss) = &share.vss_setup {
        let my_position = selected_share_indices
            .iter()
            .position(|share_index| *share_index == share.i)
            .ok_or(InvalidArgs::OldShareIndexMismatch)?;
        let points = selected_share_indices
            .iter()
            .map(|share_index| vss.I[usize::from(*share_index)].into_inner())
            .collect::<Vec<_>>();
        generic_ec_zkp::polynomial::lagrange_coefficient_at_zero(my_position, &points)
            .ok_or(InvalidArgs::InvalidOldInterpolationSet)?
            .into_inner()
    } else {
        Scalar::one()
    };
    let secret: &Scalar<E> = share.x.as_ref();
    let mut constant = coefficient * secret;
    Ok(SecretScalar::new(&mut constant))
}

fn evaluation_point<E: Curve>(new_position: u16) -> Scalar<E> {
    Scalar::from(new_position + 1)
}

fn commitment_value<E: Curve>(commitment: &MsgCommitment<E>, x: Scalar<E>) -> Point<E> {
    let mut value = Point::zero();
    let mut x_power = Scalar::one();
    for coefficient in &commitment.coefficients {
        value += *coefficient * x_power;
        x_power *= x;
    }
    value
}

fn commitments_hash<E: Curve, D: Digest>(
    sid: ExecutionId<'_>,
    config: &ReshareConfig<E>,
    commitments: &BTreeMap<u16, (MsgId, MsgCommitment<E>)>,
) -> Result<digest::Output<D>, KeyRefreshError> {
    let views = config
        .old_parties
        .iter()
        .map(|dealer| {
            commitments
                .get(dealer)
                .map(|(_, commitment)| unambiguous::CommitmentView {
                    sid,
                    dealer: *dealer,
                    coefficients: &commitment.coefficients,
                })
                .ok_or(InvalidArgs::MissingDealerMessage)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(udigest::hash_iter::<D>(views))
}

/// Runs a t-of-n reshare. Old-only parties return `None`; every member of the
/// new roster returns its new core key share.
///
/// The caller must provide an authenticated, confidential transport for P2P
/// messages. Auxiliary Paillier/Pedersen data is intentionally outside this
/// module; when the new roster changes, callers must generate matching fresh
/// auxiliary information before combining it with the returned core share.
pub async fn run_reshare<E, R, M, L, D>(
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    i: u16,
    config: ReshareConfig<E>,
    old_share: Option<&IncompleteKeyShare<E>>,
    mut tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
) -> Result<Option<IncompleteKeyShare<E>>, KeyRefreshError>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D>>,
{
    if i >= config.total_parties || (!config.is_old_party(i) && !config.is_new_party(i)) {
        return Err(InvalidArgs::PartyIndexOutOfBounds.into());
    }
    validate_local_share(i, &config, old_share)?;

    tracer.protocol_begins();
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = delivery.split();

    let mut own_commitment = None;
    let mut own_share = None;
    if config.is_old_party(i) {
        tracer.stage("Build resharing polynomial");
        let share = old_share.ok_or(InvalidArgs::MissingOldShare)?;
        let constant = dealer_constant(share, &config.old_share_indices)?;
        let polynomial =
            Polynomial::random_with_constant(rng, constant, usize::from(config.new_threshold - 1));
        let commitment = polynomial.commitment();

        tracer.send_msg();
        outgoings
            .send(Outgoing::broadcast(Msg::<E, D>::Commitment(
                commitment.clone(),
            )))
            .await
            .map_err(IoError::send_message)?;
        tracer.msg_sent();

        tracer.stage("Distribute private shares");
        let mut messages = Vec::with_capacity(config.new_parties.len().saturating_sub(1));
        for receiver in config.new_parties.iter().copied() {
            let position = config
                .new_position(receiver)
                .ok_or(InvalidArgs::InvalidReshareRoster)?;
            let message = MsgShare {
                value: polynomial.evaluate(evaluation_point::<E>(position)),
            };
            if receiver == i {
                own_share = Some(message);
            } else {
                messages.push(Outgoing::p2p(receiver, Msg::<E, D>::Share(message)));
            }
        }
        outgoings
            .send_all(&mut futures_util::stream::iter(
                messages.into_iter().map(Ok),
            ))
            .await
            .map_err(IoError::send_message)?;
        own_commitment = Some(commitment);
    }

    if !config.is_new_party(i) {
        outgoings.flush().await.map_err(IoError::send_message)?;
        tracer.protocol_ends();
        return Ok(None);
    }

    let mut rounds = RoundsRouter::<Msg<E, D>>::builder();
    let commitment_round = rounds.add_round(SubsetRoundInput::<MsgCommitment<E>>::new(
        config.old_parties.iter().copied(),
        i,
        MessageType::Broadcast,
        config.total_parties,
    ));
    let share_round = rounds.add_round(SubsetRoundInput::<MsgShare<E>>::new(
        config.old_parties.iter().copied(),
        i,
        MessageType::P2P,
        config.total_parties,
    ));
    let reliability_round = rounds.add_round(SubsetRoundInput::<MsgReliability<D>>::new(
        config.new_parties.iter().copied(),
        i,
        MessageType::Broadcast,
        config.total_parties,
    ));
    let mut rounds = rounds.listen(incomings);

    tracer.receive_msgs();
    let received_commitments = rounds
        .complete(commitment_round)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();
    let mut commitments = received_commitments
        .into_iter()
        .map(|(dealer, (msg_id, message))| (dealer, (msg_id, message)))
        .collect::<BTreeMap<_, _>>();
    if let Some(commitment) = own_commitment {
        commitments.insert(i, (0, commitment));
    }

    let malformed = commitments
        .iter()
        .filter_map(|(dealer, (msg_id, commitment))| {
            (commitment.coefficients.len() != usize::from(config.new_threshold))
                .then_some(AbortBlame::new(*dealer, *msg_id, *msg_id))
        })
        .collect::<Vec<_>>();
    if !malformed.is_empty() {
        return Err(ProtocolAborted::invalid_reshare_commitment(malformed).into());
    }

    let view_hash = commitments_hash::<E, D>(sid, &config, &commitments)?;
    if reliable_broadcast_enforced {
        tracer.stage("Check dealer commitment view");
        let reliability = MsgReliability {
            hash: udigest::hash::<D>(&unambiguous::Reliability::<D> {
                sid,
                commitments_hash: &view_hash,
            }),
        };
        outgoings
            .send(Outgoing::broadcast(Msg::<E, D>::Reliability(
                reliability.clone(),
            )))
            .await
            .map_err(IoError::send_message)?;
        let peer_views = rounds
            .complete(reliability_round)
            .await
            .map_err(IoError::receive_message)?;
        let blame = peer_views
            .into_iter()
            .filter_map(|(sender, (msg_id, message))| {
                (message.hash != reliability.hash)
                    .then_some(AbortBlame::new(sender, msg_id, msg_id))
            })
            .collect::<Vec<_>>();
        if !blame.is_empty() {
            return Err(ProtocolAborted::reshare_not_reliable(blame).into());
        }
    }

    tracer.receive_msgs();
    let received_shares = rounds
        .complete(share_round)
        .await
        .map_err(IoError::receive_message)?;
    tracer.msgs_received();
    let mut shares = received_shares;
    if let Some(share) = own_share {
        shares.insert(i, (0, share));
    }

    let my_position = config
        .new_position(i)
        .ok_or(InvalidArgs::PartyIndexOutOfBounds)?;
    let my_point = evaluation_point::<E>(my_position);
    let invalid_shares = config
        .old_parties
        .iter()
        .filter_map(|dealer| {
            let (share_msg_id, share) = shares.get(dealer)?;
            let (commitment_msg_id, commitment) = commitments.get(dealer)?;
            (Point::generator() * share.value != commitment_value(commitment, my_point))
                .then_some(AbortBlame::new(*dealer, *commitment_msg_id, *share_msg_id))
        })
        .collect::<Vec<_>>();
    if !invalid_shares.is_empty() {
        return Err(ProtocolAborted::invalid_reshare_share(invalid_shares).into());
    }
    if shares.len() != config.old_parties.len() {
        return Err(InvalidArgs::MissingDealerMessage.into());
    }

    let shared_public_key = commitments
        .values()
        .map(|(_, commitment)| commitment.coefficients[0])
        .sum::<Point<E>>();
    if shared_public_key != config.shared_public_key.into_inner() {
        return Err(ProtocolAborted::ResharePublicKeyMismatch.into());
    }

    let new_secret = shares
        .values()
        .map(|(_, share)| share.value)
        .sum::<Scalar<E>>();
    let mut new_secret = new_secret;
    let new_secret =
        NonZero::from_secret_scalar(SecretScalar::new(&mut new_secret)).ok_or(Bug::ZeroSecret)?;

    let public_shares = (0..config.new_parties.len())
        .map(|position| {
            let x = evaluation_point::<E>(
                position
                    .try_into()
                    .map_err(|_| InvalidArgs::InvalidReshareRoster)?,
            );
            let public_share = commitments
                .values()
                .map(|(_, commitment)| commitment_value(commitment, x))
                .sum::<Point<E>>();
            NonZero::from_point(public_share).ok_or(Bug::ZeroPublic.into())
        })
        .collect::<Result<Vec<_>, KeyRefreshError>>()?;

    let share = DirtyIncompleteKeyShare {
        i: my_position,
        x: new_secret,
        key_info: DirtyKeyInfo {
            curve: CurveName::new(),
            shared_public_key: config.shared_public_key,
            public_shares,
            vss_setup: Some(key_share::VssSetup {
                min_signers: config.new_threshold,
                I: (0..config.new_parties.len())
                    .map(|position| {
                        let position: u16 = position
                            .try_into()
                            .map_err(|_| InvalidArgs::InvalidReshareRoster)?;
                        NonZero::from_scalar(evaluation_point::<E>(position))
                            .ok_or(InvalidArgs::InvalidReshareRoster.into())
                    })
                    .collect::<Result<Vec<_>, KeyRefreshError>>()?,
            }),
            #[cfg(feature = "hd-wallet")]
            chain_code: config.chain_code,
        },
    }
    .validate()
    .map_err(|error| Bug::Invalid(error.into_error()))?;

    tracer.protocol_ends();
    Ok(Some(share))
}

/// Runs a proactive refresh for the current roster by invoking the reshare
/// protocol with identical old and new participant sets.
pub async fn run_key_refresh<E, R, M, L, D>(
    rng: &mut R,
    party: M,
    sid: ExecutionId<'_>,
    share: &IncompleteKeyShare<E>,
    tracer: Option<&mut dyn Tracer>,
    reliable_broadcast_enforced: bool,
) -> Result<IncompleteKeyShare<E>, KeyRefreshError>
where
    E: Curve,
    L: SecurityLevel,
    D: Digest + Clone + 'static,
    R: RngCore + CryptoRng,
    M: Mpc<ProtocolMessage = Msg<E, D>>,
{
    let config = ReshareConfig::same_roster(share)?;
    run_reshare::<E, R, M, L, D>(
        rng,
        party,
        sid,
        share.i,
        config,
        Some(share),
        tracer,
        reliable_broadcast_enforced,
    )
    .await?
    .ok_or_else(|| InvalidArgs::MissingDealerMessage.into())
}
