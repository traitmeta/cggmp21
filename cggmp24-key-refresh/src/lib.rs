//! CGGMP24 key share refresh
//!
//! This crate implements non-threshold refresh from [CGGMP24] Figure 7 and a
//! threshold (`t`-out-of-`n`) reshare protocol whose same-roster form provides
//! proactive refresh. Paillier/Pedersen auxiliary regeneration remains a
//! separate CGGMP24 protocol and must be run by callers when constructing the
//! resulting complete key shares.
//!
//! [CGGMP24]: https://ia.cr/2021/060

#![allow(non_snake_case, clippy::too_many_arguments)]
#![forbid(missing_docs)]
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod errors;
/// Non-threshold (`n`-out-of-`n`) key share refresh
pub mod non_threshold;
/// Threshold (`t`-out-of-`n`) reshare and same-roster refresh
pub mod reshare;
mod utils;

/// Protocol progress tracing
pub mod progress {
    #[doc(inline)]
    pub use cggmp24_keygen::progress::{Event, Tracer};
    #[cfg(feature = "std")]
    pub use cggmp24_keygen::progress::{PerfProfiler, PerfReport, Stderr};
}

/// Security level parameters
pub mod security_level {
    #[doc(inline)]
    pub use cggmp24_keygen::security_level::{
        define_security_level, SecurityLevel, SecurityLevel128, SecurityLevel192,
    };
}

use alloc::vec::Vec;

#[doc(inline)]
pub use key_share::{
    CoreKeyShare as IncompleteKeyShare, DirtyCoreKeyShare as DirtyIncompleteKeyShare, DirtyKeyInfo,
    InvalidCoreShare, Validate,
};

use crate::errors::IoError;
use crate::security_level::SecurityLevel;

pub use self::non_threshold::KeyRefreshOutput;
#[doc(no_inline)]
pub use self::non_threshold::Msg as NonThresholdMsg;
#[doc(no_inline)]
pub use self::reshare::Msg as ReshareMsg;
pub use cggmp24_keygen::ExecutionId;

/// Message types for the non-threshold key refresh protocol
pub mod msg {
    /// Messages for non-threshold (`n`-out-of-`n`) key refresh
    pub mod non_threshold {
        pub use crate::non_threshold::{
            Msg, MsgReliabilityCheck, MsgRound1, MsgRound2, MsgRound3Broadcast, MsgRound3Unicast,
        };
    }
    /// Messages for threshold reshare and same-roster refresh.
    pub mod reshare {
        pub use crate::reshare::{Msg, MsgCommitment, MsgReliability, MsgShare};
    }
}

/// Key refresh protocol error
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[displaydoc("key refresh protocol failed to complete")]
pub struct KeyRefreshError(#[cfg_attr(feature = "std", source)] Reason);

crate::errors::impl_from! {
    impl From for KeyRefreshError {
        err: ProtocolAborted => KeyRefreshError(Reason::Aborted(err)),
        err: IoError => KeyRefreshError(Reason::IoError(err)),
        err: Bug => KeyRefreshError(Reason::Bug(err)),
        err: InvalidArgs => KeyRefreshError(Reason::InvalidArgs(err)),
        err: Reason => KeyRefreshError(err),
    }
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Reason {
    /// Protocol was maliciously aborted by another party
    #[displaydoc("protocol was aborted by malicious party")]
    Aborted(#[cfg_attr(feature = "std", source)] ProtocolAborted),
    #[displaydoc("i/o error")]
    IoError(#[cfg_attr(feature = "std", source)] IoError),
    /// Bug occurred
    #[displaydoc("bug occurred")]
    Bug(#[cfg_attr(feature = "std", source)] Bug),
    /// Invalid arguments were provided
    #[displaydoc("invalid arguments")]
    InvalidArgs(#[cfg_attr(feature = "std", source)] InvalidArgs),
    /// Threshold key share passed to non-threshold refresh
    #[displaydoc("threshold key share is not supported by non-threshold key refresh")]
    NotThreshold,
}

/// Error indicating that caller supplied invalid arguments
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum InvalidArgs {
    #[displaydoc("party index `i` is out of bounds (must be < n)")]
    PartyIndexOutOfBounds,
    #[displaydoc("old party and stored share-index mappings have different lengths")]
    OldRosterMappingLength,
    #[displaydoc("reshare roster is empty or too small")]
    InvalidReshareRoster,
    #[displaydoc("new threshold must satisfy 2 <= t <= n")]
    InvalidNewThreshold,
    #[displaydoc("reshare roster contains duplicate protocol or share indexes")]
    DuplicateReshareIndex,
    #[displaydoc("union transport roster must use contiguous indexes starting at zero")]
    NonContiguousTransportRoster,
    #[displaydoc("old participant did not provide its current key share")]
    MissingOldShare,
    #[displaydoc("non-dealer participant unexpectedly provided an old key share")]
    UnexpectedOldShare,
    #[displaydoc("old key share does not match the configured joint public key")]
    SharedPublicKeyMismatch,
    #[displaydoc("old transport participant does not match the configured stored share index")]
    OldShareIndexMismatch,
    #[displaydoc("selected old dealers do not meet the source threshold")]
    InsufficientOldDealers,
    #[displaydoc("additive source sharing requires the full old roster")]
    AdditiveShareRequiresFullRoster,
    #[displaydoc("selected old share indexes cannot interpolate the source secret")]
    InvalidOldInterpolationSet,
    #[displaydoc("required dealer message is missing")]
    MissingDealerMessage,
    #[cfg(feature = "hd-wallet")]
    #[displaydoc("HD chain code does not match the source share")]
    ChainCodeMismatch,
}

impl From<ProtocolAborted> for Reason {
    fn from(err: ProtocolAborted) -> Self {
        Reason::Aborted(err)
    }
}

/// Error indicating that protocol was aborted by malicious party
#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum ProtocolAborted {
    #[displaydoc("party decommitment doesn't match commitment: {0:?}")]
    InvalidDecommitment(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid masked share: {0:?}")]
    InvalidMaskedShare(Vec<utils::AbortBlame>),
    #[displaydoc("party provided invalid schnorr proof: {0:?}")]
    InvalidSchnorrProof(Vec<utils::AbortBlame>),
    #[displaydoc("round1 wasn't reliable")]
    Round1NotReliable(Vec<utils::AbortBlame>),
    #[displaydoc("dealer sent an invalid resharing commitment: {0:?}")]
    InvalidReshareCommitment(Vec<utils::AbortBlame>),
    #[displaydoc("dealer sent a share inconsistent with its commitment: {0:?}")]
    InvalidReshareShare(Vec<utils::AbortBlame>),
    #[displaydoc("new participants observed inconsistent dealer commitments: {0:?}")]
    ReshareNotReliable(Vec<utils::AbortBlame>),
    #[displaydoc("reshare changed the joint public key")]
    ResharePublicKeyMismatch,
}

#[derive(Debug, displaydoc::Display)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
enum Bug {
    #[displaydoc("resulting key share is not valid")]
    Invalid(#[cfg_attr(feature = "std", source)] InvalidCoreShare),
    #[displaydoc("unexpected zero value")]
    ZeroSecret,
    #[displaydoc("unexpected zero public share")]
    ZeroPublic,
}

macro_rules! make_factory {
    ($function:ident, $variant:ident) => {
        fn $function(parties: Vec<utils::AbortBlame>) -> Self {
            Self::$variant(parties)
        }
    };
}

impl ProtocolAborted {
    make_factory!(invalid_decommitment, InvalidDecommitment);
    make_factory!(invalid_masked_share, InvalidMaskedShare);
    make_factory!(invalid_schnorr_proof, InvalidSchnorrProof);
    make_factory!(round1_not_reliable, Round1NotReliable);
    make_factory!(invalid_reshare_commitment, InvalidReshareCommitment);
    make_factory!(invalid_reshare_share, InvalidReshareShare);
    make_factory!(reshare_not_reliable, ReshareNotReliable);
}
