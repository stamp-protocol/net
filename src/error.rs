//! The main error enum for aux lives here, and documents the various
//! conditions that can arise while interacting with the library.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// An error while engaging in deserialization.
    #[error("ASN.1 deserialization error")]
    ASNDeserialize,

    /// An error while engaging in msgpack serialization.
    #[error("ASN.1 serialization error")]
    ASNSerialize,

    /// An error creating a swarm behavior
    #[error("libp2p behavior error: {0}")]
    // NOTE: cannot figure out how to #[from] this, so just going to stringify it for now...
    BehaviorError(String),

    /// Channel send error
    #[error("channel send: {0}")]
    ChannelSend(String),

    /// Error dialing
    #[error("swarm dial error: {0}")]
    DialError(#[from] libp2p::swarm::DialError),

    /// Gossip error
    #[error("gossip error: {0}")]
    Gossip(String),

    /// Kad bootstrapping error
    #[error("kademlia bootstrap failure")]
    KadBootstrap,

    /// Kad record error
    #[error("kademlia record error: {0}")]
    KadRecord(#[from] libp2p::kad::store::Error),

    /// An IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Noise error
    #[error("noise error: {0}")]
    NoiseError(#[from] libp2p::noise::Error),

    /// An error occured in the Stamp protocol itself
    #[error("stamp error: {0}")]
    Stamp(#[from] stamp_core::error::Error),

    /// A transport error
    #[error("transport error: {0}")]
    Transport(String),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;

