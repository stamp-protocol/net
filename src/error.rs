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

    /// A bad protocol name was given
    #[error("invalid libp2p protocol: {0}")]
    BadProtocol(#[from] libp2p::swarm::InvalidProtocol),

    /// An error creating a swarm behavior
    #[error("libp2p behavior error: {0}")]
    // NOTE: cannot figure out how to #[from] this, so just going to stringify it for now...
    BehaviorError(String),

    /// Channel send error
    #[error("channel send: {0}")]
    ChannelSend(String),

    /// Weird command error
    #[error("command: {0}")]
    CommandGeneric(String),

    /// A command timed out. Sorry. Try a better command.
    #[error("command timed out")]
    CommandTimeout,

    /// Error dialing
    #[error("swarm dial error: {0}")]
    DialError(#[from] libp2p::swarm::DialError),

    /// Error dealing with futures
    #[error("future: {0}")]
    Future(String),

    /// Error dealing with futures
    #[error("future: oneshot: {0}")]
    FutureOneshot(#[from] tokio::sync::oneshot::error::RecvError),

    /// Gossip error
    #[error("gossip error: {0}")]
    Gossip(String),

    /// Identity is invalid
    #[error("invalid identity, must be a PublishV1 transaction")]
    IdentityInvalid,

    /// Kad error
    #[error("kad failure: {0}")]
    Kad(String),

    /// Kad bootstrapping error
    #[error("kademlia bootstrap failure")]
    KadBootstrap,

    /// Kad record error
    #[error("kademlia record error: {0}")]
    KadRecord(#[from] libp2p::kad::store::Error),

    /// Quorum failed while putting a record
    #[error("kademlia quorum failure while storing record")]
    KadPutQuorumFailed,

    /// An IO error
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A noise error
    #[error("noise protocol: {0}")]
    NoiseProtocol(#[from] libp2p::noise::Error),

    /// An error occured in the Stamp protocol itself
    #[error("stamp error: {0}")]
    Stamp(#[from] stamp_core::error::Error),

    /// A transport error
    #[error("transport error: {0}")]
    Transport(String),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;
