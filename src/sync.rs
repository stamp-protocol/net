//! The sync module allows syncing your private identity across your devices
//! securely.

use async_std::{
    channel::{Receiver, Sender},
};
use crate::{
    error::{Error, Result},
    util,
};
use futures::{prelude::*, select};
use getset;
use rasn::{Encode, Decode, AsnType};
use stamp_core::{
    crypto::key::{SecretKey, SecretKeyNonce, SignKeypair, SignKeypairPublic, SignKeypairSignature},
    dag::{TransactionID, TransactionVersioned},
    util::BinaryVec,
};
use std::fmt;
use std::ops::Deref;
use tracing::{error};

/// An encrypted identity transaction tagged with an unencrypted transaction id.
/// The id can't be trusted, but because private syncing is meant for trusted
/// peers we can 
#[derive(Debug, Clone, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TransactionMessage {
    /// The id of this transaction.
    #[rasn(tag(explicit(0)))]
    id: TransactionID,
    /// Nonce for the encrypted transaction
    #[rasn(tag(explicit(1)))]
    nonce: SecretKeyNonce,
    /// The encrypted [TransactionVersioned][stamp_core::dag::TransactionVersioned]
    #[rasn(tag(explicit(2)))]
    body: BinaryVec,
}

impl TransactionMessage {
    /// Create a new TransactionMessage LOL
    pub fn new(id: TransactionID, nonce: SecretKeyNonce, body: BinaryVec) -> Self {
        Self { id, nonce, body }
    }
}

/// A signed container for a [TransactionMessage]. This allows verification for
/// a transaction message (by blind peers) without being able to decrypt and read
/// the transaction. The idea here is that a blind peer can discard messages that
/// aren't signed by the key derived from the private sync key.
#[derive(Debug, Clone, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TransactionMessageSigned {
    /// The [TransactionMessage].
    #[rasn(tag(explicit(0)))]
    transaction: TransactionMessage,
    /// The signature of the transaction message.
    #[rasn(tag(explicit(1)))]
    signature: SignKeypairSignature,
}

impl TransactionMessageSigned {
    /// Create and sign a new `TransactionMessageSigned`.
    pub fn seal_and_sign(enc_key: &SecretKey, sign_keypair: &SignKeypair, transaction: &TransactionVersioned) -> Result<Self> {
        let transaction_ser = util::serialize(transaction)?;
        let nonce = enc_key.gen_nonce()?;
        let encrypted_trans = enc_key.seal(transaction_ser.as_slice(), &nonce)?;
        let msg = TransactionMessage::new(transaction.id().clone(), nonce, BinaryVec::from(encrypted_trans));
        let msg_ser = util::serialize(&msg)?;
        let sig = sign_keypair.sign(enc_key, msg_ser.as_slice())?;
        Ok(Self {
            transaction: msg,
            signature: sig,
        })
    }

    /// Verify this transaction with a public key.
    pub fn verify(&self, pubkey: &SignKeypairPublic) -> Result<()> {
        let serialized = util::serialize(self.transaction())?;
        pubkey.verify(self.signature(), serialized.as_slice())?;
        Ok(())
    }

    /// Open this sealed transaction. Please use [verify()][verify] before attempting
    /// to open this.
    pub fn open(self, enc_key: &SecretKey) -> Result<TransactionVersioned> {
        let Self { transaction, .. } = self;
        let dec = enc_key.open(transaction.body().deref(), transaction.nonce())?;
        util::deserialize(dec.as_slice())
    }

    /// Turn this signed transaction message into a byte vector
    pub fn serialize(&self) -> Result<Vec<u8>> {
        util::serialize(self)
    }

    /// Turn a byte slice into a signed transaction message
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        util::deserialize(bytes)
    }
}

/// A request for identity transactions
#[derive(Debug, Clone, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct IdentityRequest {
    /// Transactions we already have and don't care about plz don't send ty
    #[rasn(tag(explicit(0)))]
    pub already_have: Vec<TransactionID>,
}

impl IdentityRequest {
    /// Create a new identity request
    pub fn new(already_have: Vec<TransactionID>) -> Self {
        Self { already_have }
    }
}

/// Send a command to the sync runner
#[derive(Debug)]
pub enum Command {
    /// Forwards a command to the core
    Forward(crate::core::Command),
    /// Ask peers for chunks of the identity we may be missing
    RequestIdentity(IdentityRequest),
    /// Quit the loop
    Quit,
    /// Send an (encrypted) identity transaction
    SendTransactions(Vec<TransactionMessageSigned>),
}

/// Sync events we might want to pay attention to
#[derive(Debug)]
pub enum Event {
    /// An error happened
    Error(Error),
    /// We received an (encrypted) identity transaction
    IdentityTransactions(Vec<TransactionMessageSigned>),
    /// Sent out when it might be a good time to ask for transactions
    MaybeRequestIdentity,
    /// Quit signal
    Quit,
    /// Someone wants the (encrypted) transactions in an identity
    RequestIdentity(IdentityRequest),
    /// Let the listener know we've subscribed to our topic
    Subscribed { topic: String },
    /// Let the listener know we've unsubscribed from our topic
    Unsubscribed { topic: String },
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Error(e) => write!(f, "Event::Error({})", e),
            Self::IdentityTransactions(transactions) => {
                write!(f, "Event::IdentityTransactions({} entries)", transactions.len())
            }
            Self::MaybeRequestIdentity => write!(f, "Event::MaybeRequestIdentity"),
            Self::Quit => write!(f, "Event::Quit"),
            Self::RequestIdentity(req) => {
                write!(f, "Event::RequestIdentity({})", req.already_have().len())
            }
            Self::Subscribed { topic } => write!(f, "Event::Subscribed({})", topic),
            Self::Unsubscribed { topic } => write!(f, "Event::Unsubscribed({})", topic),
        }
    }
}

/// This is a message sent between private sync nodes. Note that we never send
/// unencrypted identity transactions over the wire, and we don't deal with decryption
/// in this library. It's up to the [Event] listener to do the Right Thing with
/// whatever key they (don't) have.
#[derive(Debug, Clone, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Message {
    /// Send an identity transaction out to the gossip group
    #[rasn(tag(explicit(0)))]
    IdentityTransactions(Vec<TransactionMessageSigned>),
    /// Request all identity parts from all nodes in the gossip group
    #[rasn(tag(explicit(1)))]
    RequestIdentity(IdentityRequest),
}

/// Wraps the raw core event/command pipeline to add stuff relevant to private
/// syncing.
#[tracing::instrument(skip(channel, sync_pubkey, core_incoming, core_outgoing, sync_incoming, sync_outgoing))]
pub async fn run(channel: &str, sync_pubkey: &SignKeypairPublic, core_incoming: Sender<crate::core::Command>, core_outgoing: Receiver<crate::core::Event>, sync_incoming: Receiver<Command>, sync_outgoing: Sender<Event>) -> Result<()> {
    let channel = String::from(channel);
    macro_rules! sender {
        ($sender:expr, $val:expr) => {
            match $sender.send($val).await {
                Err(e) => error!("stamp_net::sync::run() -- {:?}", e),
                _ => {}
            }
        }
    }
    let mut subscribed = false;
    let topic_name = format!("sync:private:{}", channel);
    loop {
        select! {
            cmd = sync_incoming.recv().fuse() => match cmd {
                Ok(Command::Forward(core_cmd)) => {
                    sender! { core_incoming, core_cmd }
                }
                Ok(Command::Quit) => {
                    sender! { core_incoming, crate::core::Command::Quit }
                }
                Ok(Command::RequestIdentity(req)) => {
                    match util::serialize(&Message::RequestIdentity(req)) {
                        Ok(ser) => {
                            sender!{ core_incoming, crate::core::Command::TopicSend {
                                topic: topic_name.clone(),
                                message: ser,
                            } }
                        }
                        Err(e) => error!("Error serializing identity request: {}", e),
                    }
                }
                Ok(Command::SendTransactions(transactions)) => {
                    let verified = transactions.into_iter()
                        .map(|trans| trans.verify(sync_pubkey).map(|_| trans))
                        .collect::<Result<Vec<_>>>();

                    match verified {
                        Ok(transactions) => {
                            match util::serialize(&Message::IdentityTransactions(transactions)) {
                                Ok(ser) => {
                                    sender!{ core_incoming, crate::core::Command::TopicSend {
                                        topic: topic_name.clone(),
                                        message: ser,
                                    } }
                                }
                                Err(e) => error!("Error serializing transaction message: {}", e),
                            }
                        }
                        Err(e) => error!("Failed to validate outgoing transactions: {}", e),
                    }
                }
                Err(e) => {
                    sender!{ sync_outgoing, Event::Error(Error::ChannelRecv(e)) }
                }
            },
            event = core_outgoing.recv().fuse() => match event {
                Ok(crate::core::Event::DiscoveryReady) => {
                    sender!{ core_incoming, crate::core::Command::TopicSubscribe { topic: topic_name.clone() } }
                }
                Ok(crate::core::Event::Error(e)) => {
                    sender!{ sync_outgoing, Event::Error(e) }
                }
                Ok(crate::core::Event::GossipMessage { peer_id, topic, data }) => {
                    if topic == topic_name {
                        match util::deserialize::<Message>(&data) {
                            Ok(Message::IdentityTransactions(transactions)) => {
                                let verified = transactions.into_iter()
                                    .map(|trans| trans.verify(sync_pubkey).map(|_| trans))
                                    .collect::<Result<Vec<_>>>();
                                match verified {
                                    Ok(transactions) => {
                                        sender!{ sync_outgoing, Event::IdentityTransactions(transactions) }
                                    }
                                    Err(e) => error!("Failed to verify transactions (channel {}): {}", topic_name, e),
                                }
                            }
                            Ok(Message::RequestIdentity(req)) => {
                                sender!{ sync_outgoing, Event::RequestIdentity(req) }
                            }
                            Err(e) => error!("Error deserializing message: {} (from {:?})", e, peer_id),
                        }
                    }
                }
                Ok(crate::core::Event::GossipSubscribed { topic }) => {
                    if topic == topic_name {
                        subscribed = true;
                        sender!{ sync_outgoing, Event::Subscribed { topic } }
                        sender!{ sync_outgoing, Event::MaybeRequestIdentity }
                    }
                }
                Ok(crate::core::Event::GossipUnsubscribed { topic }) => {
                    if topic == topic_name {
                        subscribed = false;
                        sender!{ sync_outgoing, Event::Unsubscribed { topic } }
                    }
                }
                Ok(crate::core::Event::Pong) => {
                    if subscribed {
                        sender!{ sync_outgoing, Event::MaybeRequestIdentity }
                    }
                }
                Ok(crate::core::Event::Quit) => {
                    sender!{ sync_outgoing, Event::Quit }
                    break;
                }
                Err(e) => {
                    sender!{ sync_outgoing, Event::Error(Error::ChannelSend(format!("{}", e))) }
                }
                _ => {}
            },
        }
    }
    Ok::<(), Error>(())
}

