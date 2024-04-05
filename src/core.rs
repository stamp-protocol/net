// NOTE: NResult is required because as of writing this, libp2p doesn't namespace the `Result`
// object in the swarm derive macro, so their Result conflicts with ours.
pub use crate::error::{Error, Result as NResult};
use futures::{prelude::*, select};
use libp2p::{
    Multiaddr, PeerId, Swarm,
    dcutr,
    identify,
    identity::{self, Keypair},
    kad,
    multiaddr,
    ping,
    relay,
    request_response,
    swarm::{
        NetworkBehaviour, SwarmEvent,
        behaviour::toggle::Toggle,
    },
    tcp,
    tls,
    yamux,
};
use stamp_core::{
    dag::{Transaction, TransactionBody},
    identity::IdentityID,
    util::SerdeBinary,
};
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, warn, trace};

/// The max size a published identity can be. above this, we don't store it remotely. You have to
/// store it yourself.
const MAX_PUBLISHED_IDENTITY_SIZE: usize = 1024 * 1024 * 2;

#[derive(Debug)]
pub enum Command {
    DhtGetIdentity { identity_id: IdentityID },
    DhtPutIdentity { identity_id: IdentityID, published: Transaction },
    DhtGetByEmail { email: String },
    DhtPutByEmail { email: String, identity_id: IdentityID },
    DhtGetByName { name: String },
    DhtPutByName { name: String, identity_id: IdentityID },
    TopicSend { topic: String, message: Vec<u8> },
    TopicSubscribe { topic: String },
    TopicUnsubscribe { topic: String },
    Quit,
}

#[derive(Debug)]
pub enum Event {
    DiscoveryReady,
    Error(Error),
    GossipMessage { peer_id: Option<PeerId>, topic: String, data: Vec<u8> },
    GossipSubscribed { topic: String },
    GossipUnsubscribed { topic: String },
    IdentityFound { identity_id: IdentityID, published: Transaction },
    IdentityNotFound(IdentityID),
    IdentityStored(IdentityID),
    Ping,
    Quit,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "StampEvent")]
pub struct StampBehavior {
    dcutr: Toggle<dcutr::Behaviour>,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    ping: ping::Behaviour,
    relay_client: Toggle<relay::client::Behaviour>,
    relay: Toggle<relay::Behaviour>,
    request_response: request_response::Behaviour,
}

#[derive(Debug)]
pub enum StampEvent {
    Dcutr(dcutr::Event),
    Identify(identify::Event),
    Kad(kad::Event),
    Ping(ping::Event),
    Relay(relay::Event),
    RelayClient(relay::client::Event),
    RequestResponse(request_response::Event),
}

impl From<dcutr::Event> for StampEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}

impl From<identify::Event> for StampEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(event)
    }
}

impl From<kad::Event> for StampEvent {
    fn from(event: kad::Event) -> Self {
        Self::Kad(event)
    }
}

impl From<ping::Event> for StampEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl From<relay::Event> for StampEvent {
    fn from(event: relay::Event) -> Self {
        Self::Relay(event)
    }
}

impl From<relay::client::Event> for StampEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}

impl From<request_response::Event> for StampEvent {
    fn from(event: request_response::Event) -> Self {
        Self::RequestResponse(event)
    }
}

/// Generate a new random peer key.
pub fn random_peer_key() -> Keypair {
    Keypair::generate_ed25519()
}

/// Create our listener/processer for the StampNet node.
#[tracing::instrument(skip(local_key), fields(%router_node))]
pub fn setup(local_key: identity::Keypair, router_node: bool) -> NResult<Swarm<StampBehavior>> {
    let local_pubkey = local_key.public();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local peer id: {:?}", local_peer_id);

    let dcutr = {
        Toggle::from(if router_node { None } else { Some(dcutr::Behaviour::new(local_peer_id.clone())) })
    };

    /*
    let gossipsub = {
        let mut builder = gossipsub::ConfigBuilder::default();
        builder.validation_mode(gossipsub::ValidationMode::Strict);
        if router_node {
            builder.do_px();
        }
        let config = builder.build()
            .map_err(|x| Error::Gossip(format!("{}", x)))?;
        gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(local_key.clone()), config)
            .map_err(|x| Error::Gossip(String::from(x)))?
    };
    */

    let identify = {
        let config = identify::Config::new("stampnet/1.0.0".into(), local_pubkey)
            .with_push_listen_addr_updates(false);
        identify::Behaviour::new(config)
    };

    let kad = {
        let store_config = kad::store::MemoryStoreConfig::default();
        let store = kad::store::MemoryStore::with_config(local_peer_id.clone(), store_config);
        let mut config = kad::Config::default();
        config.set_protocol_names(vec![libp2p::StreamProtocol::new("/stampnet/dht/1.0.0")]);
        config.set_record_filtering(kad::StoreInserts::FilterBoth);
        kad::Behaviour::with_config(local_peer_id.clone(), store, config)
    };

    let ping = {
        let config = ping::Config::new();
        ping::Behaviour::new(config)
    };

    let relay = {
        if router_node {
            info!("setup() -- creating relay behavior");
            let config = relay::Config::default();
            Toggle::from(Some(relay::Behaviour::new(local_peer_id.clone(), config)))
        } else {
            Toggle::from(None)
        }
    };

    let mut behavior = StampBehavior {
        dcutr,
        gossipsub,
        identify,
        kad,
        ping,
        relay,
        relay_client: Toggle::from(None),
    };

    let builder = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            tls::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?;
    let swarm = if router_node {
        builder
            .with_behaviour(|_key| Ok(behavior))
            .map_err(|e| Error::BehaviorError(format!("{:?}", e)))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    } else {
        builder
            .with_relay_client(
                tls::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|_key, relay_client| {
                behavior.relay_client = Toggle::from(Some(relay_client));
                Ok(behavior)
            })
            .map_err(|e| Error::BehaviorError(format!("{:?}", e)))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build()
    };
    Ok(swarm)
}

/// Run our swarm and start talking to StampNet
#[tracing::instrument(skip(swarm, incoming, outgoing))]
pub async fn run(mut swarm: Swarm<StampBehavior>, mut incoming: Receiver<Command>, outgoing: Sender<Event>) -> NResult<()> {
    macro_rules! outgoing {
        ($val:expr) => {
            match outgoing.send($val).await {
                Err(e) => error!("stamp_net::core::run() -- {}:{} -- {:?}", file!(), line!(), e),
                _ => {}
            }
        }
    }
    let mut kad_has_bootstrapped = false;
    let mut kad_response_idx: HashMap<kad::QueryId, Command> = HashMap::new();
    loop {
        select! {
            cmd = incoming.recv().fuse() => match cmd {
                Some(Command::DhtGetIdentity { identity_id }) => {
                    let key = kad::RecordKey::new(&format!("/identity/id/{}", identity_id));
                    let qid = swarm.behaviour_mut().kad.get_record(key);
                    kad_response_idx.insert(qid, Command::DhtGetIdentity { identity_id }); 
                }
                Some(Command::DhtPutIdentity { identity_id, published }) => {
                    match published.entry().body() {
                        TransactionBody::PublishV1 { transactions } => {
                            let identity = match transactions.build_identity() {
                                Ok(id) => id,
                                Err(e) => {
                                    warn!("kad: put identity: could not build identity: {}", e);
                                    outgoing!{ Event::Error(e.into()) }
                                    continue;
                                }
                            };
                            match published.verify(Some(&identity)) {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!("kad: put identity: identity transaction did not verify. is it properly signed? -- {}", e);
                                    outgoing!{ Event::Error(e.into()) }
                                    continue;
                                }
                            }
                            let serialized = match published.serialize_binary() {
                                Ok(ser) => ser,
                                Err(e) => {
                                    warn!("kad: put identity: error serializing identity: {}", e);
                                    outgoing!{ Event::Error(e.into()) }
                                    continue;
                                }
                            };
                            if serialized.len() > MAX_PUBLISHED_IDENTITY_SIZE {
                                warn!("kad: put identity: published identity size {} is larger than storage threshold {}, peers will likely not publish and you will have to keep this node up indefinitely.", serialized.len(), MAX_PUBLISHED_IDENTITY_SIZE);
                            }
                            let record = kad::Record::new(Vec::from(format!("/identity/id/{}", identity_id).as_bytes()), serialized);
                            match swarm.behaviour_mut().kad.put_record(record, kad::Quorum::Majority) {
                                Ok(qid) => { kad_response_idx.insert(qid, Command::DhtPutIdentity { identity_id, published }); }
                                Err(e) => {
                                    warn!("kad: put identity: {:?}", e);
                                    outgoing!{ Event::Error(e.into()) }
                                    continue;
                                }
                            }
                        }
                        _ => {
                            warn!("dht: put identity: bad transaction given -- {}", published.id());
                            outgoing!{ Event::Error(Error::IdentityInvalid) }
                        }
                    }
                }
                Some(Command::DhtGetByEmail { email }) => {
                    let key = kad::RecordKey::new(&format!("/identity/email/{}", email));
                    let qid = swarm.behaviour_mut().kad.get_record(key);
                    kad_response_idx.insert(qid, Command::DhtGetByEmail { email }); 
                }
                Some(Command::DhtPutByEmail { email, identity_id }) => {
                    let serialized = Vec::from(identity_id.deref().as_bytes());
                    let record = kad::Record::new(Vec::from(format!("/identity/email/{}", email).as_bytes()), serialized);
                    match swarm.behaviour_mut().kad.put_record(record, kad::Quorum::Majority) {
                        Ok(qid) => { kad_response_idx.insert(qid, Command::DhtPutByEmail { email, identity_id }); }
                        Err(e) => {
                            warn!("kad: put by email: {:?}", e);
                            outgoing!{ Event::Error(e.into()) }
                            continue;
                        }
                    }
                }
                Some(Command::DhtGetByName { name }) => {
                    let key = kad::RecordKey::new(&format!("/identity/name/{}", name));
                    let qid = swarm.behaviour_mut().kad.get_record(key);
                    kad_response_idx.insert(qid, Command::DhtGetByName { name }); 
                }
                Some(Command::DhtPutByName { name, identity_id }) => {
                    let serialized = Vec::from(identity_id.deref().as_bytes());
                    let record = kad::Record::new(Vec::from(format!("/identity/name/{}", name).as_bytes()), serialized);
                    match swarm.behaviour_mut().kad.put_record(record, kad::Quorum::Majority) {
                        Ok(qid) => { kad_response_idx.insert(qid, Command::DhtPutByName { name, identity_id }); }
                        Err(e) => {
                            warn!("kad: put by name: {:?}", e);
                            outgoing!{ Event::Error(e.into()) }
                            continue;
                        }
                    }
                }
                Some(Command::TopicSend { topic: name, message }) => {
                    let topic = gossipsub::IdentTopic::new(name.as_str());
                    let len = message.len();
                    match swarm.behaviour_mut().gossipsub.publish(topic, message) {
                        Ok(msgid) => debug!("gossip: send: {} ({} -- {} bytes)", name, msgid, len),
                        Err(e) => info!("gossip: send: err: {:?}", e),
                    }
                }
                Some(Command::TopicSubscribe { topic: name }) => {
                    let topic = gossipsub::IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                        Ok(true) => info!("gossip: subscribe: {}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: subscribe: error: {:?}", e),
                    }

                    let key = kad::RecordKey::new(&name);
                    match swarm.behaviour_mut().kad.start_providing(key.clone()) {
                        Err(e) => {
                            outgoing!{ Event::Error(Error::KadRecord(e)) }
                        }
                        _ => {}
                    }
                    // we catch this on response and add providers
                    let qid = swarm.behaviour_mut().kad.get_providers(key);
                    kad_response_idx.insert(qid, Command::TopicSubscribe { topic: name }); 
                }
                Some(Command::TopicUnsubscribe { topic: name }) => {
                    let topic = gossipsub::IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                        Ok(true) => info!("gossip: unsubscribe: {}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: unsubscribe: error: {:?}", e),
                    }
                }
                Some(Command::Quit) => {
                    outgoing! { Event::Quit }
                    break;
                }
                _ => {}
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(StampEvent::Identify(identify::Event::Received { peer_id, info })) => {
                    info!("identify: new peer: {} -- {:?} -- {:?}", peer_id, info.listen_addrs, info.protocols);
                    for addr in &info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }
                    if info.protocols.iter().find(|p| p.as_ref().contains("/libp2p/circuit/relay")).is_some() {
                        let mut seen: HashSet<Multiaddr> = HashSet::new();
                        for addr in info.listen_addrs.iter() {
                            let has_circuit = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2pCircuit)).is_some();
                            if has_circuit {
                                continue;
                            }
                            let has_p2p = addr.iter().find(|m| matches!(m, multiaddr::Protocol::P2p(_))).is_some();

                            let addr = addr.clone();
                            let addr = if !has_p2p {
                                addr.with(multiaddr::Protocol::P2p(info.public_key.to_peer_id().clone()))
                            } else {
                                addr
                            };
                            let circuit_addr = addr.with(multiaddr::Protocol::P2pCircuit);
                            if seen.contains(&circuit_addr) {
                                continue;
                            }
                            if swarm.listeners().find(|l| *l == &circuit_addr).is_some() {
                                continue;
                            }
                            info!("Creating circuit relay listener: {:?}", circuit_addr);
                            match swarm.listen_on(circuit_addr.clone()) {
                                Ok(_) => {}
                                Err(e) => {
                                    outgoing!{ Event::Error(Error::Transport(format!("{}", e))) }
                                }
                            }
                            seen.insert(circuit_addr);
                        }
                    }
                    if !kad_has_bootstrapped {
                        match swarm.behaviour_mut().kad.bootstrap() {
                            Err(_) => {
                                outgoing!{ Event::Error(Error::KadBootstrap) }
                            }
                            _ => {
                                kad_has_bootstrapped = true;
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(gossipsub::Event::Message {message, ..})) => {
                    let gossipsub::Message { source, data, topic, .. } = message;
                    outgoing!{ Event::GossipMessage { peer_id: source, data, topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(gossipsub::Event::Subscribed {topic, ..})) => {
                    outgoing!{ Event::GossipSubscribed { topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(gossipsub::Event::Unsubscribed {topic, ..})) => {
                    outgoing!{ Event::GossipUnsubscribed { topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::OutboundQueryProgressed {id: _id, result: kad::QueryResult::Bootstrap(Ok(res)), step: _step, stats: _stats})) => {
                    if res.num_remaining == 0 {
                        info!("kad: bootstrapping complete");
                        outgoing!{ Event::DiscoveryReady }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(kad::Event::OutboundQueryProgressed {id: qid, result, step: _step, stats: _stats})) => {
                    match kad_response_idx.get(&qid) {
                        Some(cmd) => {
                            match (cmd, result) {
                                (Command::DhtGetIdentity { identity_id }, kad::QueryResult::GetRecord(rec_res)) => {
                                    match rec_res {
                                        Ok(kad::GetRecordOk::FoundRecord(record)) => {
                                            let published = match Transaction::deserialize_binary(record.record.value.as_slice()) {
                                                Ok(trans) => trans,
                                                Err(e) => {
                                                    outgoing! { Event::Error(e.into()) }
                                                    continue;
                                                }
                                            };
                                            match published.entry().body() {
                                                TransactionBody::PublishV1 { transactions } => {
                                                    let identity = match transactions.build_identity() {
                                                        Ok(id) => id,
                                                        Err(e) => {
                                                            warn!("kad: get identity: could not build identity {}: {}", identity_id, e);
                                                            outgoing!{ Event::Error(e.into()) }
                                                            continue;
                                                        }
                                                    };
                                                    match published.verify(Some(&identity)) {
                                                        Ok(_) => {}
                                                        Err(e) => {
                                                            warn!("kad: get identity: identity transaction for {} did not verify. is it properly signed? -- {}", identity_id, e);
                                                            outgoing!{ Event::Error(e.into()) }
                                                            continue;
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                            outgoing! { Event::IdentityFound{ identity_id: identity_id.clone(), published } };
                                        }
                                        Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                                            outgoing! { Event::IdentityNotFound(identity_id.clone()) };
                                        }
                                        Err(e) => {
                                            outgoing! { Event::Error(Error::Kad(format!("kad: get identity: {}", e))) };
                                        }
                                    }
                                }
                                (Command::DhtPutIdentity { identity_id, .. }, kad::QueryResult::PutRecord(put_res)) => {
                                    match put_res {
                                        Ok(..) => {
                                            outgoing! { Event::IdentityStored(identity_id.clone()) };
                                        }
                                        Err(e) => {
                                            outgoing! { Event::Error(Error::Kad(format!("kad: put identity: {}", e))) };
                                        }
                                    }
                                }
                                (Command::TopicSubscribe { .. }, kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { key, providers }))) => {
                                    for provider in providers.iter() {
                                        if provider == swarm.local_peer_id() {
                                            continue;
                                        }
                                        info!("gossip: add peer from kad: {:?} -- {:?}", key, provider);
                                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&provider);
                                        let addresses = swarm.connected_peers()
                                            .map(|p| {
                                                Multiaddr::empty()
                                                    .with(multiaddr::Protocol::P2p(p.clone()))
                                                    .with(multiaddr::Protocol::P2pCircuit)
                                                    .with(multiaddr::Protocol::P2p(provider.clone()))
                                            })
                                        .collect::<Vec<_>>();
                                        for addr in addresses {
                                            info!("gossip: dialing {:?}", addr);
                                            match swarm.dial(addr.clone()) {
                                                Ok(_) => {}
                                                Err(e) => {
                                                    outgoing!{ Event::Error(Error::DialError(e)) }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        None => {}
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Ping(ev)) => {
                    outgoing!{ Event::Ping }
                    trace!("ping: {:?}", ev);
                }
                SwarmEvent::Behaviour(any) => {
                    info!("swarm event: {:?}", any);
                }
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    info!("swarm: connection opened: {} -- {:?}", peer_id, endpoint);
                }
                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    info!("swarm: connection closed: {} -- {:?}", peer_id, cause);
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {:?}", address);
                }
                _ => {}
            },
        }
    }
    Ok(())
}

