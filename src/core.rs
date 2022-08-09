use async_std::{
    channel::{Receiver, Sender},
};
pub use crate::error::{Error, Result};
use futures::{prelude::*, select};
use libp2p::{
    core::{
        transport::OrTransport,
    },
    dcutr::behaviour::{Behaviour as Dcutr, Event as DcutrEvent},
    gossipsub::{
        Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage,
        IdentTopic, MessageAuthenticity, ValidationMode,
    },
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    identity::{Keypair},
    kad::{
        record::{
            store::{MemoryStore, MemoryStoreConfig},
            Key,
        },
        Kademlia, KademliaConfig, KademliaEvent,
        KademliaStoreInserts, QueryResult,
    },
    multiaddr::{Multiaddr, Protocol},
    ping::{Event as PingEvent, Ping, PingConfig, PingSuccess},
    relay::v2::{
        client::{Client as RelayClient, Event as RelayClientEvent},
        relay::{Config as RelayConfig, Event as RelayEvent, Relay},
    },
    swarm::{
        behaviour::toggle::Toggle,
        Swarm, SwarmEvent,
    },
    tcp::{
        GenTcpConfig, TcpTransport,
    },
    NetworkBehaviour,
    PeerId,
    Transport,
};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, error, info, warn, trace};

#[derive(Debug)]
pub enum Command {
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
    Ping,
    Pong,
    Quit,
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "StampEvent")]
pub struct StampBehavior {
    dcutr: Toggle<Dcutr>,
    gossipsub: Gossipsub,
    identify: Identify,
    kad: Kademlia<MemoryStore>,
    ping: Ping,
    relay_client: Toggle<RelayClient>,
    relay: Toggle<Relay>,
}

#[derive(Debug)]
pub enum StampEvent {
    Dcutr(DcutrEvent),
    Gossipsub(GossipsubEvent),
    Identify(IdentifyEvent),
    Kad(KademliaEvent),
    Ping(PingEvent),
    Relay(RelayEvent),
    RelayClient(RelayClientEvent),
}

impl From<DcutrEvent> for StampEvent {
    fn from(event: DcutrEvent) -> Self {
        Self::Dcutr(event)
    }
}

impl From<GossipsubEvent> for StampEvent {
    fn from(event: GossipsubEvent) -> Self {
        Self::Gossipsub(event)
    }
}

impl From<IdentifyEvent> for StampEvent {
    fn from(event: IdentifyEvent) -> Self {
        Self::Identify(event)
    }
}

impl From<KademliaEvent> for StampEvent {
    fn from(event: KademliaEvent) -> Self {
        Self::Kad(event)
    }
}

impl From<PingEvent> for StampEvent {
    fn from(event: PingEvent) -> Self {
        Self::Ping(event)
    }
}

impl From<RelayEvent> for StampEvent {
    fn from(event: RelayEvent) -> Self {
        Self::Relay(event)
    }
}

impl From<RelayClientEvent> for StampEvent {
    fn from(event: RelayClientEvent) -> Self {
        Self::RelayClient(event)
    }
}

/// Generate a new random peer key.
pub fn random_peer_key() -> Keypair {
    Keypair::generate_ed25519()
}

/// Create our listener/processer for the StampNet node.
#[tracing::instrument(skip(local_key), fields(%public))]
pub fn setup(local_key: Keypair, public: bool) -> Result<Swarm<StampBehavior>> {
    // Create a random PeerId
    let local_pubkey = local_key.public();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local peer id: {:?}", local_peer_id);

    let noise_keys = libp2p::noise::Keypair::<libp2p::noise::X25519Spec>::new()
        .into_authentic(&local_key)?;

    let dcutr = {
        Toggle::from(if public { None } else { Some(Dcutr::new()) })
    };

    // Create a Swarm to manage peers and events
    let gossipsub = {
        // Set a custom gossipsub
        let mut builder = GossipsubConfigBuilder::default();
        builder.validation_mode(ValidationMode::Strict);
        if public {
            builder.do_px();
        }
        let config = builder.build()
            .map_err(|x| Error::Gossip(String::from(x)))?;
        Gossipsub::new(MessageAuthenticity::Signed(local_key), config)
            .map_err(|x| Error::Gossip(String::from(x)))?
    };

    let identify = {
        let config = IdentifyConfig::new("stampnet/1.0.0".into(), local_pubkey)
            .with_push_listen_addr_updates(false);
        Identify::new(config)
    };

    let kad = {
        let store_config = MemoryStoreConfig::default();
        let store = MemoryStore::with_config(local_peer_id.clone(), store_config);
        let mut config = KademliaConfig::default();
        config.set_protocol_name("/stampnet/syncpub/1.0.0".as_bytes());
        config.set_record_filtering(KademliaStoreInserts::Unfiltered);    // FilterBoth to enable filtering
        Kademlia::with_config(local_peer_id.clone(), store, config)
    };

    let ping = {
        let config = PingConfig::new()
            .with_timeout(Duration::new(20, 0))
            .with_max_failures(std::num::NonZeroU32::new(5).unwrap())
            .with_keep_alive(true);
        Ping::new(config)
    };

    let relay = {
        if public {
            info!("setup() -- creating relay behavior");
            let config = RelayConfig::default();
            Toggle::from(Some(Relay::new(local_peer_id.clone(), config)))
        } else {
            Toggle::from(None)
        }
    };

    let (relay_transport, relay_client) = {
        if public {
            (None, Toggle::from(None))
        } else {
            let (relay_transport, relay_client) = RelayClient::new_transport_and_behaviour(local_peer_id.clone());
            (Some(relay_transport), Toggle::from(Some(relay_client)))
        }
    };

    let behavior = StampBehavior {
        dcutr,
        gossipsub,
        identify,
        kad,
        ping,
        relay,
        relay_client,
    };

    let tcp_transport = TcpTransport::new(GenTcpConfig::new().port_reuse(true));
    macro_rules! std_transport {
        ($trans:expr) => {
            {
                $trans
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(libp2p::noise::NoiseConfig::xx(noise_keys).into_authenticated())
                    .multiplex(libp2p::yamux::YamuxConfig::default())
                    .boxed()
            }
        }
    }
    let transport = if let Some(relay_transport) = relay_transport {
        std_transport!(OrTransport::new(relay_transport, tcp_transport))
    } else {
        std_transport!(tcp_transport)
    };
    let swarm = libp2p::swarm::SwarmBuilder::new(transport, behavior, local_peer_id)
        .build();
    Ok(swarm)
}

/// Run our swarm and start talking to StampNet
#[tracing::instrument(skip(swarm, incoming, outgoing))]
pub async fn run(mut swarm: Swarm<StampBehavior>, incoming: Receiver<Command>, outgoing: Sender<Event>) -> Result<()> {
    macro_rules! outgoing {
        ($val:expr) => {
            match outgoing.send($val).await {
                Err(e) => error!("stamp_net::core::run() -- {}:{} -- {:?}", file!(), line!(), e),
                _ => {}
            }
        }
    }
    let mut kad_has_bootstrapped = false;
    loop {
        select! {
            cmd = incoming.recv().fuse() => match cmd {
                Ok(Command::TopicSend { topic: name, message }) => {
                    let topic = IdentTopic::new(name.as_str());
                    let len = message.len();
                    match swarm.behaviour_mut().gossipsub.publish(topic, message) {
                        Ok(msgid) => debug!("gossip: send: {} ({} -- {} bytes)", name, msgid, len),
                        Err(e) => info!("gossip: send: err: {:?}", e),
                    }
                }
                Ok(Command::TopicSubscribe { topic: name }) => {
                    let topic = IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                        Ok(true) => info!("gossip: subscribe: {}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: subscribe: error: {:?}", e),
                    }

                    let key = Key::new(&Vec::from(name.as_bytes()));
                    match swarm.behaviour_mut().kad.start_providing(key.clone()) {
                        Err(e) => {
                            outgoing!{ Event::Error(Error::KadRecord(e)) }
                        }
                        _ => {}
                    }
                    // we catch this on response and add providers
                    swarm.behaviour_mut().kad.get_providers(key.clone());
                }
                Ok(Command::TopicUnsubscribe { topic: name }) => {
                    let topic = IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                        Ok(true) => info!("gossip: unsubscribe: {}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: unsubscribe: error: {:?}", e),
                    }
                }
                Ok(Command::Quit) => {
                    outgoing! { Event::Quit }
                    break;
                }
                _ => {}
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(StampEvent::Identify(IdentifyEvent::Received { peer_id, info })) => {
                    info!("identify: new peer: {} -- {:?} -- {:?}", peer_id, info.listen_addrs, info.protocols);
                    for addr in &info.listen_addrs {
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());
                    }
                    if info.protocols.iter().find(|p| p.contains("/libp2p/circuit/relay")).is_some() {
                        let mut seen: HashSet<Multiaddr> = HashSet::new();
                        for addr in info.listen_addrs.iter() {
                            let has_circuit = addr.iter().find(|m| matches!(m, Protocol::P2pCircuit)).is_some();
                            if has_circuit {
                                continue;
                            }
                            let has_p2p = addr.iter().find(|m| matches!(m, Protocol::P2p(_))).is_some();

                            let addr = addr.clone();
                            let addr = if !has_p2p {
                                addr.with(Protocol::P2p(info.public_key.to_peer_id().as_ref().clone()))
                            } else {
                                addr
                            };
                            let circuit_addr = addr.with(Protocol::P2pCircuit);
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
                SwarmEvent::Behaviour(StampEvent::Gossipsub(GossipsubEvent::Message {message, ..})) => {
                    let GossipsubMessage { source, data, topic, .. } = message;
                    outgoing!{ Event::GossipMessage { peer_id: source, data, topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(GossipsubEvent::Subscribed {topic, ..})) => {
                    outgoing!{ Event::GossipSubscribed { topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Gossipsub(GossipsubEvent::Unsubscribed {topic, ..})) => {
                    outgoing!{ Event::GossipUnsubscribed { topic: topic.into_string() } }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(KademliaEvent::OutboundQueryCompleted {id: _id, result: QueryResult::Bootstrap(Ok(res)), stats: _stats})) => {
                    if res.num_remaining == 0 {
                        info!("kad: bootstrapping complete");
                        outgoing!{ Event::DiscoveryReady }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(KademliaEvent::OutboundQueryCompleted {id: _id, result: QueryResult::GetProviders(Ok(res)), stats: _stats})) => {
                    for provider in res.providers.iter() {
                        if provider == swarm.local_peer_id() {
                            continue;
                        }
                        info!("gossip: add peer from kad: {:?} -- {:?}", res.key, provider);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&provider);
                        let addresses = swarm.connected_peers()
                            .map(|p| {
                                Multiaddr::empty()
                                    .with(Protocol::P2p(p.as_ref().clone()))
                                    .with(Protocol::P2pCircuit)
                                    .with(Protocol::P2p(provider.as_ref().clone()))
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
                SwarmEvent::Behaviour(StampEvent::Ping(ev)) => {
                    match ev.result {
                        Ok(PingSuccess::Ping { .. }) => outgoing!{ Event::Ping },
                        Ok(PingSuccess::Pong) => outgoing!{ Event::Pong },
                        _ => {}
                    }
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

