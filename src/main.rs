use async_std::{
    channel::{self, Receiver, Sender},
    task,
};
use clap::{Arg, App};
use futures::{prelude::*, select};
use libp2p::{
    core::{
        transport::OrTransport,
        multiaddr::Protocol,
    },
    dcutr::behaviour::{Behaviour as Dcutr, Event as DcutrEvent},
    gossipsub::{
        Gossipsub, GossipsubConfigBuilder, GossipsubEvent,
        IdentTopic, MessageAuthenticity, ValidationMode,
    },
    identify::{Identify, IdentifyConfig, IdentifyEvent},
    identity::{self, Keypair},
    kad::{
        record::{
            store::{MemoryStore, MemoryStoreConfig},
            Key,
        },
        Kademlia, KademliaConfig, KademliaEvent,
        QueryResult,
    },
    ping::{Event as PingEvent, Ping, PingConfig},
    relay::v2::{
        client::{Client as RelayClient, Event as RelayClientEvent},
        relay::{Config as RelayConfig, Event as RelayEvent, Relay},
    },
    swarm::{Swarm, SwarmEvent},
    Multiaddr,
    NetworkBehaviour,
    PeerId,
    Transport,
};
use log::{error, info, warn, trace};
use std::error::Error;
use std::time::Duration;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "StampEvent")]
struct StampBehavior {
    dcutr: Dcutr,
    gossipsub: Gossipsub,
    identify: Identify,
    kad: Kademlia<MemoryStore>,
    ping: Ping,
    relay: Relay,
    relay_client: RelayClient,
}

#[derive(Debug)]
pub enum SError {
    Custom(String),
}

enum Command {
    TopicSend { topic: String, message: Vec<u8> },
    TopicSubscribe { topic: String },
    TopicUnsubscribe { topic: String },
    Quit,
}

#[derive(Debug)]
enum Event {
    Error(SError),
    Quit,
}

#[derive(Debug)]
enum StampEvent {
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

fn setup(local_key: Keypair) -> Result<Swarm<StampBehavior>, Box<dyn Error>> {
    // Create a random PeerId
    let local_pubkey = local_key.public();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local peer id: {:?}", local_peer_id);

    let noise_keys = libp2p::noise::Keypair::<libp2p::noise::X25519Spec>::new()
        .into_authentic(&local_key)?;

    let dcutr = {
        Dcutr::new()
    };

    // Create a Swarm to manage peers and events
    let gossipsub = {
        // Set a custom gossipsub
        let config = GossipsubConfigBuilder::default()
            .validation_mode(ValidationMode::Strict)
            .build()?;
        Gossipsub::new(MessageAuthenticity::Signed(local_key), config)?
    };

    let identify = {
        let config = IdentifyConfig::new("stampnet/1.0.0".into(), local_pubkey)
            .with_push_listen_addr_updates(true);
        Identify::new(config)
    };

    let kad = {
        let store_config = MemoryStoreConfig::default();
        let store = MemoryStore::with_config(local_peer_id.clone(), store_config);
        let mut config = KademliaConfig::default();
        config.set_protocol_name("/stampnet/syncpub/1.0.0".as_bytes());
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
        let config = RelayConfig::default();
        Relay::new(local_peer_id.clone(), config)
    };

    let (relay_transport, relay_client) = {
        RelayClient::new_transport_and_behaviour(local_peer_id.clone())
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

    let tcp_transport = libp2p::tcp::TcpConfig::new()
        .port_reuse(true);
    let transport = OrTransport::new(relay_transport, tcp_transport)
        .upgrade(libp2p::core::upgrade::Version::V1)
        .authenticate(libp2p::noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();

    let swarm = libp2p::swarm::SwarmBuilder::new(transport, behavior, local_peer_id)
        .build();
    Ok(swarm)
}

async fn run(mut swarm: Swarm<StampBehavior>, incoming: Receiver<Command>, outgoing: Sender<Event>) -> Result<(), SError> {
    macro_rules! outgoing {
        ($val:expr) => {
            match outgoing.send($val).await {
                Err(e) => error!("stampnet::run() -- {:?}", e),
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
                        Ok(msgid) => info!("gossip: send: {} ({} -- {} bytes)", name, msgid, len),
                        Err(e) => info!("gossip: send: err: {:?}", e),
                    }
                }
                Ok(Command::TopicSubscribe { topic: name }) => {
                    let topic = IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.subscribe(&topic) {
                        Ok(true) => info!("gossip: subscribe: +{}", name),
                        Ok(false) => {}
                        Err(e) => warn!("gossip: subscribe: error: {:?}", e),
                    }

                    let key = Key::new(&Vec::from(name.as_bytes()));
                    match swarm.behaviour_mut().kad.start_providing(key.clone()) {
                        Err(_e) => {
                            outgoing!{ Event::Error(SError::Custom("failed to start providing topic".into())) }
                        }
                        _ => {}
                    }
                    // we catch this on response and add providers
                    swarm.behaviour_mut().kad.get_providers(key.clone());
                }
                Ok(Command::TopicUnsubscribe { topic: name }) => {
                    let topic = IdentTopic::new(name.as_str());
                    match swarm.behaviour_mut().gossipsub.unsubscribe(&topic) {
                        Ok(true) => info!("gossip: unsubscribe: -{}", name),
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
                    info!("identify: new peer: {} -- {:?}", peer_id, info.listen_addrs);
                    for addr in info.listen_addrs {
                        match swarm.dial(addr.clone()) {
                            Ok(_) => {}
                            Err(err) => {
                                outgoing!{ Event::Error(SError::Custom(format!("identify: new peer: failed to dial: {:?}", err))) }
                            }
                        }
                        swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                    }
                    if !kad_has_bootstrapped {
                        match swarm.behaviour_mut().kad.bootstrap() {
                            Err(_e) => {
                                outgoing!{ Event::Error(SError::Custom("failed to boostrap kad".into())) }
                            }
                            _ => {
                                kad_has_bootstrapped = true;
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Kad(KademliaEvent::OutboundQueryCompleted {id: _id, result: QueryResult::GetProviders(Ok(res)), stats: _stats})) => {
                    for provider in res.providers.iter() {
                        if provider == swarm.local_peer_id() {
                            continue;
                        }
                        info!("gossip: add peer from kad: {:?} -- {:?}", res.key, provider);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&provider);
                        let peers = swarm.connected_peers()
                            .map(|x| x.clone())
                            .collect::<Vec<_>>();
                        for peer in peers {
                            if &peer == provider {
                                continue;
                            }
                            let addr = Multiaddr::empty()
                                .with(Protocol::P2p(peer.as_ref().clone()))
                                .with(Protocol::P2pCircuit)
                                .with(Protocol::P2p(provider.as_ref().clone()));
                            info!("gossip: dialing {:?}", addr);
                            match swarm.dial(addr.clone()) {
                                Ok(_) => {}
                                Err(err) => {
                                    outgoing!{ Event::Error(SError::Custom(format!("gossip: failed to dial {:?}: {:?}", addr, err))) }
                                }
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(StampEvent::Ping(ev)) => {
                    trace!("ping: {:?}", ev);
                }
                SwarmEvent::Behaviour(any) => {
                    info!("oh behave: {:?}", any);
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

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let app = App::new("Stampnet")
        .bin_name("stamp-net")
        .max_term_width(100)
        .about("A stamp net test program")
        .arg(Arg::with_name("listen")
            .short('l')
            .long("listen")
            .takes_value(true)
            .default_value("/ip4/0.0.0.0/tcp/0")
            .help("A MultiAddr listen address"))
        .arg(Arg::with_name("bootstrap")
            .short('b')
            .long("bootstrap")
            .takes_value(true)
            .value_delimiter(',')
            .help("A node to bootstrap with. Separate multiple nodes with a comma (,)"))
        .arg(Arg::with_name("message")
            .short('m')
            .long("message")
            .takes_value(true)
            .help("A message to send on the main topic."))
        .arg(Arg::with_name("message-delay")
            .short('d')
            .long("message-delay")
            .takes_value(true)
            .value_parser(clap::value_parser!(u64))
            .help("A message to send on the main topic."))
        .arg(Arg::with_name("seed")
            .short('s')
            .long("seed")
            .takes_value(true)
            .value_parser(clap::value_parser!(u8))
            .help("A seed value (0-255) to initiate the private key"));
    let args = app.get_matches();
    let listen_addr = args.value_of("listen").expect("listen arg");
    let bootstrap_nodes = args.values_of("bootstrap")
        .map(|b| b.collect::<Vec<_>>())
        .unwrap_or_else(|| Vec::new());
    let message = args.value_of("message");
    let message_delay: u64 = args.get_one("message-delay").map(|x| *x).unwrap_or(15);
    let seed: Option<&u8> = args.get_one("seed");

    fn generate_key(seed: u8) -> Keypair {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;

        let secret_key = identity::ed25519::SecretKey::from_bytes(&mut bytes)
            .expect("this returns `Err` only if the length is wrong; the length is correct; qed");
        Keypair::Ed25519(secret_key.into())
    }

    let local_key = seed
        .map(|s| generate_key(*s))
        .unwrap_or_else(|| Keypair::generate_ed25519());
    let mut swarm = setup(local_key)?;
    swarm.listen_on(listen_addr.parse()?)?;
    for node in bootstrap_nodes {
        let address: Multiaddr = node.parse()?;
        if address.iter().find(|p| p == &Protocol::P2pCircuit).is_none() {
            let circuit_addr = address.clone().with(Protocol::P2pCircuit);
            info!("Creating circuit relay listener: {:?}", circuit_addr);
            swarm.listen_on(circuit_addr)?;
        }
        match swarm.dial(address.clone()) {
            Ok(_) => info!("Dialed {:?}", address),
            Err(e) => error!("Dial {:?} failed: {:?}", address, e),
        };
    }

    let (incoming_send, incoming_recv) = channel::bounded::<Command>(16);
    let (outgoing_send, outgoing_recv) = channel::bounded::<Event>(16);
    let runner = task::spawn(async {
        run(swarm, incoming_recv, outgoing_send).await
    });
    let events = task::spawn(async move {
        loop {
            let event = outgoing_recv.recv().await
                .map_err(|e| SError::Custom(format!("failed to recv event: {:?}", e)))?;
            info!("event: {:?}", event);
            match event {
                Event::Quit => { break; }
                _ => {}
            }
        }
        Ok::<(), SError>(())
    });


    if let Some(msg) = message {
        task::sleep(Duration::from_secs(5)).await;
        incoming_send.send(Command::TopicSubscribe { topic: "chatter".into() }).await?;
        task::sleep(Duration::from_secs(message_delay)).await;
        incoming_send.send(Command::TopicSend { topic: "chatter".into(), message: Vec::from(msg.as_bytes()) }).await?;
    }

    runner.await.map_err(|_| std::io::Error::from_raw_os_error(1))?;
    events.await.map_err(|_| std::io::Error::from_raw_os_error(1))?;
    Ok(())
}
