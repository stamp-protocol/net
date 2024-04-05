# Stamp net notes

Need to collect my thoughts.

## Blueprint

- All syncing uses req-response pattern
- Stamp net handles:
  - Discovery
  - Efficient syncing (N or M peers etc)
  - Local API
    - join topic
    - leave topic
    - query transactions
    - send message to topic
    - get identity by id
    - store identity by id
  - Signaling remote events to local handlers
  - (Relay) joins certain topics on request
    - Topic whitelist/blacklist
    - Identity whitelist/blacklist
      - identity ID
      - stamp from identity ID
- Stamp net does not handle:
  - Storage (aux et al handles this)
  - verification of messages

## Modes:

- Private
  - Default mode
  - Provides no services other than req/res
  - Participates in Kad if IP is public
- Relay
  - Participates as Kad server
  - Provides DCUTR/NAT traversal
  - Advertises itself as a relay in Kad

-----------------


## Sync

This works using a pre-shared key between devices, allowing them to securely communicate.
The pre-shared key is used to derive a keypair, which is used to sign the sync transactions
so they can be verified.

Sync messages are encrypted via the pre-shared key, and the encrypted body is stored in an
`ExtV1` payload, with the inner `TransactionID` set in `context.transaction_id`, allowing
for querying/routing without being able to decrypt the transaction.

One or more "routers" can be specified when starting the sync process. Routers store messages
for offline nodes with some retention setting. The router acts like a sync node, however it
cannot decrypt messages, only store and forward them to authorized nodes.

Nodes in the Sync protocol, including router nodes, use the request-response pattern as
gossipsub privacy cannot be guaranteed. Discovery is achieved via Kad.

## Net

## Share


-----------------

## Sync

A generic way of syncing transactions between nodes *selectively*.

Can this be done in a general sense?

### Syncing private identity transactions

- Transactions wrapped in `ExtV1` with the payload being an encrypted stamp trans *and*
  `context.transaction_id` being set to the inner transaction.
- Signed by some kind of dedicated syncing key that is shared with recipients (ie, user-
  owned devices) directly.
- Can use public-only key for allowing untrusted sync between intermittent nodes.

### Syncing arbitrary transactions

- Predicated on *public* identity syncing between nodes, ie all
  nodes will have (public) knowledge of identities involved.
  - Could be solved by StampNet. Keep dreaming tho.
  - Identities can register their whereabouts so others can discover and share with them.
- Transactions (`ExtV1`) are signed by the originating identity...if public identity syncing
  is implemented, this does NOT require a separate syncing key.
- Benefits from non-decrypting, untrusted node that can route various channels to various
  participants.
  - Channel must be part of signed transaction. Use `ExtV1.context`?
  - Untrusted node channel creation/destruction: ability to create or destroy channels
    - A way to accept/sync arbitrary channels, or based on pattern.
    - Can this be done via a signed transaction? ie, remote control?
      - Need to avoid having to manually enter topics in CLI or some other such horrible
        interface

### Questions

Can the untrusted node from private identity syncing and arbitrary transaction syncing be the
same component?

Similarities:

- Both operate on `ExtV1` transactions
- Both are mainly used for syncing private data
- Both use some concept of channels to route transactions
- Both mostly use the same libp2p mechanisms, mostly.

Differences:

- `ExtV1` transactions will be in different format
  - Private identity syncing stores transaction id in `ExtV1.context`
  - Arbitrary syncing just uses `Transaction.id`
  - Can be generalized via `TransactionQuery`
- Different keys, and thus different mechanisms
  - Private sync uses a one-time bootstrapping sync key
  - Arbitrary sync signs data via identity admin key.
  - The differences here present challenges in the syncing logic. There might need to be
    some form of detection that treats the different transactions differently.

## Share (+ Sync)

The more I think about it, the more share and sync would both benefit from
some sort of public topic registration + forwarding and storage.

Sync does this by itself, but running your own sync node is going to be a
no-go for most people. So how does one say:

"Hey, I've got this gossip channel X and I want you to listen to it and
store messages on it and forward them to others who request this channel
assuming they prove they have the correct key."

