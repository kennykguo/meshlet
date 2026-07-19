project: meshlet

build a small encrypted overlay network in rust on one arch linux machine.

the finished system will have:

node a behind nat/firewall
        │
        ├── direct encrypted udp when possible
        │
        └── encrypted relay fallback
        │
node b on another private subnet

a separate coordination server will distribute identities, addresses, and routes. this recreates the important architectural ideas from the tailscale article without attempting to reproduce wireguard itself: centralized control, distributed data transfer, nat traversal, relay fallback, and subnet routing.

i recommend rust for the main implementation. it exposes socket addresses, byte buffers, packet formats, and state transitions clearly. we will initially avoid async rust and use blocking sockets plus threads so the network mechanics remain visible.

what the final project will demonstrate
control plane:
    nodes register identities, public keys, addresses, and routes

data plane:
    nodes exchange encrypted packets directly over udp

relay plane:
    forwards ciphertext when direct communication is blocked

routing plane:
    forwards packets to another private subnet

policy plane:
    allows or rejects communication between nodes

the final test topology will run entirely through linux network namespaces:

private subnet a                           private subnet b

node a                                     node b
10.10.0.2                                  10.20.0.2
    │                                          │
    │ private network                          │ private network
    │                                          │
nat/router a ───── simulated internet ───── router b
192.0.2.10                                 198.51.100.10
                       │
                       │
              coordination server
                  203.0.113.10

a network namespace is an isolated linux networking environment. each namespace gets its own interfaces, routes, firewall rules, and addresses. this lets one physical machine behave like several separate computers and routers.

the address ranges above are documentation-only ranges. they are useful for experiments because they should not refer to real internet hosts.

your questions mapped to project stages
question	stage that answers it
what is the internet?	simulated internet and router stage
public address versus private address	namespace and nat stage
how do public vpns use static addresses?	public coordination and gateway stage
what does “behind a firewall” mean?	stateful firewall stage
how does outward client traffic work?	nat connection-tracking stage
how does the public address forward replies?	nat translation-table stage
do ports belong to tcp?	tcp and udp socket stage
how do cryptographic handshakes work?	authenticated handshake stage
what are subnets?	routing-table stage
what is a subnet router?	route-advertisement stage
how does this relate to distributed systems?	membership, discovery, failure, leases, and policy stages
stage 1: sockets, addresses, and ports

build four small modes inside one binary:

meshlet tcp-server
meshlet tcp-client
meshlet udp-server
meshlet udp-client

each mode should print:

local socket address
remote socket address
number of bytes sent or received
the exact received bytes

a socket address is:

ip address + port

but the complete identity of a transport endpoint includes the protocol:

tcp + 192.0.2.10 + port 8000
udp + 192.0.2.10 + port 8000

ports do not belong to ip itself. both tcp and udp have separate 16-bit source-port and destination-port fields in their own headers.

therefore, these can coexist:

tcp port 8000
udp port 8000

they are distinct because the protocol differs.

the first packet experiment will show:

ethernet frame
    contains an ip packet
        contains a tcp segment or udp datagram
            contains your application bytes

we will inspect this with tcpdump.

stage 2: construct a small internet

the internet is not one giant network owned by one entity.

it is a collection of separate networks connected by routers:

network a ── router ── network b ── router ── network c

an ip packet contains a destination ip address. each router consults a routing table and chooses where to send the packet next.

a routing table contains rules like:

destination prefix     next hop
10.10.0.0/24           interface a
10.20.0.0/24           interface b
0.0.0.0/0              upstream router

a prefix represents a group of addresses.

10.10.0.0/24

means that the first 24 bits identify the network. the final 8 bits identify a host inside that network.

approximately:

network:
    10.10.0.x

possible final byte:
    0 through 255

we will create several namespaces and connect them with virtual ethernet pairs. a virtual ethernet pair behaves like a cable with two ends.

stage 3: private addresses, public addresses, and nat

private ipv4 ranges include:

10.0.0.0/8
172.16.0.0/12
192.168.0.0/16

these addresses are not globally routed across the public internet.

your laptop might use:

192.168.1.20

while its router uses a public address assigned by an internet provider:

203.0.113.50

nat translates between them.

suppose your laptop sends:

protocol:       udp
source:         192.168.1.20:50000
destination:    198.51.100.30:9000

the router may rewrite it as:

protocol:       udp
source:         203.0.113.50:62001
destination:    198.51.100.30:9000

the router records a mapping:

udp 203.0.113.50:62001
    ↔
udp 192.168.1.20:50000

when a reply arrives for 203.0.113.50:62001, the router looks up the entry, rewrites the destination, and forwards it to the laptop.

this directly answers how one public address can serve several private devices.

the mapping includes a port because many internal connections share the same public ip.

stage 4: “behind a firewall”

a stateful firewall remembers active communication.

when the private client sends outward:

client → server

the firewall records state describing that flow.

a simplified flow key is called the five-tuple:

source ip
source port
destination ip
destination port
transport protocol

a matching reply:

server → client

is accepted because the firewall recognizes it as part of an existing flow.

an unrelated inbound packet is rejected:

unknown internet host → private client

because:

no matching connection state exists
no explicit inbound firewall rule exists

this is what “the client is behind a firewall but can connect outward” means.

the client initiates communication. the firewall permits matching responses.

stage 5: static public vpn addresses

a public vpn gateway needs a stable location clients can contact.

commercial vpn operators commonly obtain addresses from:

a cloud provider
a hosting provider
an internet service provider
an address block they control

the address remains assigned to the gateway or to the provider’s virtual networking configuration.

a client can therefore store:

vpn.example.com:51820

dns translates the hostname into a public ip address.

for our project, the coordination server and relay will receive fixed addresses inside the simulated public network:

coordination server:
    203.0.113.10

relay:
    203.0.113.20

the private nodes will always know how to contact them.

this reproduces the important property of a public vpn gateway without renting an actual internet server.

stage 6: control plane and distributed-systems membership

each node will generate a persistent node id and register with the coordinator:

node id
identity public key
current udp endpoint
overlay ip address
advertised subnet routes
last heartbeat time

the coordinator maintains a membership table:

node a:
    alive
    endpoint = 192.0.2.10:41000

node b:
    alive
    endpoint = 198.51.100.10:42000

this introduces distributed-systems problems:

identity versus location

the node identity should remain stable while its network address changes.

identity:
    node a

old location:
    192.0.2.10:41000

new location:
    192.0.2.44:53000
failure detection

the coordinator cannot know immediately whether a node crashed or lost connectivity.

nodes send periodic heartbeats.

the coordinator treats a node as unavailable when its heartbeat expires.

this is not perfect knowledge. a missing heartbeat could mean:

node crashed
network dropped packets
router failed
coordinator was temporarily unreachable

that uncertainty is fundamental in distributed systems.

leases

a registration will have an expiration time.

the node must periodically renew it.

this prevents stale addresses from remaining valid forever.

stage 7: authenticated cryptographic handshake

we will not implement encryption algorithms ourselves. we will use established implementations but build the handshake protocol and state machine ourselves.

each node will have two kinds of keys.

identity key:
    ed25519
    used to sign and verify handshake messages

ephemeral exchange key:
    x25519
    used to derive a temporary shared secret

the handshake will work approximately like this:

node a → node b:

client hello
    node a identity public key
    node a ephemeral public key
    random nonce
    signature over the message

node b performs:

1. look up node a's expected identity key

2. verify the signature

3. reject the message if verification fails

4. generate its own ephemeral x25519 key pair

then node b returns:

server hello
    node b identity public key
    node b ephemeral public key
    both nonces
    signature over the full handshake transcript

both sides compute:

shared secret =
    x25519(our ephemeral private key,
           peer ephemeral public key)

the mathematical operation produces the same shared secret on both nodes without transmitting that secret.

the secret is passed through hkdf:

shared secret
    + handshake transcript
    ↓
hkdf
    ↓
a-to-b encryption key
b-to-a encryption key

packets will then use chacha20-poly1305.

it provides:

confidentiality:
    outsiders cannot read the contents

integrity:
    modified packets fail verification

authentication:
    a valid packet proves knowledge of the session key

discarding the ephemeral private keys after the handshake provides forward secrecy: later theft of the long-term identity key should not reveal previously recorded session traffic.

stage 8: direct connectivity and relay fallback

nodes first exchange observed udp endpoints through the coordinator.

they send small probes toward one another:

node a → node b endpoint
node b → node a endpoint

these outbound probes create nat state.

when this succeeds, encrypted packets travel directly.

when it fails, both nodes maintain outbound connections to the relay:

node a → relay ← node b

the relay receives a frame like:

destination node id
encrypted payload

it forwards the payload but does not possess the session encryption key.

this demonstrates the difference between:

routing bytes
and
understanding bytes
stage 9: overlay addresses and tun interfaces

initially, meshlet will send application messages.

later, it will create a linux tun interface.

a tun interface behaves like a virtual layer-3 network card.

the kernel writes complete ip packets into it:

application
    ↓
linux tcp/ip stack
    ↓
meshlet0 tun interface
    ↓
meshlet process reads raw ip packet bytes

the process then:

reads destination overlay ip
chooses a peer
encrypts the ip packet
sends it over udp

the receiving node:

receives ciphertext
verifies and decrypts it
writes the recovered ip packet into its tun interface

the receiving kernel then delivers it to the destination application.

at this point, ordinary programs can communicate through the overlay without knowing that meshlet exists.

stage 10: subnets and subnet routers

i assume “subsets” meant subnets.

a subnet is a set of ip addresses represented by a prefix:

10.20.0.0/16

a subnet router is a node that can reach that entire prefix and agrees to forward packets into it.

suppose node b is connected to:

legacy subnet:
    10.20.0.0/16

node b advertises to the coordinator:

i can route packets for 10.20.0.0/16

node a receives a routing rule:

destination 10.20.0.0/16
    → encrypted tunnel to node b

node b decrypts the packet and forwards it onto the legacy subnet.

we will implement route selection using longest-prefix matching.

given:

10.0.0.0/8       → router x
10.20.0.0/16     → router y
10.20.30.0/24    → router z

a packet for 10.20.30.5 uses router z, because /24 is the most specific matching prefix.

proposed repository layout
meshlet/
├── crates/
│   ├── meshlet-proto/
│   │   └── packet formats and serialization
│   ├── meshlet-node/
│   │   └── sockets, handshake, encryption, routing
│   ├── meshlet-coord/
│   │   └── registration and membership
│   └── meshlet-relay/
│       └── ciphertext forwarding
├── lab/
│   ├── create-topology.sh
│   ├── destroy-topology.sh
│   └── firewall-rules.sh
└── notes/
    └── observations.md

the notes file matters. after each stage, record:

what packet was sent
which headers changed
which address was private
which address was public
which router table entry was used
which firewall state allowed or rejected it
arch linux setup
sudo pacman -S rustup iproute2 nftables tcpdump conntrack-tools
rustup default stable

optional packet inspection:

sudo pacman -S wireshark-cli

the relevant tools are:

ip:
    interfaces, addresses, routes, namespaces

nft:
    firewall and nat rules

tcpdump:
    raw packet observation

conntrack:
    kernel nat and connection-state table

cargo:
    building the rust programs
first implementation target

do not begin with crypto or tun interfaces.

the first checkpoint is:

one rust binary
four modes
tcp server/client
udp server/client
packet captures proving the difference

the program should expose every socket address and every byte count. after that works, we place the client and server in separate namespaces and introduce routing, firewalling, and nat one layer at a time.

that progression prevents the project from becoming a large opaque “vpn implementation” before the underlying packet behavior is understood.

summary

meshlet will begin as a socket and linux-routing lab, then grow into an authenticated encrypted overlay with coordination, nat traversal, relay fallback, tun-based packet transport, and subnet routing. every major feature corresponds directly to one of your networking questions and to a concrete distributed-systems concept.

project purpose

the project’s purpose is to make internet routing, transport ports, public and private addressing, nat, stateful firewalls, cryptographic handshakes, distributed membership, overlay networks, and subnet routing observable through code and packet traces rather than only through diagrams.

containers?