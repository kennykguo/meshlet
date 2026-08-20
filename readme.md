project: meshlet

build a small encrypted overlay network in rust on one arch linux machine.

learning contract

this repository exists to teach networking from first principles. every stage should answer four questions:

1. what problem caused this mechanism to be invented?
2. what concrete bytes or state does it introduce?
3. what changes along one packet's path, and what stays the same?
4. what latency, failure, or security tradeoff does it create?

linux commands are laboratory equipment, not the subject. we will use namespaces, nftables, and routing commands only when they make a fundamental behavior observable. we will not turn this into a system-administration or deployment-automation project.

learner-run commands should include a linux observation mechanism such as a
network namespace, tcpdump, ip, nftables, or a tun device. correctness and
negative cases belong in automated code tests run during implementation, not
in separate learner commands whose only purpose is to prove or disprove a case.

we will also keep three boundaries explicit:

concept:
    the transferable idea, such as route selection, connection state, identity, authenticated encryption, or queueing

lab mechanism:
    the linux feature used to reproduce it on one machine

production extension:
    what changes with physical nics, switches, many nodes, failures, load, and operational ownership

current checkpoint

completed:
    tcp and udp sockets
    ethernet/ip/tcp/udp packet captures
    network namespaces and veth links
    routing across two networks
    private-to-public source nat and reverse translation
    udp round-trip latency measurement
    executable stateful-firewall model
    live stateful-firewall packet experiment
    live coordinator registration through nat
    authenticated coordinator registration and wrong-key rejection
    authenticated peer handshake and encrypted echo
    one-session opaque udp relay carrying the encrypted exchange
    automatic direct-first path selection with relay fallback

implemented, awaiting your live observation:
    coordinator endpoint lookup and lease expiration
    one ordinary ipv4 echo request and reply transported through tun and udp

after that:
    tun-based layer-3 packet transport

fundamentals-first roadmap

stage	fundamental	implementation evidence
1	transport endpoints and byte streams/datagrams	rust socket code plus tcp/udp captures
2	local links, ip prefixes, next hops, and routing	ttl and mac changes across r0/r1
3	private addressing and nat	four-point pre/post translation capture
4	stateful firewall semantics	one outbound flow, its reply, and one rejected inbound flow
5	stable public rendezvous	dns name and fixed simulated endpoint
6	control plane, membership, leases, and failure uncertainty	coordinator registration and expiry
7	identity, key agreement, derivation, and authenticated encryption	authenticated handshake trace and encrypted echo
8	direct connectivity and relay fallback	probe state machine plus direct/relay traces
9	tun layer-3 overlay	one ordinary ip packet transported through userspace
10	subnets, route advertisement, and longest-prefix matching	authorized prefix routed through a peer
11	containers as isolated processes	namespace/cgroup objects behind one container
12	wireshark as structured packet evidence	pcap with layer and timing annotations
13	latency, tail behavior, queueing, and throughput	loopback and routed/nat rtt distributions

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

a network namespace is an isolated linux network stack. each namespace has its own interfaces, addresses, routes, sockets, and firewall state. this lets one kernel imitate several computers and routers while sharing the same filesystem and cpu.

10.10.0.0/24 and 10.20.0.0/24 are inside the private-use 10.0.0.0/8 range. 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24 are documentation-only ranges and should not identify real internet hosts.

what this lab can and cannot reproduce

it can expose:
    kernel socket behavior
    ethernet, ip, tcp, udp, icmp, arp, routing, nat, and firewall state
    coordination protocols, cryptographic handshakes, relay selection, tun packet flow, and subnet routing
    process scheduling, syscall, queueing, and kernel data-path latency

it cannot reproduce by itself:
    physical-link propagation delay
    switch asic behavior
    nic dma and interrupt behavior
    multi-host clock synchronization
    real internet congestion, loss, path changes, or adversaries

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
what is a container?	namespace, cgroup, image, and container-network stage
how do i inspect packet layers interactively?	wireshark stage
where does network latency come from?	measurement and low-latency stages
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

a prefix represents a set of ip addresses used for route matching.

10.10.0.0/24

means that the first 24 address bits must match 10.10.0. the remaining 8 bits distinguish addresses inside that prefix.

approximately:

network:
    10.10.0.x

possible final byte:
    0 through 255

the final 8 bits are sometimes called the host portion, but they are not a mac address. an ip address and a mac address are separate identifiers:

ip address:
    used for end-to-end routing across networks

mac address:
    used to deliver an ethernet frame across one local link

a router normally preserves the source and destination ip addresses, decreases ttl, removes the incoming ethernet frame, and creates a new ethernet frame for the next link.

we will create several namespaces and connect them with virtual ethernet pairs. a veth pair is two virtual interfaces joined by the kernel: an ethernet frame sent into one endpoint appears at the other endpoint.

this stage is complete when:

node a reaches node b through a router
tcpdump on both router interfaces shows changing mac addresses
the ip endpoints and transport ports remain stable
ttl decreases by one router hop

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

our observed nat trace is:

private side request:
    10.10.0.2:48700 → 192.0.2.20:8000

public side request:
    192.0.2.10:48700 → 192.0.2.20:8000

public side reply:
    192.0.2.20:8000 → 192.0.2.10:48700

private side reply:
    192.0.2.20:8000 → 10.10.0.2:48700

the experiment matters because it proves the transformation and reverse mapping. the nftables syntax is only how this one-machine lab requests that behavior.

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

the fundamental experiment is intentionally small:

1. permit a new private-to-public flow
2. permit the matching reply
3. reject a new public-to-private flow
4. prove where the rejected packet stopped

we care about the state machine and packet path, not memorizing firewall configuration syntax.

run the executable model:

cargo run -- firewall-demo

`cargo run` compiles and starts the debug binary. `--` ends cargo's own options, so `firewall-demo` is passed to meshlet as its mode.

the model stores exact reply flows in a hash map until their deadline. it lets us inspect the decision rule without mixing it with linux configuration. it is not yet a packet firewall: it does not parse live packets, forward them, model tcp handshake states, or handle concurrent access. the next experiment compares this small model with the kernel's real connection tracking.

live packet experiment

rebuild the three-network-namespace topology, then install the experiment rules:

bash namespaces.md
bash lab/firewall-live.sh setup

the setup adds one temporary route so mesh-b can deliver an unsolicited packet to the router. without that route, mesh-b itself would report “network is unreachable,” and the firewall would never receive the packet.

the router's forwarding policy is:

private r0 → public r1:
    allow new exchanges and packets belonging to tracked exchanges

public r1 → private r0:
    allow only packets belonging to tracked exchanges

anything else:
    count and drop

`ct` means connection tracking: kernel-maintained memory about observed packet flows. `new` means the packet begins a flow the tracker has not yet seen in both directions. `established` means the tracker has seen traffic that belongs to an existing two-way exchange. `related` means a separate flow is associated with an existing one, such as some network error messages. `counter` records matching packet and byte totals. `drop` stops the packet; `accept` permits it to continue through this firewall hook.

show the rules and their counters at any time:

bash lab/firewall-live.sh show

remove only this experiment's firewall table and temporary route:

bash lab/firewall-live.sh cleanup

a firewall and nat are different even when one router performs both:

nat:
    rewrites addresses or ports

firewall:
    decides whether a packet may continue

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

the control plane distributes decisions and metadata. it is not normally on the per-packet data path:

control plane:
    who is a member, which identity key belongs to whom, which endpoint is current, which routes and policies are allowed

data plane:
    the repeated movement of application packets between nodes

this separation exists so nodes can exchange most packets directly without sending every payload through a central coordinator.

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

the coordinator is authoritative for membership metadata but does not have perfect knowledge of reality. heartbeats and leases turn silence into a time-bounded guess. this stage will make that uncertainty explicit with expiration, re-registration, duplicate messages, and an unreachable node.

first coordinator implementation

the first version is an in-memory udp service. it supports two versioned messages:

MESHLET/1 REGISTER NODE_ID LEASE_SECONDS
MESHLET/1 LOOKUP NODE_ID

`MESHLET/1` is a protocol-version label. a protocol is an agreed message format and behavior. including the version lets a receiver reject message formats it does not understand instead of silently misinterpreting them.

the registry maps:

node id → observed udp source endpoint + expiration deadline

the endpoint is observed from the received udp datagram. it is not accepted from a claimed address inside the request. behind nat, this means the coordinator sees the router's translated source endpoint rather than the node's private endpoint.

the datagram is bounded to 1024 bytes, node ids are bounded and validated, leases are limited to 1–300 seconds, messages have an explicit version, clients use a response timeout, and expiration is tested with a caller-controlled monotonic time. these are transferable production principles; this teaching protocol and implementation are original to Meshlet.

the first version intentionally has no authentication and stores no durable data. anyone who can contact it can claim or replace a node id, and all entries disappear if the coordinator process restarts. we will demonstrate the identity flaw before adding cryptographic authentication.

coordinator modes:

meshlet coordinator-server [BIND_ADDRESS]
meshlet coordinator-register [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID] [LEASE_SECONDS]
meshlet coordinator-lookup [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID]

live namespace experiment

rebuild the topology and binary:

bash namespaces.md
cargo build

the current lab uses four simulated machines. `mesh-a` and `mesh-b` are peers,
`mesh-r` is their router, and `mesh-c` is the coordinator. a simulated machine
is a network namespace: a separate network stack inside the same linux kernel.
the coordinator is a process running inside `mesh-c`; in a real deployment it
would normally run on a separate host, vm, or container.

start the coordinator on mesh-c:

sudo ip netns exec mesh-c target/debug/meshlet \
  coordinator-server 203.0.113.10:9000

register mesh-a for 30 seconds:

sudo ip netns exec mesh-a target/debug/meshlet \
  coordinator-register 10.10.0.2:0 203.0.113.10:9000 mesh-a 30

look it up before the lease expires:

sudo ip netns exec mesh-b target/debug/meshlet \
  coordinator-lookup 192.0.2.20:0 203.0.113.10:9000 mesh-a

the client knows its private local endpoint, while the coordinator should report
a source endpoint translated to the router's `203.0.113.1` address. this is
location discovery: the service tells a node how another packet appeared at a
shared observation point.

authenticated coordinator registration

the two keys have different capabilities:

private key:
    secret bytes held by the node. they can create signatures. possession of
    these bytes is what lets a process act as that node.

public key:
    non-secret bytes copied to the coordinator. they can verify signatures but
    cannot feasibly create one or recover the private key.

a signature is a fixed-size mathematical proof tied to the exact message bytes
and a private key. verification is the yes/no calculation performed with the
corresponding public key. this provides authentication and tamper detection; it
does not encrypt the message or hide it.

the coordinator's authorization file is the initial trust decision:

mesh-a -> mesh-a's public key

the mathematics proves that a signature matches that key. the file tells the
coordinator which key is allowed to act as `mesh-a`. safely adding that mapping
is called enrollment.

version 2 adds a challenge-response exchange. a challenge is a fresh random
value chosen by the verifier. it is public, not a password. its purpose is to
make this registration different from every earlier registration:

1. node asks for a challenge using its node id
2. coordinator generates an unpredictable 32-byte challenge and binds it to that node id plus the observed udp source endpoint for 10 seconds
3. node signs a canonical registration message containing the node id, requested lease, and challenge
4. coordinator finds the pre-authorized public key for that node id and strictly verifies the ed25519 signature
5. coordinator consumes the challenge and records the observed endpoint only after verification succeeds

the word nonce means a value intended for one use. replay means sending an old,
previously valid message again. consuming the nonce prevents replay. binding it
to the observed source prevents its use from a different endpoint. signing the
lease prevents someone from changing a signed 30-second lease into 300 seconds.

any caller may receive a challenge. that is safe: only the owner of the
authorized private key can produce the required answer. the observed impostor
experiment reached the coordinator and received a challenge, but its different
private key produced a signature that did not match the authorized public key,
so verification failed.

the learning keys live under `.meshlet/keys` so every file is visible inside the
project. `.meshlet` is excluded by `.gitignore`: private keys must not enter git
history. the private identity file uses unix mode 0600, meaning only its owner
may read or write it. the directory uses mode 0700, meaning only its owner may
list or enter it. public authorization files are non-secret. key generation
refuses to overwrite either output.

create the private project directory and generate a node identity:

mkdir -p -m 700 .meshlet/keys
target/debug/meshlet identity-generate mesh-a \
  .meshlet/keys/mesh-a.identity \
  .meshlet/keys/authorized-nodes

start the authenticated coordinator:

sudo ip netns exec mesh-c target/debug/meshlet \
  coordinator-server-auth 203.0.113.10:9000 \
  .meshlet/keys/authorized-nodes

register using the private identity:

sudo ip netns exec mesh-a target/debug/meshlet \
  coordinator-register-auth \
  10.10.0.2:0 203.0.113.10:9000 mesh-a 120 \
  .meshlet/keys/mesh-a.identity

look up the authenticated registration:

sudo ip netns exec mesh-b target/debug/meshlet \
  coordinator-lookup-auth \
  192.0.2.20:0 203.0.113.10:9000 mesh-a

this proves control of the private signing key authorized for `mesh-a`, recent round-trip access to the observed endpoint, and agreement on the signed registration fields. it does not prove that the node is uncompromised, that another peer can reach it, or that it remains alive for the entire lease.

the current protocol authenticates the registering node only. it does not
authenticate the coordinator to the node, encrypt control messages, authorize
lookup callers, limit request rates, persist state, rotate keys, or revoke a
stolen key. those omissions are visible boundaries of the learning stage, not
production security claims.

production security extension

the project-local key directory is a deliberate learning compromise: visible,
inspectable, and protected from accidental git commits. a production system
would normally store private keys in a restricted operating-system secret
store, or use a tpm or hsm: hardware designed to perform cryptographic
operations without releasing the private key bytes. a hosted service may use a
kms, meaning a managed key-management service. production also needs protected
enrollment, key rotation (replacing keys), revocation (declaring a key no longer
trusted), encrypted backups, access auditing, and a protected channel to the
coordinator. public keys may be distributed widely; private keys must never be
logged or copied into source control.

stage 7: authenticated cryptographic handshake

we will not implement encryption algorithms ourselves. we will use established implementations but build the handshake protocol and state machine ourselves.

the four separate cryptographic goals are:

identity authentication:
    prove which long-term node signed a handshake

key agreement:
    derive a shared secret without sending that secret

key derivation:
    turn shared material and transcript context into independent directional keys

authenticated encryption:
    hide packet contents and reject modification

each node will have two kinds of keys.

identity key:
    ed25519
    used to sign and verify handshake messages

ephemeral exchange key:
    x25519
    used to derive a temporary shared secret

the implemented handshake uses two packets, so it takes one network round trip:

node a → node b:

client hello
    node a ephemeral public key
    signature over the protocol version, both node ids, and that public key

the identity public key is not sent as self-asserted truth. node b loads the
public key already authorized for node a and uses that key to verify the
signature.

node b performs:

1. look up node a's expected identity key

2. verify the signature

3. reject the message if verification fails

4. generate its own ephemeral x25519 key pair

then node b returns:

server hello
    node b ephemeral public key
    signature over both node ids and both ephemeral public keys

node a verifies that signature using the public identity key it already trusts
for node b. each ephemeral key pair is freshly generated for one handshake.

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

data packets now use chacha20-poly1305.

chacha20-poly1305 is an aead: authenticated encryption with associated data. the encrypted payload is confidential, while selected unencrypted headers can still be covered by integrity protection.

it provides:

confidentiality:
    outsiders cannot read the contents

integrity:
    modified packets fail verification

authentication:
    a valid packet proves knowledge of the session key

discarding the ephemeral private keys after the handshake provides forward secrecy: later theft of the long-term identity key should not reveal previously recorded session traffic.

the implementation derives two 32-byte directional keys:

client to server key
server to client key

directional means each traffic direction receives a different key. therefore,
both directions may start their packet number at zero without reusing a nonce
with the same key.

each encrypted UDP datagram contains:

visible header
    meshlet packet marker
    direction
    packet number

encrypted body
    application bytes
    authentication tag

ciphertext means the unreadable encrypted form of the application bytes. the
16-byte authentication tag is a compact check produced by the cipher; the
receiver rejects the packet if the key, header, or ciphertext does not match it.

a nonce is a value that must be unique for every packet encrypted with one
key. meshlet constructs it from the direction and packet number. it is not a
secret. the packet number starts at zero and increases. the receiver expects
the next number, so the same datagram cannot be accepted twice.

the visible header is associated data: it is not hidden, but it is included in
the authentication calculation. changing either the header or ciphertext makes
the packet invalid.

the client sends one encrypted message and the server returns its decrypted
bytes through the opposite directional key. successfully decrypting those
packets confirms that both peers derived the same keys. the keys disappear when
the two learning processes exit.

live encrypted-echo experiment

start the one-exchange server inside mesh-b's network namespace:

sudo ip netns exec mesh-b target/release/meshlet \
  secure-echo-server \
  192.0.2.20:7000 \
  .meshlet/keys/mesh-b.identity \
  .meshlet/keys/authorized-nodes

observe the whole exchange on every mesh-r interface:

sudo ip netns exec mesh-r \
  tcpdump -nni any -X 'udp port 7000'

run the client inside mesh-a's network namespace:

sudo ip netns exec mesh-a target/release/meshlet \
  secure-echo-client \
  10.10.0.2:0 \
  192.0.2.20:7000 \
  .meshlet/keys/mesh-a.identity \
  mesh-b \
  .meshlet/keys/mesh-b.authorization

there are four UDP datagrams: client hello, server hello, encrypted request,
and encrypted echo. because `-i any` watches both router interfaces, it normally
shows each datagram once entering and once leaving: eight capture lines. the
hello fields remain visible. the last two datagrams expose only the 13-byte
header (`MSH3`, direction, and packet number) followed by ciphertext and a
16-byte authentication tag. `hello from encrypted meshlet` appears only in the
processes' decrypted output, not in those captured datagrams.

the client reports handshake time separately from encrypted-echo round-trip
time. the server separately reports handshake cryptography and data-packet
cryptography. each number is one observation, not a stable benchmark.

on a real wide-area path, the network round trip will usually dominate this
setup cost. after the handshake, key agreement and identity signatures are
not repeated for every data packet; the cheaper symmetric packet cipher will
operate on the data path.

this is deliberately a one-exchange learning server. retries, concurrent
clients, out-of-order delivery, key rotation, and session resumption are omitted
until an experiment gives us a concrete reason to introduce them.

we use established library implementations and explicit byte encodings.
production systems do not copy cryptographic primitives into application code.

stage 8: direct connectivity and relay fallback

connectivity means that packets sent to an endpoint can actually reach the intended node and that replies can return. knowing an ip address is not enough when nat mappings, firewalls, or changing ports affect the path.

we will build this in two small steps. first, run the same secure echo directly
and through a relay so the two data paths are visible. second, add automatic
probing and path selection. this keeps forwarding separate from the later
decision about which path to use.

the first relay is deliberately a one-client, one-exchange udp process:

client endpoint ← relay socket → configured server endpoint

an endpoint is an ip address plus a udp port. the relay learns the client's
endpoint from the source of the first datagram. it already knows the server's
endpoint from its command line. it then copies each received datagram to the
other endpoint without parsing or changing its payload.

opaque means the relay treats the payload as an uninterpreted sequence of
bytes. the end nodes still perform the handshake, authenticate node identities,
derive session keys, and encrypt the request. the relay has none of those keys.

this relay is not an ip router. the kernel router forwards an ip packet by
looking up that packet's destination address. the relay is a userspace program:
it receives one udp datagram addressed to its own socket, then sends a new udp
datagram containing the same payload toward the other endpoint.

live relayed encrypted-echo experiment

if the namespaces were created before the relay address was added to
`namespaces.md`, add that address to mesh-c's existing interface:

sudo ip -n mesh-c address replace 203.0.113.20/24 dev c0

start the existing encrypted server in mesh-b:

sudo ip netns exec mesh-b target/release/meshlet \
  secure-echo-server \
  192.0.2.20:7000 \
  .meshlet/keys/mesh-b.identity \
  .meshlet/keys/authorized-nodes

start the relay at a second address in mesh-c. its configured upstream is the
encrypted server:

sudo ip netns exec mesh-c target/release/meshlet \
  udp-relay \
  203.0.113.20:7100 \
  192.0.2.20:7000

observe both udp legs on every router interface:

sudo ip netns exec mesh-r \
  tcpdump -nni any -X '(udp port 7000 or udp port 7100)'

run the same secure client, changing only its destination from the direct
server endpoint to the relay endpoint:

sudo ip netns exec mesh-a target/release/meshlet \
  secure-echo-client \
  10.10.0.2:0 \
  203.0.113.20:7100 \
  .meshlet/keys/mesh-a.identity \
  mesh-b \
  .meshlet/keys/mesh-b.authorization

the secure exchange still has four logical messages: client hello, server
hello, encrypted request, and encrypted echo. each message now travels in two
udp datagrams: endpoint to relay, then relay to the other endpoint. that makes
eight network datagrams. `tcpdump -i any` normally observes each once entering
and once leaving mesh-r, producing about sixteen capture records.

mesh-b will report the relay socket as its network peer, but it will still
report `mesh-a` as the authenticated node. this distinction is fundamental:
an endpoint says where the current packet came from; cryptographic identity
says which key signed the handshake.

the relay adds a userspace receive, a userspace send, another routed leg, and
more opportunities to wait in queues or for process scheduling. compare its
round-trip time with the earlier direct observation, but treat each single run
as an example rather than a benchmark.

this first relay intentionally omits multiple clients, long-lived sessions,
registration, authentication at the relay, retries, and rate limits. none is
needed to observe the fundamental forwarding path.

the automatic-selection step will work as follows. nodes first exchange
observed udp endpoints through the coordinator.

they send small probes toward one another:

node a → node b endpoint
node b → node a endpoint

these outbound probes create nat state.

when this succeeds, encrypted packets travel directly.

when it fails, both nodes maintain outbound paths to a multi-node relay:

node a → relay ← node b

unlike the one-client relay above, that relay will need a small visible routing
envelope such as:

destination node id
encrypted payload

it forwards the payload but does not possess the session encryption key.

this demonstrates the difference between:

routing bytes
and
understanding bytes

the decision will be evidence-driven:

probing:
    send small authenticated messages over a candidate path

timeout:
    stop waiting after a defined interval

fallback:
    use the relay when no direct path is confirmed

recovery:
    keep testing whether a lower-latency direct path becomes available

the relay adds another network hop and more queueing opportunity, so we will measure direct and relayed rtt separately. it must learn only the routing envelope needed to forward ciphertext, not the decrypted payload.

`secure-echo-client-auto` implements the first three decisions with the existing
authenticated handshake. it waits up to 250 milliseconds for a valid direct
server hello. a network error or timeout permits a relay attempt. a malformed
or incorrectly signed response stops the operation instead of being treated as
a reachability problem. once one path completes the handshake, the client uses
that session for encrypted data rather than performing a separate probe round
trip.
stage 9: overlay addresses and tun interfaces

initially, meshlet will send application messages.

later, it will create a linux tun interface.

a tun interface behaves like a virtual layer-3 network card.

layer 3 means the tun interface reads and writes ip packets. it does not carry ethernet headers or mac addresses. a tap interface is the related layer-2 mechanism that carries ethernet frames; meshlet uses tun because the overlay routes ip.

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

this is the key abstraction boundary:

ordinary application:
    opens normal tcp or udp sockets to an overlay ip

kernel:
    constructs an ip packet and selects meshlet0

meshlet process:
    reads the packet, chooses a peer, encrypts it, transports it, decrypts the peer packet, and writes it back to tun

we will first forward one visible icmp packet, then add encryption. this keeps packet transport separate from cryptographic correctness.

the first implementation is `tun-udp-one`. it attaches to an existing Linux
TUN interface and handles one IPv4 packet in each direction. one worker reads a
kernel-produced IP packet from TUN and sends those exact bytes as a UDP payload.
the other receives a UDP payload and writes the recovered IP packet into TUN.

start the mesh-b endpoint:

sudo ip netns exec mesh-b target/release/meshlet \
  tun-udp-one meshlet0 192.0.2.20:7200 192.0.2.10:7200

start the mesh-a endpoint:

sudo ip netns exec mesh-a target/release/meshlet \
  tun-udp-one meshlet0 10.10.0.2:7200 192.0.2.20:7200

observe the outer UDP transport at the router:

sudo ip netns exec mesh-r tcpdump -nni any -X 'udp port 7200'

ask mesh-a's ordinary Linux IP stack to send one ICMP echo request to mesh-b's
overlay address:

sudo ip netns exec mesh-a ping -c 1 -W 1 100.64.0.2

`ping` knows nothing about Meshlet or UDP. its packet follows the connected
`100.64.0.0/24` route into `meshlet0`; Meshlet reads it, carries it through UDP,
and writes it into mesh-b's `meshlet0`. the reply follows the reverse path.

this first packet transport is intentionally unencrypted. the capture exposes
the complete inner IP packet inside the outer UDP payload. the next step will
place the existing authenticated-encryption packet format between the TUN read
and UDP send, then decrypt before the TUN write.

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

longest-prefix matching means selecting the matching route with the greatest prefix length. it chooses the most specific address set, not the route with the numerically largest address.

a subnet router differs from an ordinary overlay endpoint:

ordinary endpoint:
    receives packets addressed to itself

subnet router:
    advertises reachability for a prefix and forwards packets to other machines behind it

route advertisement is a claim, not proof. the control plane must decide whether to authorize, distribute, expire, or prefer that claim.

stage 11: containers from first principles

a container is an ordinary process whose operating-system view and resource usage are constrained.

namespaces isolate what the process can see:
    process ids
    mounts
    hostname
    users
    network interfaces, addresses, routes, and sockets

cgroups account for and limit resources:
    cpu time
    memory
    process count
    io

an image supplies a filesystem and metadata used to start the process. a container runtime assembles the namespaces, cgroups, filesystem, environment, and process. unlike a virtual machine, a typical container shares the host kernel.

container networking commonly automates primitives we are already using manually:

container network namespace
    ↕ veth pair
host bridge or routed interface
    ↕ routing, nat, and policy
other containers or external networks

the learning experiment will create the equivalent topology manually, then run the same meshlet process through a container runtime and identify which kernel objects the runtime created. the goal is to understand the abstraction, not memorize docker or kubernetes commands.

stage 12: wireshark and evidence-driven debugging

tcpdump and wireshark observe the same packet layers through libpcap-compatible captures. tcpdump is compact and scriptable; wireshark provides interactive decoding, filtering, stream following, timing views, and packet-by-packet field inspection.

we will save pcap files rather than rely only on terminal text:

tcpdump -i interface -w experiment.pcap

useful wireshark display filters include:

arp
icmp
udp.port == 8000
tcp.port == 8000
ip.addr == 10.10.0.2
tcp.flags.syn == 1

the workflow is:

1. state a prediction
2. capture at the relevant boundary
3. find the first field that differs from the prediction
4. map that field back to route, neighbor, socket, nat, firewall, or application state

stage 13: latency and performance as a recurring lens

latency is elapsed time. rtt is round-trip time from request send through reply receipt. throughput is completed work per unit time. optimizing one can worsen the other when batching or queueing is introduced.

the first benchmark uses stop-and-wait udp: only one request is outstanding, and the server echoes an eight-byte sequence number. the client uses a monotonic clock, performs warm-up exchanges, avoids per-packet printing and allocation, and reports min, p50, p99, and max.

benchmark modes:

meshlet udp-bench-server [BIND_ADDRESS]
meshlet udp-rtt-client [BIND_ADDRESS] [SERVER_ADDRESS] [SAMPLES]

the udp client calls connect, but connected udp does not perform a handshake. it records a default peer in the kernel, permits send and recv without repeating the address, and filters incoming datagrams to that peer.

build benchmarks with optimization:

cargo build --release

loopback baseline inside mesh-a:

sudo ip netns exec mesh-a target/release/meshlet udp-bench-server 127.0.0.1:8000
sudo ip netns exec mesh-a target/release/meshlet udp-rtt-client 127.0.0.1:0 127.0.0.1:8000 10000

routed and nat path:

sudo ip netns exec mesh-b target/release/meshlet udp-bench-server 192.0.2.20:8000
sudo ip netns exec mesh-a target/release/meshlet udp-rtt-client 10.10.0.2:0 192.0.2.20:8000 10000

percentiles describe a distribution:

p50:
    half the samples completed at or below this time

p99:
    ninety-nine percent completed at or below this time

tail latency:
    the slow end of the distribution, often caused by scheduling, queueing, cache misses, contention, retransmission, or one-time state creation

the measurement sequence is:

1. loopback baseline
2. routed namespace path
3. routed plus nat path
4. cold versus warm neighbor and connection-tracking state
5. payload sizes around mtu boundaries
6. cpu affinity and scheduler jitter
7. bursts, socket buffers, and queueing
8. multiple in-flight messages: latency versus throughput
9. system-call batching
10. physical nic queues, dma, interrupts, rss, numa, kernel bypass, rdma, and dpdk

the one-machine namespace lab can measure kernel and scheduler costs. physical-nic and multi-host conclusions require separate hardware measurements.

possible later repository layout
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
│   └── capture-experiment.sh
└── notes/
    └── observations.md

do not split the current single binary merely to imitate a production repository. split crates only when protocol encoding, node data path, coordinator, and relay have independently testable contracts.

when an observation changes the mental model, record:

what packet was sent
which headers changed
which address was private
which address was public
which router table entry was used
which state or decision changed the result
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
original implementation target

do not begin with crypto or tun interfaces.

the first checkpoint is:

one rust binary
four modes
tcp server/client
udp server/client
packet captures proving the difference

this checkpoint is complete. the program exposes socket addresses and byte counts, and the namespace lab has demonstrated routing and nat.

that progression prevents the project from becoming a large opaque “vpn implementation” before the underlying packet behavior is understood.

summary

meshlet will begin as a socket and linux-routing lab, then grow into an authenticated encrypted overlay with coordination, nat traversal, relay fallback, tun-based packet transport, and subnet routing. every major feature corresponds directly to one of your networking questions and to a concrete distributed-systems concept.

project purpose

the project’s purpose is to make internet routing, transport ports, public and private addressing, nat, stateful firewalls, containers, cryptographic handshakes, distributed membership, overlay networks, relay fallback, tun interfaces, subnet routing, packet inspection, and latency tradeoffs observable through code and packet traces rather than only through diagrams.

golang learning track

go fits this project best at a service boundary, especially a later coordinator implementation. coordinators perform request parsing, concurrent network io, timers, maps, serialization, and operational diagnostics: areas where go's small language, garbage collection, goroutines, channels, networking standard library, fast builds, and simple binary deployment are strong.

meshlet's packet data path will remain in rust so the project can study explicit ownership, byte representations, cryptographic state, system calls, tun io, and latency without introducing a garbage-collected runtime into the hottest path.

after the coordinator protocol and authentication rules are stable, implement the same coordinator contract in go and run the rust nodes against both servers. this creates a meaningful language boundary and proves that the protocol, rather than one implementation, is the contract.

the go learning sequence will start from zero:

1. source files, packages, modules, compilation, and the `main` entry point
2. values, variables, constants, functions, structs, methods, pointers, slices, and maps
3. interfaces, explicit error values, `defer`, resource lifetime, and cancellation with contexts
4. goroutines, channels, locks, races, and ownership conventions
5. udp/http servers, deadlines, bounded inputs, serialization, and tests
6. garbage collection, allocation, escape analysis, latency, the race detector, benchmarks, and pprof
7. implement the Meshlet coordinator protocol and compare behavior, failure handling, and performance with the rust version

we will not mix go into the repository merely for syntax practice. the second coordinator becomes worthwhile when interoperability and control-plane concurrency are real learning goals.
