# Meshlet

Build a small encrypted overlay network in Rust on one Arch Linux machine.

> See the [implementation index](CODEMAP.md) to find code by command, concept,
> or runtime call path.

## Purpose

Meshlet is a learning project, not a production VPN or deployment template. It
builds networking mechanisms one at a time so their packet paths, state, and
design tradeoffs remain visible in code. One Linux kernel uses network
namespaces to imitate nodes, routers, public networks, and private subnets.

The project covers sockets, routing, NAT, stateful firewalls, coordination,
cryptographic handshakes, direct and relayed paths, TUN overlays, subnet
routing, and container isolation.

## Reproduce the project

Requirements: Linux, root access for namespace operations, Rust, Go, BusyBox,
`iproute2`, nftables, and tcpdump.

Build the Rust networking binary and create the simulated network:

```bash
git clone --recurse-submodules git@github.com:kennykguo/meshlet.git
cd meshlet
rustup default stable
cargo build --release
bash namespaces.md
sudo ip netns exec mesh-a ping -c 1 -W 1 192.0.2.20
```

Build and run the [Mini Container](https://github.com/kennykguo/mini-container)
submodule with its private veth network:

```bash
git submodule update --init --recursive
cd toy-container
bash setup-rootfs.sh
go build -o toy-container .
sudo ./toy-container --rootfs .rootfs /bin/sh -c \
  'ip address; ip route; ping -c 1 -W 1 10.200.0.1'
```

The numbered stages below contain the focused commands for each mechanism.

## Guide

- [Learning contract](#learning-contract)
- [Current checkpoint](#current-checkpoint)
- [Fundamentals-first roadmap](#fundamentals-first-roadmap)
- [Target architecture](#target-architecture)
- [Scope and limitations](#scope-and-limitations)
- [Questions mapped to stages](#questions-mapped-to-project-stages)
- [Learning stages](#stage-1-sockets-addresses-and-ports)
- [Go learning track](#go-learning-track)

## Learning contract

This repository exists to teach networking from first principles. Every stage should answer four questions:

1. What problem caused this mechanism to be invented?
2. What concrete bytes or state does it introduce?
3. What changes along one packet's path, and what stays the same?
4. What latency, failure, or security tradeoff does it create?

Linux commands are laboratory equipment, not the subject. We use namespaces,
nftables, and routing commands only when they make fundamental behavior
observable. This is not a system-administration or deployment-automation project.

Learner-run commands should include a Linux observation mechanism such as a
network namespace, tcpdump, IP, nftables, or a TUN device. Correctness and
negative cases belong in automated code tests run during implementation, not
in separate learner commands whose only purpose is to prove or disprove a case.

We keep three boundaries explicit:

- **Concept:** the transferable idea, such as route selection, connection
  state, identity, authenticated encryption, or queueing.
- **Lab mechanism:** the Linux feature used to reproduce it on one machine.
- **Production extension:** what changes with physical NICs, switches, many
  nodes, failures, load, and operational ownership.

## Current checkpoint

### Completed

- TCP and UDP sockets
- Ethernet/IP/TCP/UDP packet captures
- Network namespaces and veth links
- Routing across two networks
- Private-to-public source NAT and reverse translation
- UDP round-trip latency measurement
- Executable stateful-firewall model
- Live stateful-firewall packet experiment
- Live coordinator registration through NAT
- Authenticated coordinator registration and wrong-key rejection
- Authenticated peer handshake and encrypted echo
- One-session opaque UDP relay carrying the encrypted exchange
- Automatic direct-first path selection with relay fallback
- One ordinary IPv4 echo request and reply transported through TUN and UDP
- One private subnet reached through `mesh-b` as a subnet router
- Route advertisement and longest-prefix peer selection
- Container namespaces, root filesystem, cgroups, synchronization, and veth networking

### Implemented, awaiting live observation

- Coordinator endpoint lookup and lease expiration

## Fundamentals-first roadmap

| Stage | Fundamental | Implementation evidence |
| ---: | --- | --- |
| 1 | Transport endpoints and byte streams/datagrams | Rust socket code plus TCP/UDP captures |
| 2 | Local links, IP prefixes, next hops, and routing | TTL and MAC changes across `r0`/`r1` |
| 3 | Private addressing and NAT | Four-point pre/post translation capture |
| 4 | Stateful firewall semantics | One outbound flow, its reply, and one rejected inbound flow |
| 5 | Stable public rendezvous | DNS name and fixed simulated endpoint |
| 6 | Control plane, membership, leases, and failure uncertainty | Coordinator registration and expiry |
| 7 | Identity, key agreement, derivation, and authenticated encryption | Authenticated handshake trace and encrypted echo |
| 8 | Direct connectivity and relay fallback | Probe state machine plus direct/relay traces |
| 9 | TUN layer-3 overlay | One ordinary IP packet transported through userspace |
| 10 | Subnets, route advertisement, and longest-prefix matching | Advertised prefix mapped to a peer |
| 11 | Containers as isolated processes | Namespace/cgroup/veth objects behind one container |

## Target architecture

```text
node a behind nat/firewall
        │
        ├── direct encrypted udp when possible
        │
        └── encrypted relay fallback
        │
node b on another private subnet
```

A separate coordination server will distribute identities, addresses, and routes. This recreates the important architectural ideas from the Tailscale article without attempting to reproduce WireGuard itself: centralized control, distributed data transfer, NAT traversal, relay fallback, and subnet routing.

I recommend Rust for the main implementation. It exposes socket addresses, byte buffers, packet formats, and state transitions clearly. We will initially avoid async Rust and use blocking sockets plus threads so the network mechanics remain visible.

### Architectural planes

- **Control plane:** nodes register identities, public keys, addresses, and routes.
- **Data plane:** nodes exchange encrypted packets directly over UDP.
- **Relay plane:** forwards ciphertext when direct communication is blocked.
- **Routing plane:** forwards packets to another private subnet.
- **Policy plane:** allows or rejects communication between nodes.

### Test topology

The final test topology runs entirely through Linux network namespaces:

```text
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
```

A network namespace is an isolated Linux network stack. Each namespace has its own interfaces, addresses, routes, sockets, and firewall state. This lets one kernel imitate several computers and routers while sharing the same filesystem and CPU.

10.10.0.0/24 and 10.20.0.0/24 are inside the private-use 10.0.0.0/8 range. 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24 are documentation-only ranges and should not identify real internet hosts.

## Scope and limitations

### What this lab can expose

- Kernel socket behavior
- Ethernet, IP, TCP, UDP, ICMP, ARP, routing, NAT, and firewall state
- Coordination protocols, cryptographic handshakes, relay selection, TUN packet flow, and subnet routing
- Process scheduling, system calls, queueing, and kernel data-path latency

### What it cannot reproduce by itself

- Physical-link propagation delay
- Switch ASIC behavior
- NIC DMA and interrupt behavior
- Multi-host clock synchronization
- Real internet congestion, loss, path changes, or adversaries

## Questions mapped to project stages

| Question | Stage that answers it |
| --- | --- |
| What is the internet? | Simulated internet and router stage |
| Public address versus private address? | Namespace and NAT stage |
| How do public VPNs use static addresses? | Public coordination and gateway stage |
| What does “behind a firewall” mean? | Stateful firewall stage |
| How does outward client traffic work? | NAT connection-tracking stage |
| How does the public address forward replies? | NAT translation-table stage |
| Do ports belong to TCP? | TCP and UDP socket stage |
| How do cryptographic handshakes work? | Authenticated handshake stage |
| What are subnets? | Routing-table stage |
| What is a subnet router? | Route-advertisement stage |
| How does this relate to distributed systems? | Membership, discovery, failure, leases, and policy stages |
| What is a container? | Namespace, cgroup, image, and container-network stage |

## Stage 1: Sockets, addresses, and ports

Build four small modes inside one binary:

```bash
meshlet tcp-server
meshlet tcp-client
meshlet udp-server
meshlet udp-client
```

Each mode should print:

- Local socket address
- Remote socket address
- Number of bytes sent or received
- The exact received bytes

A socket address is:

IP address + port

But the complete identity of a transport endpoint includes the protocol:

```text
TCP + 192.0.2.10 + port 8000
UDP + 192.0.2.10 + port 8000
```

Ports do not belong to IP itself. Both TCP and UDP have separate 16-bit source-port and destination-port fields in their own headers.

Therefore, these can coexist:

```text
TCP port 8000
UDP port 8000
```

They are distinct because the protocol differs.

The first packet experiment will show:

```text
Ethernet frame
    contains an IP packet
        contains a TCP segment or UDP datagram
            contains your application bytes
```

We will inspect this with tcpdump.

## Stage 2: Construct a small internet

The internet is not one giant network owned by one entity.

It is a collection of separate networks connected by routers:

Network a ── router ── network b ── router ── network c

An IP packet contains a destination IP address. Each router consults a routing table and chooses where to send the packet next.

A routing table contains rules like:

```text
Destination prefix     next hop
10.10.0.0/24           interface a
10.20.0.0/24           interface b
0.0.0.0/0              upstream router
```

A prefix represents a set of IP addresses used for route matching. In
`10.10.0.0/24`, the first 24 address bits must match 10.10.0. The remaining 8
bits distinguish addresses inside that prefix.

Approximately:

Network:
    10.10.0.x

Possible final byte:
    0 through 255

The final 8 bits are sometimes called the host portion, but they are not a MAC address. An IP address and a MAC address are separate identifiers:

IP address:
    used for end-to-end routing across networks

MAC address:
    used to deliver an Ethernet frame across one local link

A router normally preserves the source and destination IP addresses, decreases TTL, removes the incoming Ethernet frame, and creates a new Ethernet frame for the next link.

We will create several namespaces and connect them with virtual Ethernet pairs. A veth pair is two virtual interfaces joined by the kernel: an Ethernet frame sent into one endpoint appears at the other endpoint.

This stage is complete when:

- Node A reaches node B through a router
- tcpdump on both router interfaces shows changing MAC addresses
- The IP endpoints and transport ports remain stable
- TTL decreases by one router hop

## Stage 3: Private addresses, public addresses, and NAT

Private IPv4 ranges include:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`

These addresses are not globally routed across the public internet.

Your laptop might use `192.168.1.20`, while its router uses a public address
assigned by an internet provider, such as `203.0.113.50` in this lab.

NAT translates between them.

Suppose your laptop sends:

```text
Protocol:       UDP
source:         192.168.1.20:50000
destination:    198.51.100.30:9000
```

The router may rewrite it as:

```text
Protocol:       UDP
source:         203.0.113.50:62001
destination:    198.51.100.30:9000
```

The router records a mapping:

```text
UDP 203.0.113.50:62001
    ↔
UDP 192.168.1.20:50000
```

When a reply arrives for 203.0.113.50:62001, the router looks up the entry, rewrites the destination, and forwards it to the laptop.

This directly answers how one public address can serve several private devices.

The mapping includes a port because many internal connections share the same public IP.

Our observed NAT trace is:

Private side request:
    10.10.0.2:48700 → 192.0.2.20:8000

Public side request:
    192.0.2.10:48700 → 192.0.2.20:8000

Public side reply:
    192.0.2.20:8000 → 192.0.2.10:48700

Private side reply:
    192.0.2.20:8000 → 10.10.0.2:48700

The experiment matters because it proves the transformation and reverse mapping. The nftables syntax is only how this one-machine lab requests that behavior.

## Stage 4: “Behind a firewall”

A stateful firewall remembers active communication.

When the private client sends outward:

Client → server

The firewall records state describing that flow.

A simplified flow key is called the five-tuple:

- Source IP
- Source port
- Destination IP
- Destination port
- Transport protocol

A matching reply (`server → client`) is accepted because the firewall
recognizes it as part of an existing flow.

An unrelated inbound packet (`unknown internet host → private client`) is
rejected because:

- No matching connection state exists
- No explicit inbound firewall rule exists

This is what “the client is behind a firewall but can connect outward” means.

The client initiates communication. The firewall permits matching responses.

The fundamental experiment is intentionally small:

1. Permit a new private-to-public flow
2. Permit the matching reply
3. Reject a new public-to-private flow
4. Prove where the rejected packet stopped

We care about the state machine and packet path, not memorizing firewall configuration syntax.

Run the executable model:

```bash
cargo run -- firewall-demo
```

`cargo run` compiles and starts the debug binary. `--` ends cargo's own options, so `firewall-demo` is passed to Meshlet as its mode.

The model stores exact reply flows in a hash map until their deadline. It lets us inspect the decision rule without mixing it with Linux configuration. It is not yet a packet firewall: it does not parse live packets, forward them, model TCP handshake states, or handle concurrent access. The next experiment compares this small model with the kernel's real connection tracking.

### Live packet experiment

Rebuild the three-network-namespace topology, then install the experiment rules:

```bash
bash namespaces.md
bash lab/firewall-live.sh setup
```

The setup adds one temporary route so mesh-b can deliver an unsolicited packet to the router. Without that route, mesh-b itself would report “network is unreachable,” and the firewall would never receive the packet.

The router's forwarding policy is:

Private r0 → public r1:
    allow new exchanges and packets belonging to tracked exchanges

Public r1 → private r0:
    allow only packets belonging to tracked exchanges

Anything else:
    count and drop

`ct` means connection tracking: kernel-maintained memory about observed packet flows. `new` means the packet begins a flow the tracker has not yet seen in both directions. `established` means the tracker has seen traffic that belongs to an existing two-way exchange. `related` means a separate flow is associated with an existing one, such as some network error messages. `counter` records matching packet and byte totals. `drop` stops the packet; `accept` permits it to continue through this firewall hook.

Show the rules and their counters at any time:

```bash
bash lab/firewall-live.sh show
```

Remove only this experiment's firewall table and temporary route:

```bash
bash lab/firewall-live.sh cleanup
```

A firewall and NAT are different even when one router performs both:

NAT:
    rewrites addresses or ports

Firewall:
    decides whether a packet may continue

## Stage 5: Static public VPN addresses

A public VPN gateway needs a stable location clients can contact.

Commercial VPN operators commonly obtain addresses from:

- A cloud provider
- A hosting provider
- An internet service provider
- An address block they control

The address remains assigned to the gateway or to the provider’s virtual networking configuration.

A client can therefore store:

`vpn.example.com:51820`

DNS translates the hostname into a public IP address.

For our project, the coordination server and relay will receive fixed addresses inside the simulated public network:

Coordination server:
    203.0.113.10

Relay:
    203.0.113.20

The private nodes will always know how to contact them.

This reproduces the important property of a public VPN gateway without renting an actual internet server.

## Stage 6: Control plane and distributed-systems membership

The control plane distributes decisions and metadata. It is not normally on the per-packet data path:

Control plane:
    who is a member, which identity key belongs to whom, which endpoint is current, which routes and policies are allowed

Data plane:
    the repeated movement of application packets between nodes

This separation exists so nodes can exchange most packets directly without sending every payload through a central coordinator.

Each node will generate a persistent node ID and register with the coordinator:

- Node ID
- Identity public key
- Current UDP endpoint
- Overlay IP address
- Advertised subnet routes
- Last heartbeat time

The coordinator maintains a membership table:

Node a:
    alive
    endpoint = 192.0.2.10:41000

Node b:
    alive
    endpoint = 198.51.100.10:42000

This introduces distributed-systems problems:

Identity versus location

The node identity should remain stable while its network address changes.

Identity:
    node a

Old location:
    192.0.2.10:41000

New location:
    192.0.2.44:53000
failure detection

The coordinator cannot know immediately whether a node crashed or lost connectivity.

Nodes send periodic heartbeats.

The coordinator treats a node as unavailable when its heartbeat expires.

This is not perfect knowledge. A missing heartbeat could mean:

- Node crashed
- Network dropped packets
- Router failed
- Coordinator was temporarily unreachable

That uncertainty is fundamental in distributed systems.

Leases

A registration will have an expiration time.

The node must periodically renew it.

This prevents stale addresses from remaining valid forever.

The coordinator is authoritative for membership metadata but does not have perfect knowledge of reality. Heartbeats and leases turn silence into a time-bounded guess. This stage will make that uncertainty explicit with expiration, re-registration, duplicate messages, and an unreachable node.

First coordinator implementation

The first version is an in-memory UDP service. It supports two versioned messages:

MESHLET/1 REGISTER NODE_ID LEASE_SECONDS
MESHLET/1 LOOKUP NODE_ID

`MESHLET/1` is a protocol-version label. A protocol is an agreed message format and behavior. Including the version lets a receiver reject message formats it does not understand instead of silently misinterpreting them.

The registry maps:

`node ID → observed UDP source endpoint + expiration deadline`

The endpoint is observed from the received UDP datagram. It is not accepted from a claimed address inside the request. Behind NAT, this means the coordinator sees the router's translated source endpoint rather than the node's private endpoint.

The datagram is bounded to 1024 bytes, node IDs are bounded and validated, leases are limited to 1–300 seconds, messages have an explicit version, clients use a response timeout, and expiration is tested with a caller-controlled monotonic time. These are transferable production principles; this teaching protocol and implementation are original to Meshlet.

The first version intentionally has no authentication and stores no durable data. Anyone who can contact it can claim or replace a node ID, and all entries disappear if the coordinator process restarts. We will demonstrate the identity flaw before adding cryptographic authentication.

Coordinator modes:

```bash
meshlet coordinator-server [BIND_ADDRESS]
meshlet coordinator-register [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID] [LEASE_SECONDS]
meshlet coordinator-lookup [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID]
```

Live namespace experiment

Rebuild the topology and binary:

```bash
bash namespaces.md
cargo build
```

The current lab uses four simulated machines. `mesh-a` and `mesh-b` are peers,
`mesh-r` is their router, and `mesh-c` is the coordinator. A simulated machine
is a network namespace: a separate network stack inside the same Linux kernel.
The coordinator is a process running inside `mesh-c`; in a real deployment it
would normally run on a separate host, VM, or container.

Start the coordinator on mesh-c:

```bash
sudo ip netns exec mesh-c target/debug/meshlet \
  coordinator-server 203.0.113.10:9000
```

Register mesh-a for 30 seconds:

```bash
sudo ip netns exec mesh-a target/debug/meshlet \
  coordinator-register 10.10.0.2:0 203.0.113.10:9000 mesh-a 30
```

Look it up before the lease expires:

```bash
sudo ip netns exec mesh-b target/debug/meshlet \
  coordinator-lookup 192.0.2.20:0 203.0.113.10:9000 mesh-a
```

The client knows its private local endpoint, while the coordinator should report
a source endpoint translated to the router's `203.0.113.1` address. This is
location discovery: the service tells a node how another packet appeared at a
shared observation point.

Authenticated coordinator registration

The two keys have different capabilities:

Private key:
    secret bytes held by the node. They can create signatures. Possession of
    these bytes is what lets a process act as that node.

Public key:
    non-secret bytes copied to the coordinator. They can verify signatures but
    cannot feasibly create one or recover the private key.

A signature is a fixed-size mathematical proof tied to the exact message bytes
and a private key. Verification is the yes/no calculation performed with the
corresponding public key. This provides authentication and tamper detection; it
does not encrypt the message or hide it.

The coordinator's authorization file is the initial trust decision:

Mesh-a -> mesh-a's public key

The mathematics proves that a signature matches that key. The file tells the
coordinator which key is allowed to act as `mesh-a`. Safely adding that mapping
is called enrollment.

Version 2 adds a challenge-response exchange. A challenge is a fresh random
value chosen by the verifier. It is public, not a password. Its purpose is to
make this registration different from every earlier registration:

1. Node asks for a challenge using its node ID
2. Coordinator generates an unpredictable 32-byte challenge and binds it to that node ID plus the observed UDP source endpoint for 10 seconds
3. Node signs a canonical registration message containing the node ID, requested lease, and challenge
4. Coordinator finds the pre-authorized public key for that node ID and strictly verifies the Ed25519 signature
5. Coordinator consumes the challenge and records the observed endpoint only after verification succeeds

The word nonce means a value intended for one use. Replay means sending an old,
previously valid message again. Consuming the nonce prevents replay. Binding it
to the observed source prevents its use from a different endpoint. Signing the
lease prevents someone from changing a signed 30-second lease into 300 seconds.

Any caller may receive a challenge. That is safe: only the owner of the
authorized private key can produce the required answer. The observed impostor
experiment reached the coordinator and received a challenge, but its different
private key produced a signature that did not match the authorized public key,
so verification failed.

The learning keys live under `.meshlet/keys` so every file is visible inside the
project. `.meshlet` is excluded by `.gitignore`: private keys must not enter git
history. The private identity file uses Unix mode 0600, meaning only its owner
may read or write it. The directory uses mode 0700, meaning only its owner may
list or enter it. Public authorization files are non-secret. Key generation
refuses to overwrite either output.

Create the private project directory and generate a node identity:

```bash
mkdir -p -m 700 .meshlet/keys
target/debug/meshlet identity-generate mesh-a \
  .meshlet/keys/mesh-a.identity \
  .meshlet/keys/authorized-nodes
```

Start the authenticated coordinator:

```bash
sudo ip netns exec mesh-c target/debug/meshlet \
  coordinator-server-auth 203.0.113.10:9000 \
  .meshlet/keys/authorized-nodes
```

Register using the private identity:

```bash
sudo ip netns exec mesh-a target/debug/meshlet \
  coordinator-register-auth \
  10.10.0.2:0 203.0.113.10:9000 mesh-a 120 \
  .meshlet/keys/mesh-a.identity
```

Look up the authenticated registration:

```bash
sudo ip netns exec mesh-b target/debug/meshlet \
  coordinator-lookup-auth \
  192.0.2.20:0 203.0.113.10:9000 mesh-a
```

This proves control of the private signing key authorized for `mesh-a`, recent round-trip access to the observed endpoint, and agreement on the signed registration fields. It does not prove that the node is uncompromised, that another peer can reach it, or that it remains alive for the entire lease.

The current protocol authenticates the registering node only. It does not
authenticate the coordinator to the node, encrypt control messages, authorize
lookup callers, limit request rates, persist state, rotate keys, or revoke a
stolen key. Those omissions are visible boundaries of the learning stage, not
production security claims.

### Production security extension

The project-local key directory is a deliberate learning compromise: visible,
inspectable, and protected from accidental git commits. A production system
would normally store private keys in a restricted operating-system secret
store, or use a TPM or HSM: hardware designed to perform cryptographic
operations without releasing the private key bytes. A hosted service may use a
KMS, meaning a managed key-management service. Production also needs protected
enrollment, key rotation (replacing keys), revocation (declaring a key no longer
trusted), encrypted backups, access auditing, and a protected channel to the
coordinator. Public keys may be distributed widely; private keys must never be
logged or copied into source control.

## Stage 7: Authenticated cryptographic handshake

We will not implement encryption algorithms ourselves. We will use established implementations but build the handshake protocol and state machine ourselves.

The four separate cryptographic goals are:

Identity authentication:
    prove which long-term node signed a handshake

Key agreement:
    derive a shared secret without sending that secret

Key derivation:
    turn shared material and transcript context into independent directional keys

Authenticated encryption:
    hide packet contents and reject modification

Each node will have two kinds of keys.

Identity key:
    Ed25519
    used to sign and verify handshake messages

Ephemeral exchange key:
    X25519
    used to derive a temporary shared secret

The implemented handshake uses two packets, so it takes one network round trip:

Node a → node b:

Client hello
    node a ephemeral public key
    signature over the protocol version, both node IDs, and that public key

The identity public key is not sent as self-asserted truth. Node b loads the
public key already authorized for node a and uses that key to verify the
signature.

Node b performs:

1. Look up node a's expected identity key

2. Verify the signature

3. Reject the message if verification fails

4. Generate its own ephemeral X25519 key pair

Then node b returns:

Server hello
    node b ephemeral public key
    signature over both node IDs and both ephemeral public keys

Node a verifies that signature using the public identity key it already trusts
for node b. Each ephemeral key pair is freshly generated for one handshake.

Both sides compute:

Shared secret =
    X25519(our ephemeral private key,
           peer ephemeral public key)

The mathematical operation produces the same shared secret on both nodes without transmitting that secret.

The secret is passed through HKDF:

Shared secret
    + Handshake transcript
    ↓
HKDF
    ↓
a-to-b encryption key
b-to-a encryption key

Data packets now use chacha20-poly1305.

Chacha20-poly1305 is an aead: authenticated encryption with associated data. The encrypted payload is confidential, while selected unencrypted headers can still be covered by integrity protection.

It provides:

Confidentiality:
    outsiders cannot read the contents

Integrity:
    modified packets fail verification

Authentication:
    a valid packet proves knowledge of the session key

Discarding the ephemeral private keys after the handshake provides forward secrecy: later theft of the long-term identity key should not reveal previously recorded session traffic.

The implementation derives two 32-byte directional keys:

Client to server key
server to client key

Directional means each traffic direction receives a different key. Therefore,
both directions may start their packet number at zero without reusing a nonce
with the same key.

Each encrypted UDP datagram contains:

Visible header
    Meshlet packet marker
    direction
    packet number

Encrypted body
    application bytes
    authentication tag

Ciphertext means the unreadable encrypted form of the application bytes. The
16-byte authentication tag is a compact check produced by the cipher; the
receiver rejects the packet if the key, header, or ciphertext does not match it.

A nonce is a value that must be unique for every packet encrypted with one
key. Meshlet constructs it from the direction and packet number. It is not a
secret. The packet number starts at zero and increases. The receiver expects
the next number, so the same datagram cannot be accepted twice.

The visible header is associated data: it is not hidden, but it is included in
the authentication calculation. Changing either the header or ciphertext makes
the packet invalid.

The client sends one encrypted message and the server returns its decrypted
bytes through the opposite directional key. Successfully decrypting those
packets confirms that both peers derived the same keys. The keys disappear when
the two learning processes exit.

Live encrypted-echo experiment

Start the one-exchange server inside mesh-b's network namespace:

```bash
sudo ip netns exec mesh-b target/release/meshlet \
  secure-echo-server \
  192.0.2.20:7000 \
  .meshlet/keys/mesh-b.identity \
  .meshlet/keys/authorized-nodes
```

Observe the whole exchange on every mesh-r interface:

```bash
sudo ip netns exec mesh-r \
  tcpdump -nni any -X 'udp port 7000'
```

Run the client inside mesh-a's network namespace:

```bash
sudo ip netns exec mesh-a target/release/meshlet \
  secure-echo-client \
  10.10.0.2:0 \
  192.0.2.20:7000 \
  .meshlet/keys/mesh-a.identity \
  mesh-b \
  .meshlet/keys/mesh-b.authorization
```

There are four UDP datagrams: client hello, server hello, encrypted request,
and encrypted echo. Because `-i any` watches both router interfaces, it normally
shows each datagram once entering and once leaving: eight capture lines. The
hello fields remain visible. The last two datagrams expose only the 13-byte
header (`MSH3`, direction, and packet number) followed by ciphertext and a
16-byte authentication tag. `hello from encrypted meshlet` appears only in the
processes' decrypted output, not in those captured datagrams.

The client reports handshake time separately from encrypted-echo round-trip
time. The server separately reports handshake cryptography and data-packet
cryptography. Each number is one observation, not a stable benchmark.

On a real wide-area path, the network round trip will usually dominate this
setup cost. After the handshake, key agreement and identity signatures are
not repeated for every data packet; the cheaper symmetric packet cipher will
operate on the data path.

This is deliberately a one-exchange learning server. Retries, concurrent
clients, out-of-order delivery, key rotation, and session resumption are omitted
until an experiment gives us a concrete reason to introduce them.

We use established library implementations and explicit byte encodings.
Production systems do not copy cryptographic primitives into application code.

## Stage 8: Direct connectivity and relay fallback

Connectivity means that packets sent to an endpoint can actually reach the intended node and that replies can return. Knowing an IP address is not enough when NAT mappings, firewalls, or changing ports affect the path.

We will build this in two small steps. First, run the same secure echo directly
and through a relay so the two data paths are visible. Second, add automatic
probing and path selection. This keeps forwarding separate from the later
decision about which path to use.

The first relay is deliberately a one-client, one-exchange UDP process:

Client endpoint ← relay socket → configured server endpoint

An endpoint is an IP address plus a UDP port. The relay learns the client's
endpoint from the source of the first datagram. It already knows the server's
endpoint from its command line. It then copies each received datagram to the
other endpoint without parsing or changing its payload.

Opaque means the relay treats the payload as an uninterpreted sequence of
bytes. The end nodes still perform the handshake, authenticate node identities,
derive session keys, and encrypt the request. The relay has none of those keys.

This relay is not an IP router. The kernel router forwards an IP packet by
looking up that packet's destination address. The relay is a userspace program:
it receives one UDP datagram addressed to its own socket, then sends a new UDP
datagram containing the same payload toward the other endpoint.

### Live relayed encrypted-echo experiment

If the namespaces were created before the relay address was added to
`namespaces.md`, add that address to mesh-c's existing interface:

```bash
sudo ip -n mesh-c address replace 203.0.113.20/24 dev c0
```

Start the existing encrypted server in mesh-b:

```bash
sudo ip netns exec mesh-b target/release/meshlet \
  secure-echo-server \
  192.0.2.20:7000 \
  .meshlet/keys/mesh-b.identity \
  .meshlet/keys/authorized-nodes
```

Start the relay at a second address in mesh-c. Its configured upstream is the
encrypted server:

```bash
sudo ip netns exec mesh-c target/release/meshlet \
  udp-relay \
  203.0.113.20:7100 \
  192.0.2.20:7000
```

Observe both UDP legs on every router interface:

```bash
sudo ip netns exec mesh-r \
  tcpdump -nni any -X '(udp port 7000 or udp port 7100)'
```

Run the same secure client, changing only its destination from the direct
server endpoint to the relay endpoint:

```bash
sudo ip netns exec mesh-a target/release/meshlet \
  secure-echo-client \
  10.10.0.2:0 \
  203.0.113.20:7100 \
  .meshlet/keys/mesh-a.identity \
  mesh-b \
  .meshlet/keys/mesh-b.authorization
```

The secure exchange still has four logical messages: client hello, server
hello, encrypted request, and encrypted echo. Each message now travels in two
UDP datagrams: endpoint to relay, then relay to the other endpoint. That makes
eight network datagrams. `tcpdump -i any` normally observes each once entering
and once leaving mesh-r, producing about sixteen capture records.

Mesh-b will report the relay socket as its network peer, but it will still
report `mesh-a` as the authenticated node. This distinction is fundamental:
an endpoint says where the current packet came from; cryptographic identity
says which key signed the handshake.

The relay adds a userspace receive, a userspace send, another routed leg, and
more opportunities to wait in queues or for process scheduling. Compare its
round-trip time with the earlier direct observation, but treat each single run
as an example rather than a benchmark.

This first relay intentionally omits multiple clients, long-lived sessions,
registration, authentication at the relay, retries, and rate limits. None is
needed to observe the fundamental forwarding path.

The automatic-selection step will work as follows. Nodes first exchange
observed UDP endpoints through the coordinator.

They send small probes toward one another:

Node a → node b endpoint
node b → node a endpoint

These outbound probes create NAT state.

When this succeeds, encrypted packets travel directly.

When it fails, both nodes maintain outbound paths to a multi-node relay:

Node a → relay ← node b

Unlike the one-client relay above, that relay will need a small visible routing
envelope such as:

Destination node ID
encrypted payload

It forwards the payload but does not possess the session encryption key.

This demonstrates the difference between:

Routing bytes
and
understanding bytes

The decision will be evidence-driven:

Probing:
    send small authenticated messages over a candidate path

Timeout:
    stop waiting after a defined interval

Fallback:
    use the relay when no direct path is confirmed

Recovery:
    keep testing whether a lower-latency direct path becomes available

The relay adds another network hop and more queueing opportunity, so we will measure direct and relayed RTT separately. It must learn only the routing envelope needed to forward ciphertext, not the decrypted payload.

`secure-echo-client-auto` implements the first three decisions with the existing
authenticated handshake. It waits up to 250 milliseconds for a valid direct
server hello. A network error or timeout permits a relay attempt. A malformed
or incorrectly signed response stops the operation instead of being treated as
a reachability problem. Once one path completes the handshake, the client uses
that session for encrypted data rather than performing a separate probe round
trip.
## Stage 9: Overlay addresses and TUN interfaces

Initially, Meshlet will send application messages.

Later, it will create a Linux TUN interface.

A TUN interface behaves like a virtual layer-3 network card.

Layer 3 means the TUN interface reads and writes IP packets. It does not carry Ethernet headers or MAC addresses. A tap interface is the related layer-2 mechanism that carries Ethernet frames; Meshlet uses TUN because the overlay routes IP.

The kernel writes complete IP packets into it:

Application
    ↓
Linux TCP/IP stack
    ↓
meshlet0 TUN interface
    ↓
Meshlet process reads raw IP packet bytes

The process then:

Reads destination overlay IP
chooses a peer
encrypts the IP packet
sends it over UDP

The receiving node:

Receives ciphertext
verifies and decrypts it
writes the recovered IP packet into its TUN interface

The receiving kernel then delivers it to the destination application.

At this point, ordinary programs can communicate through the overlay without knowing that Meshlet exists.

This is the key abstraction boundary:

Ordinary application:
    opens normal TCP or UDP sockets to an overlay IP

Kernel:
    constructs an IP packet and selects meshlet0

Meshlet process:
    reads the packet, chooses a peer, encrypts it, transports it, decrypts the peer packet, and writes it back to TUN

We will first forward one visible ICMP packet, then add encryption. This keeps packet transport separate from cryptographic correctness.

The first implementation is `tun-udp-one`. It attaches to an existing Linux
TUN interface and handles one IPv4 packet in each direction. One worker reads a
kernel-produced IP packet from TUN and sends those exact bytes as a UDP payload.
The other receives a UDP payload and writes the recovered IP packet into TUN.

Start the mesh-b endpoint:

```bash
sudo ip netns exec mesh-b target/release/meshlet \
  tun-udp-one meshlet0 192.0.2.20:7200 192.0.2.10:7200
```

Start the mesh-a endpoint:

```bash
sudo ip netns exec mesh-a target/release/meshlet \
  tun-udp-one meshlet0 10.10.0.2:7200 192.0.2.20:7200
```

Observe the outer UDP transport at the router:

```bash
sudo ip netns exec mesh-r tcpdump -nni any -X 'udp port 7200'
```

Ask mesh-a's ordinary Linux IP stack to send one ICMP echo request to mesh-b's
overlay address:

```bash
sudo ip netns exec mesh-a ping -c 1 -W 1 100.64.0.2
```

`ping` knows nothing about Meshlet or UDP. Its packet follows the connected
`100.64.0.0/24` route into `meshlet0`; Meshlet reads it, carries it through UDP,
and writes it into mesh-b's `meshlet0`. The reply follows the reverse path.

This first packet transport is intentionally visible, so the capture exposes
the complete inner IP packet inside the outer UDP payload. Placing the existing
authenticated-encryption packet format between the TUN and UDP operations is
an integration step, not a new networking concept, so the learning path moves
next to subnet routing.

## Stage 10: Subnets and subnet routers

I assume “subsets” meant subnets.

A subnet is a set of IP addresses represented by a prefix:

10.20.0.0/16

A subnet router is a node that can reach that entire prefix and agrees to forward packets into it.

Suppose node b is connected to:

Legacy subnet:
    10.20.0.0/16

Node b advertises to the coordinator:

I can route packets for 10.20.0.0/16

Node a receives a routing rule:

Destination 10.20.0.0/16
    → encrypted tunnel to node b

Node b decrypts the packet and forwards it onto the legacy subnet.

We will implement route selection using longest-prefix matching.

Given:

10.0.0.0/8       → router x
10.20.0.0/16     → router y
10.20.30.0/24    → router z

A packet for 10.20.30.5 uses router z, because /24 is the most specific matching prefix.

Longest-prefix matching means selecting the matching route with the greatest prefix length. It chooses the most specific address set, not the route with the numerically largest address.

A subnet router differs from an ordinary overlay endpoint:

Ordinary endpoint:
    receives packets addressed to itself

Subnet router:
    advertises reachability for a prefix and forwards packets to other machines behind it

Route advertisement is a claim, not proof. The control plane must decide whether to authorize, distribute, expire, or prefer that claim.

The first subnet-router topology adds a machine that does not run Meshlet:

Mesh-a 100.64.0.1
    ↓ TUN and UDP
mesh-b 100.64.0.2 and 10.30.0.1
    ↓ ordinary routed link
mesh-d 10.30.0.2

`mesh-b` is the subnet router because it connects the overlay to
`10.30.0.0/24` and has Linux IP forwarding enabled. `mesh-a` routes that prefix
into `meshlet0`. `mesh-d` routes replies for the overlay prefix through
`10.30.0.1`.

The Meshlet packet code is unchanged. An IP tunnel can carry a packet whose
destination is the remote VPN node or a machine reachable through that node.

Start the mesh-b and mesh-a `tun-udp-one` processes exactly as in stage 9. In a
third terminal, observe the inner packet crossing mesh-b:

```bash
sudo ip netns exec mesh-b tcpdump -nni any 'icmp'
```

Then send one ordinary ping from mesh-a to the machine behind mesh-b:

```bash
sudo ip netns exec mesh-a ping -c 1 -W 1 10.30.0.2
```

The request enters mesh-b through `meshlet0` and leaves through `b1`. The reply
enters through `b1` and leaves through `meshlet0`. The reported inner TTL is 63
because mesh-b routed the inner packet once. Mesh-r routes the outer UDP packet
but does not modify the encapsulated inner packet's TTL.

This proves the forwarding mechanism. The next step is the control decision:
represent advertised prefixes and select the most specific matching peer using
longest-prefix matching.

### Route-advertisement experiment

The data path already knows how to carry and forward an IP packet. This
experiment adds the control-plane decision that happens before that data path
is used:

1. A node sends a claim that it can route a prefix.
2. The coordinator stores the claim until its lease expires.
3. `mesh-a` asks which node should receive a particular destination.

This learning path is intentionally unauthenticated. In production, the
coordinator would authenticate the node making a route claim and apply policy
to the prefixes it may advertise. The earlier authentication and encryption
experiments remain in the project; they are simply not part of this stage.

Start the route-aware coordinator in `mesh-c`:

```sh
sudo ip netns exec mesh-c target/release/meshlet \
  coordinator-route-server \
  203.0.113.10:9001
```

`ip netns exec mesh-c` runs the process with mesh-c's isolated network stack.
The remaining argument selects the coordinator's UDP endpoint.

While it remains running, publish the real subnet route from `mesh-b`:

```sh
sudo ip netns exec mesh-b target/release/meshlet \
  coordinator-advertise-route \
  192.0.2.20:0 203.0.113.10:9001 \
  mesh-b 10.30.0.0/24 120
```

`192.0.2.20:0` means bind locally to that IP address and let Linux choose an
unused UDP source port. `120` is the lease lifetime in seconds.

Before those leases expire, ask from `mesh-a` which node should receive a
packet addressed to `10.30.0.2`:

```sh
sudo ip netns exec mesh-a target/release/meshlet \
  coordinator-route-lookup \
  10.10.0.2:0 203.0.113.10:9001 \
  10.30.0.2
```

The expected decision is:

```text
MESHLET/1 ROUTE_FOUND 10.30.0.2 10.30.0.0/24 mesh-b
```

The lookup still uses longest-prefix matching. Overlapping-prefix selection is
covered by the Rust tests rather than by an artificial learner command. This
control plane returns `prefix -> node`. Endpoint lookup, tunnel setup, and
installing a Linux route are separate actions; they are not hidden inside this
command.

Observed result:

```text
MESHLET/1 ROUTE_ADVERTISED mesh-b 10.30.0.0/24 120
MESHLET/1 ROUTE_FOUND 10.30.0.2 10.30.0.0/24 mesh-b
```

Mesh-a's lookup reached the coordinator from `203.0.113.1`, the public source
address assigned by mesh-r's NAT. The coordinator selected mesh-b but did not
send a data packet or change either node's Linux routing table.

## Stage 11: Containers from first principles

A container is an ordinary process whose operating-system view and resource
usage are constrained.

**Namespaces isolate what the process can see:**

- Process IDs
- Mounts
- Hostname
- Users
- Network interfaces, addresses, routes, and sockets

**Cgroups account for and limit resources:**

- CPU time
- Memory
- Process count
- I/O

An image supplies a filesystem and metadata used to start the process. A
container runtime assembles the namespaces, cgroups, filesystem, environment,
and process. Unlike a virtual machine, a typical container shares the host
kernel.

Container networking automates primitives we are already using manually:

```text
container network namespace
    ↕ veth pair
host bridge or routed interface
    ↕ routing, nat, and policy
other containers or external networks
```

The learning experiment will create the equivalent topology manually, then run the same Meshlet process through a container runtime and identify which kernel objects the runtime created. The goal is to understand the abstraction, not memorize Docker or Kubernetes commands.

#### Learning approach: toy mechanisms before products

The goal is to predict what the kernel and runtime do, then measure their cost.
We will not build an image registry, orchestrator, production sandbox, or full
Linux system-call implementation.

#### Language sequencing

Stage 11 uses Go for the toy launcher because process creation and Linux
runtime code are a natural fit for it. Go and containers are not taught
simultaneously. First, write an ordinary Go program that starts an ordinary
child process. Only after that code is understood is each Linux isolation
mechanism added one at a time.

Each increment should be small enough to explain completely before it is used.

#### Fast-feedback contract

1. A unit test should finish in about one second.
2. A live mechanism experiment should finish in under five seconds.
3. A focused benchmark should finish in under thirty seconds.
4. Reuse one local root filesystem and one release binary; do not rebuild or
   download an image for every experiment
5. Change one isolation boundary at a time and compare against the same native
   workload

### 11.0: Go and ordinary process execution

This is a language prerequisite, not yet a container.

Go sequence:

1. Create a module and one `package main` source file
2. Define `func main`, print values, and read command-line arguments
3. Move validation into a function and return an explicit `error`
4. Construct an `exec.Cmd` describing a child program
5. Connect the child's input and output to the terminal and run it
6. Inspect the parent and child with `ps`

Every new Go term will be defined when it first appears: package, import,
function, variable, slice, variadic argument, multiple return values, interface,
pointer, method, and error. Concurrency, garbage collection, interfaces of our
own, and networking are deliberately postponed.

**Checkpoint:**
    the Go launcher runs a selected one-shot command with no isolation. Its
    behavior is still equivalent to starting an ordinary child process.

### 11.1: Process plus namespaces

**Mental model.** A container starts as an ordinary process. Namespaces change
which kernel objects that process can see.

**Linux experiment.** Use `unshare` to give one short-lived Meshlet command new
PID, hostname, and mount views. Use `lsns`, `ps`, and `/proc/PID/ns` to compare
the outer and isolated views.

**Toy implementation.** Extend the understood Go launcher with one namespace
flag at a time. It is a teaching launcher, not a security boundary.

**Prediction to learn.** The program code is unchanged; only its
operating-system view changes.

### 11.2: cgroup v2

**Mental model.** A namespace controls visibility. A cgroup accounts for and
limits resource consumption. Neither concept implies the other.

**Linux experiment.** Place one deterministic worker in a child cgroup,
inspect `cpu.stat` and `memory.current`, then apply one safe CPU or memory
limit.

**Toy implementation.** Extend the launcher by writing the child PID and
limits to the cgroup v2 filesystem. No daemon or scheduler is added.

**Prediction to learn.** The process sees the same instructions, but the
kernel changes how much CPU or memory it may consume.

### 11.3: Root filesystem and image

**Mental model.** A root filesystem is the directory tree a process sees as
`/`. An image is a stored, transportable description of filesystem layers and
startup metadata; it is not a running container.

**Linux experiment.** Construct one tiny local root filesystem, enter it with
a new mount namespace, and observe which files do and do not exist.

**Toy implementation.** Add root-directory selection, a private `/proc`, a
working directory, and environment variables to the launcher. Skip layered
filesystems and image distribution.

**Prediction to learn.** Process isolation and filesystem packaging are
separate mechanisms.

### 11.4: OCI bundles and `runc`

OCI means Open Container Initiative. Its runtime specification defines a
portable bundle: a `config.json` description plus a root filesystem. `runc` is
a low-level OCI runtime that reads that bundle, creates the requested
namespaces, mounts, and cgroup, and starts the configured process.

**Experiment:**
    express the same toy launcher configuration as an OCI bundle; run it with
    `runc create`, `runc state`, `runc start`, and `runc delete`; compare the
    resulting namespace identifiers and cgroup membership.

**Important boundary:**
    `runc` mainly constructs and starts the environment. After startup, an
    ordinary native-container application still makes system calls directly to
    the host Linux kernel. `runc` is not a proxy on every application request.

**Official references:**
    https://github.com/opencontainers/runtime-spec/blob/main/runtime.md
    https://github.com/opencontainers/runc/blob/main/README.md

### 11.5: Higher-level runtime, briefly

**Mental model:**
    Podman or Docker manages images, defaults, networking, and lifecycle; it
    eventually delegates low-level process creation to an OCI runtime such as
    `runc`.

**Experiment:**
    run the same local workload once with Podman and inspect its process tree,
    namespace identifiers, cgroup, mounts, and generated OCI configuration.

**Scope boundary:**
    stop after mapping the layers. Do not introduce Kubernetes, deployment
    manifests, registries, or container administration.

### 11.6: gVisor and `runsc`

GVisor is different from a native `runc` container. Its `runsc` OCI runtime
starts a userspace application kernel called the Sentry. Most application
system calls are handled by the Sentry instead of going directly to the host
Linux kernel. GVisor also normally uses its own userspace network stack,
Netstack.

**Mental model:**

Native or runc container:
    application -> host Linux system call

GVisor:
    application -> Sentry implementation -> limited host Linux operations

**Toy implementation:**
    build a tiny userspace operation broker. A toy application asks it to
    perform only a few abstract operations such as reading a file or sending a
    UDP datagram. This demonstrates mediation but will not pretend to intercept
    arbitrary Linux system calls or provide real sandbox security.

**Real experiment:**
    run the same OCI bundle with `runsc`, inspect its Sentry process and network
    view, then compare behavior with `runc`. Use the current `systrap` platform
    first; compare KVM only if the host exposes suitable hardware support.

**Official references:**
    https://gVisor.dev/docs/
    https://gVisor.dev/docs/architecture_guide/platforms/
    https://gVisor.dev/docs/user_guide/networking/

### 11.7: Performance and low-latency reasoning

Measure setup separately from steady-state work:

**Cold start:**
    elapsed time from launcher invocation until the process is ready

**CPU-only loop:**
    mostly measures instruction execution without many system calls

**System-call loop:**
    exposes boundary-crossing cost

**Filesystem metadata:**
    repeated open, stat, and close operations

**UDP RTT and throughput:**
    exposes network-stack copies, scheduling, batching, and queueing

**Memory:**
    maximum resident memory and idle per-container overhead

**Tools:**
    `/usr/bin/time -v` for elapsed time and memory
    `strace -c` for system-call counts and time
    `perf stat` for cycles, instructions, context switches, and faults
    Meshlet's release-mode UDP benchmark for p50 and p99 latency

Comparison order:

1. Native process
2. Manual namespaces
3. Toy launcher
4. Runc
5. GVisor systrap
6. GVisor KVM only when appropriate

**Expected reasoning:**
    namespaces usually add little steady-state data-path work. Cgroup limits can
    create throttling or contention. Runc setup affects startup more than the
    application's steady-state system-call path. GVisor adds software work at
    system-call, filesystem, and networking boundaries, so I/O-heavy workloads
    generally expose more overhead than CPU-heavy workloads.

We will report distributions rather than one timing: warm-up, p50, p99,
throughput, CPU usage, memory, and context switches. A performance change is
accepted only when the measured workload and boundary are clearly named.

## Possible later repository layout

```text
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
```

Do not split the current single binary merely to imitate a production repository. Split crates only when protocol encoding, node data path, coordinator, and relay have independently testable contracts.

## Observation checklist

When an observation changes the mental model, record:

- What packet was sent
- Which headers changed
- Which address was private
- Which address was public
- Which router-table entry was used
- Which state or decision changed the result

## Arch Linux setup

```bash
sudo pacman -S rustup iproute2 nftables tcpdump conntrack-tools
rustup default stable
```

| Tool | Purpose |
| --- | --- |
| `ip` | Interfaces, addresses, routes, and namespaces |
| `nft` | Firewall and NAT rules |
| `tcpdump` | Raw packet observation |
| `conntrack` | Kernel NAT and connection-state table |
| `cargo` | Building the Rust programs |

## Original implementation target

Do not begin with crypto or TUN interfaces.

The first checkpoint was:

- One Rust binary
- Four modes
- TCP server/client
- UDP server/client
- Packet captures proving the difference

This checkpoint is complete. The program exposes socket addresses and byte counts, and the namespace lab has demonstrated routing and NAT.

That progression prevents the project from becoming a large opaque “VPN implementation” before the underlying packet behavior is understood.

## Summary

Meshlet will begin as a socket and Linux-routing lab, then grow into an authenticated encrypted overlay with coordination, NAT traversal, relay fallback, TUN-based packet transport, and subnet routing. Every major feature corresponds directly to one of your networking questions and to a concrete distributed-systems concept.

## Project purpose

The project’s purpose is to make internet routing, transport ports, public and private addressing, NAT, stateful firewalls, containers, cryptographic handshakes, distributed membership, overlay networks, relay fallback, TUN interfaces, subnet routing, packet inspection, and latency tradeoffs observable through code and packet traces rather than only through diagrams.

## Go learning track

Go first appears in stage 11.0 because a small process launcher is a concrete,
bounded program. It teaches source files, functions, arguments, errors, and
child processes before any Linux isolation mechanism is added. The learner,
rather than the assistant, writes each launcher increment.

Go also fits this project at a later service boundary, especially a coordinator implementation. Coordinators perform request parsing, concurrent network I/O, timers, maps, serialization, and operational diagnostics: areas where Go's small language, garbage collection, goroutines, channels, networking standard library, fast builds, and simple binary deployment are strong.

Meshlet's packet data path will remain in Rust so the project can study explicit ownership, byte representations, cryptographic state, system calls, TUN I/O, and latency without introducing a garbage-collected runtime into the hottest path.

After the coordinator protocol and authentication rules are stable, implement the same coordinator contract in Go and run the Rust nodes against both servers. This creates a meaningful language boundary and proves that the protocol, rather than one implementation, is the contract.

The broader Go learning sequence starts from zero:

1. Source files, packages, modules, compilation, and the `main` entry point
2. Values, variables, constants, functions, structs, methods, pointers, slices, and maps
3. Interfaces, explicit error values, `defer`, resource lifetime, and cancellation with contexts
4. Goroutines, channels, locks, races, and ownership conventions
5. UDP/HTTP servers, deadlines, bounded inputs, serialization, and tests
6. Garbage collection, allocation, escape analysis, latency, the race detector, benchmarks, and pprof
7. Implement the Meshlet coordinator protocol and compare behavior, failure handling, and performance with the Rust version

We will not rewrite the Rust packet data path in Go merely for syntax practice.
The launcher teaches operating-system process boundaries; the later second
coordinator becomes worthwhile when interoperability and control-plane
concurrency are real learning goals.


---

*Learning scope: level 4–7 networking principles.*
