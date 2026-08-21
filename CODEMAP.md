# Meshlet code map

Use this file to find an implementation. The learning narrative and commands
remain in `readme.md`; this file maps those concepts to code.

## Organization principles

1. **Commands enter through `src/main.rs`.** Find the command string in
   `main`, then follow the single function it dispatches to.
2. **One mechanism owns one module.** Protocol parsing, state, and the small
   runnable example for a mechanism live together unless another module owns a
   reusable primitive.
3. **Control plane and data plane stay separate.** `coordinator.rs` discovers
   nodes and routes; `handshake.rs`, `secure_packet.rs`, `relay.rs`, and
   `tun.rs` move or protect peer traffic.
4. **Pure state precedes operating-system I/O.** `firewall.rs`, `routing.rs`,
   and `RelayState` can be understood and tested without namespaces or sockets.
5. **Wire boundaries are explicit.** Encode, parse, sign, derive, seal, and
   open functions mark where typed state becomes bytes or bytes become typed
   state.
6. **Linux setup stays outside Rust.** `namespaces.md` builds the simulated
   machines; `firewall-setup/firewall-setup.sh` installs the live firewall.
7. **Comments explain boundaries, not ordinary syntax.** Every named function
   has a two-line header: what it does, then who calls it. Additional inline
   comments are reserved for uncommon libraries, wire formats, kernel APIs, or
   safety constraints.

## Find code by concept

| Concept | Primary implementation | Entry command or caller |
| --- | --- | --- |
| TCP and UDP echo | `src/main.rs` | `tcp-*`, `udp-*` |
| UDP latency measurement | `src/main.rs` | `udp-bench-server`, `udp-rtt-client` |
| Stateful firewall model | `src/firewall.rs` | `firewall-demo` |
| Live Linux firewall | `firewall-setup/firewall-setup.sh` | `setup`, `show`, `cleanup` |
| Identity files and signatures | `src/identity.rs` | `identity-generate`, coordinator and handshake callers |
| Coordinator registration and lookup | `src/coordinator.rs` | `coordinator-*` |
| Route advertisements and longest-prefix match | `src/routing.rs` | coordinator route commands |
| Authenticated peer handshake | `src/handshake.rs` | `secure-echo-*` |
| Encrypted packet format and replay order | `src/secure_packet.rs` | handshake encrypted echo |
| Opaque relay forwarding | `src/relay.rs` | `udp-relay` and automatic fallback |
| TUN-to-UDP packet transport | `src/tun.rs` | `tun-udp-one` |
| Simulated hosts, links, routes, NAT, and TUN setup | `namespaces.md` | run as a Bash lab |

## Runtime call paths

### Ordinary echo

```text
main
└── tcp_server / tcp_client / udp_server / udp_client
    └── std::net socket operations
```

### Coordinator

```text
main
├── coordinator client command
│   └── request builder -> exchange -> UDP server
└── coordinator server command
    └── parse_request -> Registry::handle -> Response::encode
                              ├── registration table
                              └── RouteRegistry
```

The authenticated registration path replaces `parse_request` and `Registry`
dispatch with `parse_auth_request` and `AuthenticatedCoordinator` challenge
handling.

### Secure peer traffic

```text
main
└── handshake client/server
    ├── identity loading and signature verification
    ├── X25519 shared secret -> HKDF directional keys
    └── PacketSender::seal / PacketReceiver::open
        └── ChaCha20-Poly1305 encrypted UDP payload
```

Automatic fallback first calls the same direct handshake. Only a reachability
failure retries it through `relay::run`; authentication failures do not.

### Overlay packet transport

```text
Linux route -> meshlet0 TUN -> tun::run_one_exchange -> UDP
UDP -> tun::run_one_exchange -> peer meshlet0 TUN -> Linux route
```

## External libraries at a glance

| Library | Narrow role in Meshlet |
| --- | --- |
| `ed25519-dalek` | Long-term signatures that authenticate node IDs |
| `x25519-dalek` | Short-lived Diffie-Hellman shared secret during a handshake |
| `hkdf` + `sha2` | Derive two directional encryption keys from shared material |
| `chacha20poly1305` | Encrypt packet contents and authenticate contents plus header |
| `getrandom` | Ask the operating system for cryptographic random bytes |
| `libc` | Call Linux's TUN `ioctl`, which has a C interface |

## Supporting files

- `Cargo.toml` declares the Rust package and external libraries.
- `Cargo.lock` pins exact resolved dependency versions.
- `readme.md` is the staged teaching specification and command guide.
- `commands.txt` and `observations.md` are learning notes, not runtime inputs.
- `.meshlet/keys/` contains local learning identities and authorizations when
  generated; it is data, not source code.
