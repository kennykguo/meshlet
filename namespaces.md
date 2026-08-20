# Delete the previous simulated machines, then create empty network stacks.
sudo ip netns del mesh-a
sudo ip netns del mesh-r
sudo ip netns del mesh-b
sudo ip netns del mesh-c

sudo ip netns add mesh-a
sudo ip netns add mesh-r
sudo ip netns add mesh-b
sudo ip netns add mesh-c


# Let mesh-r move IP packets between its interfaces instead of acting only as a host.
sudo ip netns exec mesh-r sysctl -w net.ipv4.ip_forward=1

# Each veth pair is two virtual Ethernet interfaces joined back-to-back.
# a0<->r0, b0<->r1, and c0<->r2 are the lab's three virtual cables.
sudo ip link add a0 type veth peer name r0
sudo ip link add b0 type veth peer name r1
sudo ip link add c0 type veth peer name r2

sudo ip link set a0 netns mesh-a
sudo ip link set r0 netns mesh-r
sudo ip link set b0 netns mesh-b
sudo ip link set r1 netns mesh-r
sudo ip link set c0 netns mesh-c
sudo ip link set r2 netns mesh-r


# Give each end of every virtual cable an IPv4 address.
sudo ip -n mesh-a address add 10.10.0.2/24 dev a0
sudo ip -n mesh-r address add 10.10.0.1/24 dev r0
sudo ip -n mesh-r address add 192.0.2.10/24 dev r1
sudo ip -n mesh-b address add 192.0.2.20/24 dev b0
sudo ip -n mesh-r address add 203.0.113.1/24 dev r2
sudo ip -n mesh-c address add 203.0.113.10/24 dev c0


# "up" enables an interface. "lo" is the machine's loopback interface.
sudo ip -n mesh-a link set a0 up
sudo ip -n mesh-a link set lo up

sudo ip -n mesh-r link set r0 up
sudo ip -n mesh-r link set lo up
sudo ip -n mesh-r link set r1 up
sudo ip -n mesh-r link set r2 up

sudo ip -n mesh-b link set b0 up
sudo ip -n mesh-b link set lo up

sudo ip -n mesh-c link set c0 up
sudo ip -n mesh-c link set lo up

# Teach each non-router which next-hop router handles a remote /24 network.
sudo ip -n mesh-a route add 192.0.2.0/24 via 10.10.0.1 dev a0
sudo ip -n mesh-a route add 203.0.113.0/24 via 10.10.0.1 dev a0
sudo ip -n mesh-b route add 203.0.113.0/24 via 192.0.2.10 dev b0
sudo ip -n mesh-c route add 192.0.2.0/24 via 203.0.113.1 dev c0


# When private mesh-a packets leave r1 or r2, replace their source IP with
# the router's address on that outgoing network. Replies use the saved NAT state.
sudo ip netns exec mesh-r nft add table ip meshlet_nat

sudo ip netns exec mesh-r nft \
  'add chain ip meshlet_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'

sudo ip netns exec mesh-r nft \
  'add rule ip meshlet_nat postrouting oifname "r1" ip saddr 10.10.0.0/24 snat to 192.0.2.10'

sudo ip netns exec mesh-r nft \
  'add rule ip meshlet_nat postrouting oifname "r2" ip saddr 10.10.0.0/24 snat to 203.0.113.1'
