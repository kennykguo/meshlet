sudo ip netns del mesh-a
sudo ip netns del mesh-r
sudo ip netns del mesh-b

sudo ip netns add mesh-a
sudo ip netns add mesh-r
sudo ip netns add mesh-b


# Forwarding
sudo ip netns exec mesh-r sysctl -w net.ipv4.ip_forward=1

sudo ip link add a0 type veth peer name r0
sudo ip link add b0 type veth peer name r1

sudo ip link set a0 netns mesh-a
sudo ip link set r0 netns mesh-r
sudo ip link set b0 netns mesh-b
sudo ip link set r1 netns mesh-r


sudo ip -n mesh-a address add 10.10.0.2/24 dev a0
sudo ip -n mesh-r address add 10.10.0.1/24 dev r0
sudo ip -n mesh-r address add 192.0.2.10/24 dev r1
sudo ip -n mesh-b address add 192.0.2.20/24 dev b0


sudo ip -n mesh-a link set a0 up
sudo ip -n mesh-a link set lo up

sudo ip -n mesh-r link set r0 up
sudo ip -n mesh-r link set lo up
sudo ip -n mesh-r link set r1 up

sudo ip -n mesh-b link set b0 up
sudo ip -n mesh-b link set lo up

sudo ip -n mesh-a route add 192.0.2.0/24 via 10.10.0.1 dev a0


# NAT
sudo ip netns exec mesh-r nft add table ip meshlet_nat

sudo ip netns exec mesh-r nft \
  'add chain ip meshlet_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'

sudo ip netns exec mesh-r nft \
  'add rule ip meshlet_nat postrouting oifname "r1" ip saddr 10.10.0.0/24 snat to 192.0.2.10'
