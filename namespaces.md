sudo ip netns add mesh-a
sudo ip netns add mesh-r
sudo ip netns add mesh-b

sudo ip link add a0 type veth peer name r0
sudo ip link add b0 type veth peer name r1

sudo ip link set a0 netns mesh-a
sudo ip link set r0 netns mesh-r
sudo ip link set b0 netns mesh-b
sudo ip link set r1 netns mesh-r