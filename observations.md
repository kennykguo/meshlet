➜  meshlet git:(main) ✗ sudo ip netns exec mesh-a ping -c 2 10.10.0.1
PING 10.10.0.1 (10.10.0.1) 56(84) bytes of data.
From 10.10.0.2 icmp_seq=1 Destination Host Unreachable
From 10.10.0.2 icmp_seq=2 Destination Host Unreachable

--- 10.10.0.1 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1042ms
pipe 2




➜  meshlet git:(main) ✗ sudo ip -n mesh-a -brief address
sudo ip -n mesh-r -brief address
sudo ip -n mesh-b -brief address
lo               UNKNOWN        127.0.0.1/8 ::1/128 
a0@if30          UP             10.10.0.2/24 fe80::6c2f:5cff:fea4:e7d8/64 
lo               UNKNOWN        127.0.0.1/8 ::1/128 
r0@if31          UP             10.10.0.1/24 fe80::84f2:c4ff:fe3c:6b2a/64 
r1@if33          UP             10.20.0.1/24 fe80::6057:5eff:fe1f:adf6/64 
lo               UNKNOWN        127.0.0.1/8 ::1/128 
b0@if32          UP             10.20.0.2/24 fe80::f4f9:cbff:fed2:e05e/64 



➜  meshlet git:(main) ✗ sudo ip netns exec mesh-a ping -c 2 10.10.0.1
sudo ip netns exec mesh-b ping -c 2 10.20.0.1
sudo ip netns exec mesh-a ping -c 1 -W 1 10.20.0.2
PING 10.10.0.1 (10.10.0.1) 56(84) bytes of data.
64 bytes from 10.10.0.1: icmp_seq=1 ttl=64 time=0.041 ms
64 bytes from 10.10.0.1: icmp_seq=2 ttl=64 time=0.035 ms

--- 10.10.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1060ms
rtt min/avg/max/mdev = 0.035/0.038/0.041/0.003 ms
PING 10.20.0.1 (10.20.0.1) 56(84) bytes of data.
64 bytes from 10.20.0.1: icmp_seq=1 ttl=64 time=0.037 ms
64 bytes from 10.20.0.1: icmp_seq=2 ttl=64 time=0.032 ms

--- 10.20.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1045ms
rtt min/avg/max/mdev = 0.032/0.034/0.037/0.002 ms
ping: connect: Network is unreachable
➜  meshlet git:(main) ✗


| Field | At `r0` | At `r1` |
|---|---|---|
| Source IP | `10.10.0.2` | `10.10.0.2` |
| Destination IP | `10.20.0.2` | `10.20.0.2` |
| Source MAC | `a0` | `r1` |
| Destination MAC | `r0` | `b0` |
| TTL | 64 arriving | 63 leaving |
| UDP ports | Unchanged | Unchanged |
| Application bytes | Unchanged | Unchanged |