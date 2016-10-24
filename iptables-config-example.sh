#!/bin/bash

echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_mem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_rmem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_wmem

CLIENTS_IFACE="eth0"

ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100

# Careful, as this will erase any other preexisting entries
iptables -t mangle -F
iptables -t mangle -A PREROUTING -i $CLIENTS_IFACE -p tcp -j TPROXY --on-port 5000 --tproxy-mark 1
