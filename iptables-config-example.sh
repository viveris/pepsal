#!/bin/bash

echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_mem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_rmem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_wmem

SAT_RECV="192.168.0.0/16"
NQ=1
OUT_IFACE="eth0"
CLIENTS_IFACE="eth1"

iptables -t mangle -F
iptables -t nat -F
iptables -t mangle -A PREROUTING -i $CLIENTS_IFACE -p tcp --syn -j NFQUEUE --queue-num=$NQ
iptables -t nat -A POSTROUTING -s $SAT_RECV  -o $OUT_IFACE -j MASQUERADE
iptables -t nat -A PREROUTING -s $SAT_RECV -p tcp -j REDIRECT --to-port 5000
