#!/bin/bash

echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_mem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_rmem
echo "8192 2100000 8400000" >/proc/sys/net/ipv4/tcp_wmem

SAT_RECV="192.168.200.0/16"
NQ=9
OUT_IFACE="wlan0"
CLIENTS_IFACE="eth0"

iptables -t mangle -F
iptables -t nat -F

iptables -t nat -F TCP_OPTIMIZATION
iptables -t mangle -F TCP_OPTIMIZATION

#
/sbin/iptables -I PREROUTING -t mangle -p tcp --syn -j TCP_OPTIMIZATION
/sbin/iptables -I PREROUTING -t nat -p tcp --syn -j TCP_OPTIMIZATION
#/sbin/iptables -I POSTROUTING -t nat -p tcp --syn -j TCP_OPTIMIZATION
#/sbin/iptables -I POSTROUTING -t nat -s 192.168.200.2 -j MASQUERADE

iptables -t mangle -I TCP_OPTIMIZATION -i eth0 -s 192.168.200.0/24 -p tcp -j NFQUEUE --queue-num=9
iptables -t nat -A POSTROUTING -s $SAT_RECV  -o $OUT_IFACE -j MASQUERADE
iptables -t nat -I TCP_OPTIMIZATION -i eth0 -s 192.168.200.0/24 -p tcp -j REDIRECT --to-port 6009

#iptables -A PREROUTING -t nat -p tcp
#iptables -A PREROUTING -t mangle -p tcp -flags syn

#iptables -t mangle -A PREROUTING -i $CLIENTS_IFACE -p tcp --syn -j NFQUEUE --queue-num=$NQ
#iptables -t nat -A POSTROUTING -s $SAT_RECV  -o $OUT_IFACE -j MASQUERADE
#iptables -t nat -A PREROUTING -s $SAT_RECV -p tcp -j REDIRECT --to-port 6001
