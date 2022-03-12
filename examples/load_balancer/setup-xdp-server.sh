#!/bin/bash

if [[ $# -lt 1 ]]; then
	echo "Interface required"
	exit 1
fi

if  [ $# -lt 2 ]; then
	queues=1
else
	queues=$2
fi

sudo ip link del veth1a
sudo ip link set br1 down
sudo brctl delbr br1

sudo ip link add veth1a numrxqueues $queues numtxqueues $queues type veth \
		peer veth1b numrxqueues $queues numtxqueues $queues
sudo ip link set veth1a up
sudo ip link set veth1b up
sudo ip addr add 192.168.0.1/24 dev veth1a

sudo brctl addbr br1
sudo ip link set br1 up
sudo brctl addif br1 ens1f0
sudo brctl addif br1 veth1b

# Avoid arp requests when the backend tries to contact the client
sudo ip route add 10.0.0.0/24 via 192.168.0.254
sudo arp -s 192.168.0.254 bb:bb:bb:bb:bb:bb

mac=$(cat /sys/class/net/veth1a/address)

echo "2 2" > services.txt
echo "10.0.0.2 11211 TCP 192.168.0.1 11211 $mac veth1b" >> services.txt
echo "10.0.0.2 11211 UDP 192.168.0.1 11211 $mac veth1b" >> services.txt

sudo ip link set $1 up
sudo ip link set $1 promisc on
$HOME/scripts/set-rx-queues-rss.sh $queues $1