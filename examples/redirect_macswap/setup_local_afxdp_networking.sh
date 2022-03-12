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

sudo ip link add veth1a numrxqueues $queues numtxqueues $queues type veth \
		peer veth1b numrxqueues $queues numtxqueues $queues
sudo ip link set veth1a up
sudo ip link set veth1b up
sudo ip addr add 10.0.0.2/24 dev veth1a
sudo ethtool -K veth1a tx off txvlan off

sudo ip link set $1 promisc on
$HOME/scripts/set-rx-queues-rss.sh $queues $1