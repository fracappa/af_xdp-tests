// SPDX-License-Identifier: GPL-2.0
#include "load_balancer.h"
#include <arpa/inet.h>
#include <linux/jhash.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/* 
 * Including the common/statistcis.h header creates problems with other
 * inclusions
 */
struct xdp_cpu_stats {
	unsigned long rx_npkts;
	unsigned long tx_npkts;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct xdp_cpu_stats);
	__uint(max_entries, 1);
} xdp_stats SEC(".maps");

#ifdef MONITOR_LOOKUP_TIME
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, unsigned long);
	__uint(max_entries, 1);
} lookup_time SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct service_id);
	__type(value, struct service_info);
	__uint(max_entries, MAX_SERVICES);
} services SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct backend_id);
	__type(value, struct backend_info);
	__uint(max_entries, MAX_BACKENDS);
} backends SEC(".maps");

/* 
 * A PERCPU_LRU map should be used here. Simple HASH is used to be coherent with
 * user space data plane
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct session_id);
	__type(value, struct replace_info);
	__uint(max_entries, MAX_SESSIONS);
} active_sessions SEC(".maps");

SEC("xdp_prog") int load_balancer(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_TX;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end) {
		return XDP_ABORTED;
	}

	void *next = (void *)iph + (iph->ihl << 2);
	uint16_t *sport, *dport, *l4check;

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > data_end) {
			return XDP_ABORTED;
		}

		sport = &tcph->source;
		dport = &tcph->dest;
		l4check = &tcph->check;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > data_end) {
			return XDP_ABORTED;
		}

		sport = &udph->source;
		dport = &udph->dest;
		l4check = &udph->check;

		break;

	default:
		return XDP_TX;
	}

	struct session_id sid = {0};

	sid.saddr = iph->saddr;
	sid.daddr = iph->daddr;
	sid.proto = iph->protocol;
	sid.sport = *sport;
	sid.dport = *dport;

	uint32_t old_addr, new_addr;
	uint16_t old_port, new_port;

	/* Look for known sessions */
#ifdef MONITOR_LOOKUP_TIME
	unsigned long before = bpf_ktime_get_ns();
#endif
	struct replace_info *rep = bpf_map_lookup_elem(&active_sessions, &sid);
#ifdef MONITOR_LOOKUP_TIME
    unsigned long elapsed = bpf_ktime_get_ns() - before;
	unsigned long *tot_lookup = bpf_map_lookup_elem(&lookup_time, &zero);
	if (!tot_lookup) {
		return XDP_ABORTED;
	}
	*tot_lookup += elapsed;
#endif

	if (rep) {
		if (rep->dir == DIR_TO_BACKEND) {
			old_addr = iph->daddr;
			iph->daddr = rep->addr;
			old_port = *dport;
			*dport = rep->port;
		} else {
			old_addr = iph->saddr;
			iph->saddr = rep->addr;
			old_port = *sport;
			*sport = rep->port;
		}
		new_addr = rep->addr;
		new_port = rep->port;

		goto FORWARD;
	}

	/* New session, apply load balancing logic */
	struct service_id srvid = {
		.vaddr = iph->daddr,
		.vport = *dport,
		.proto = iph->protocol
	};
	struct service_info *srvinfo = bpf_map_lookup_elem(&services, &srvid);
	if (!srvinfo) {
		/* Destination is not a virtual service */
		return XDP_TX;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = jhash(&sid, sizeof(struct session_id), 0) % srvinfo->backends
	};
	struct backend_info *bkdinfo = bpf_map_lookup_elem(&backends, &bkdid);
	if (!bkdinfo) {
		bpf_printk("ERROR: missing backend");
		return XDP_TX;
	}

	old_addr = iph->daddr;
	iph->daddr = bkdinfo->addr;
	new_addr = bkdinfo->addr;
	old_port = *dport;
	*dport = bkdinfo->port;
	new_port = bkdinfo->port;

	/* Store the forward session */
	struct replace_info newrep = {
		.dir = DIR_TO_BACKEND,
		.addr = bkdinfo->addr,
		.port = bkdinfo->port
	};
	if (bpf_map_update_elem(&active_sessions, &sid, &newrep, 0)) {
		bpf_printk("ERROR: unable to add forward session to map");
		goto FORWARD;
	}

	/* Store the backward session */
	newrep = (struct replace_info){
		.dir = DIR_TO_CLIENT,
		.addr = srvid.vaddr,
		.port = srvid.vport
	};
	sid.daddr = sid.saddr;
	sid.dport = sid.sport;
	sid.saddr = bkdinfo->addr;
	sid.sport = bkdinfo->port;
	if (bpf_map_update_elem(&active_sessions, &sid, &newrep, 0)) {
		bpf_printk("ERROR: unable to add backward session to map");
		goto FORWARD;
	}

FORWARD:;
	/* Update ip checksum */
	uint32_t csum = ~csum_unfold(iph->check);
	csum = csum_add(csum, ~old_addr);
	csum = csum_add(csum, new_addr);
	iph->check = csum_fold(csum);

	/* Update l4 checksum */
	csum = ~csum_unfold(*l4check);
	csum = csum_add(csum, ~old_addr);
	csum = csum_add(csum, new_addr);
	csum = csum_add(csum, ~old_port);
	csum = csum_add(csum, new_port);
	*l4check = csum_fold(csum);

    /* Should update MAC addresses here */

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
