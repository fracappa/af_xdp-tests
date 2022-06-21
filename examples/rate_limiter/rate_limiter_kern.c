#include "rate_limiter.h"


#include <arpa/inet.h>
#include <linux/jhash.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

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

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 32);
} xsks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct session_id);
	__type(value, int);
	__uint(max_entries, MAX_CONTRACTS);
} positions SEC(".maps");


struct contract contracts[MAX_CONTRACTS] = {};

static inline int limit_rate(struct xdp_md *ctx, struct contract *contract) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// // Consume tokens
	int64_t needed_tokens = (data_end - data + 4) * 8;
	uint8_t retval;

	if (contract->bucket.tokens >= needed_tokens) {
		__sync_fetch_and_add(&contract->bucket.tokens, -needed_tokens);
		retval = XDP_TX;
	} else {
		retval = XDP_DROP;
	}
	return retval;
}


SEC("xdp") 
int rate_limiter(struct xdp_md *ctx) {
	// return bpf_redirect_map(&xsks, 0, XDP_DROP);

	int index = ctx->rx_queue_index;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct session_id key = {0};
  
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

	if (stats->rx_npkts%7 != 0){
		return bpf_redirect_map(&xsks, index, XDP_DROP);
	}
	

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

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > data_end) {
			return XDP_ABORTED;
		}

		key.sport = tcph->source;
		key.dport = tcph->dest;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > data_end) {
			return XDP_ABORTED;
		}

		key.sport = udph->source;
		key.dport = udph->dest;
		break;
	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;

	int *position = bpf_map_lookup_elem(&positions, &key);
	
	if(!position){
		return XDP_DROP;
	}

	volatile int array_index = *position;
	int safe_index = array_index;


	if(safe_index < 0 || safe_index >= MAX_CONTRACTS){
		return XDP_DROP;
	}
	struct contract *contract = &contracts[safe_index];
	//Apply action
	switch (contract->action) {
		case ACTION_PASS:
		return XDP_PASS;
		break;

		case ACTION_LIMIT:
		return limit_rate(ctx, contract);
		break;

		case ACTION_DROP:
		return XDP_DROP;
		break;
	}
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";