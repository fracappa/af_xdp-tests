#include "policer_wc.h"


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
	__type(value, struct contract);
	__uint(max_entries, MAX_CONTRACTS);
} contracts SEC(".maps");


static inline int limit_rate(struct xdp_md *ctx, struct session_id *session, struct contract *contract) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
  
     int size = (data_end - data) * 8;
  
     if (contract->counter < size) {
        return XDP_DROP;
     }

    __sync_fetch_and_add(&contract->counter, -size);
  
     return XDP_TX;
}

SEC("xdp") int rate_limiter(struct xdp_md *ctx) {
  // bpf_printk("Entering XDP program..\n");
  int index = ctx->rx_queue_index;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct session_id key = {0};

const char fmt_str[] = "counter: %d\n";

  
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

	struct contract *contract = bpf_map_lookup_elem(&contracts, &key);

	if (!contract) {
		bpf_printk("No value retrieved.\n");
		return XDP_DROP;
	}

 bpf_trace_printk(fmt_str, sizeof(fmt_str), contract->counter);


// /* What should be redirected to AF_XDP: remote traffic */
  if(contract->local == 0){
	  bpf_printk("Redirecting to AF_XDP..\n");
	  return bpf_redirect_map(&xsks, index, XDP_DROP);
  }


  //Apply action
  switch (contract->action) {
    case ACTION_PASS:
      return XDP_PASS;
      break;

    case ACTION_LIMIT:
      return limit_rate(ctx, &key, contract);
      break;

    case ACTION_DROP:
      return XDP_DROP;
      break;
  }
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";