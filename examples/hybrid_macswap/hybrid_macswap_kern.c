#include "hybrid_macswap.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

/* 
 * Including the common/statistics.h header creates problems with other
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

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 32);
} xsks SEC(".maps");

SEC("xdp") int ingress_redirect_macswap(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

	// /*
	//  * Need to send the at least one packet to user space for busy polling to
	//  * work in combined mode.
	//  */
	// if (stats->rx_npkts == 1) {
	// 	return bpf_redirect_map(&xsks, 0, XDP_ABORTED);
	// }

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	/* Use the first bit of the dst mac addr to choose between drop/redir */
	// if (*(uint8_t *)&eth->h_dest & 1) {
	// 	swap_mac_addresses(data);

	// 	return XDP_DROP;
	// }

	// swap_mac_addresses(data);

	return bpf_redirect_map(&xsks, 0, XDP_ABORTED);
	// return XDP_TX;
}

char _license[] SEC("license") = "GPL";
