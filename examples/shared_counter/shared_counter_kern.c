#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
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


unsigned long global_counter = 0;
unsigned long xdp_counter = 0;

SEC("xdp") int shared_counter(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int zero = 0;

	struct xdp_cpu_stats *stats = bpf_map_lookup_elem(&xdp_stats, &zero);
	if (!stats) {
		return XDP_ABORTED;
	}
	stats->rx_npkts++;

    if (stats->rx_npkts%2 != 0){
		return bpf_redirect_map(&xsks, index, XDP_DROP);
	}

    xdp_counter++;
    global_counter++;

    // __sync_fetch_and_add(&xdp_counter, 1);
    // __sync_fetch_and_add(&global_counter, 1);

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
