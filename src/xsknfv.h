#ifndef __XSKNFV_XSKNFV_H
#define __XSKNFV_XSKNFV_H

#include <stdint.h>
#include <bpf/libbpf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XSKNFV_MAX_INTERFACES 32
#define XSKNFV_MAX_WORKERS 32

/* Application working modes */
#define MODE_AF_XDP 0x1
#define MODE_XDP 0x2
#define MODE_COMBINED MODE_AF_XDP | MODE_XDP

/* 
 * Custom packet processing function defined by the user.
 * Returns the ifindex toward which redirect the packet or -1 to drop it
 */
int xsknfv_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex);

struct xsknfv_config {
	char *interfaces[XSKNFV_MAX_INTERFACES];
	unsigned num_interfaces;
	unsigned workers;
    unsigned working_mode;
    uint32_t xdp_flags;
    uint32_t batch_size;
    int poll;
    uint32_t xdp_bind_flags;
    int unaligned_chunks;
    int xsk_frame_size;
    int busy_poll;
	char xdp_filename[256];
    // xsknfv_packet_processor processor;
};

struct xsknfv_socket_stats {
    /* Ring level stats */
	unsigned long rx_npkts;
	unsigned long tx_npkts;
	unsigned long rx_dropped_npkts;
	unsigned long rx_invalid_npkts;
	unsigned long tx_invalid_npkts;
	unsigned long rx_full_npkts;
	unsigned long rx_fill_empty_npkts;
	unsigned long tx_empty_npkts;

    /* Application level stats */
	unsigned long rx_empty_polls;
	unsigned long fill_fail_polls;
	unsigned long copy_tx_sendtos;
	unsigned long tx_wakeup_sendtos;
    unsigned long tx_trigger_sendtos;
	unsigned long opt_polls;
};

/*
 * Future API:
 * int xsknfv_parse_args(int argc, char **argv, struct xsknfv_config *config);
 * int xsknfv_init(struct xsknfv_config *config, struct bpf_object **bpf_obj);
 */

/* Current API */
int xsknfv_init(int argc, char **argv, struct xsknfv_config *config,
		struct bpf_object **bpf_obj);
int xsknfv_init_skel(int argc, char **argv, struct xsknfv_config *config,
		struct bpf_object **bpf_obj, void *skeleton);
int xsknfv_cleanup();
int xsknfv_start_workers();
int xsknfv_stop_workers();
int xsknfv_get_socket_stats(unsigned worker_idx, unsigned iface_idx,
		struct xsknfv_socket_stats *stats);
void enter_xsks_into_map(struct bpf_object *obj);
#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* __XSKNFV_XSKNFV_H */