#include "xsknfv.h"
#include <bpf/xsk.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#define FRAMES_PER_SOCKET (4 * 1024)

/* Application working modes */
#define MODE_AF_XDP 0x1
#define MODE_XDP 0x2
#define MODE_COMBINED MODE_AF_XDP | MODE_XDP

#define POLL_TIMEOUT_MS 1000

static size_t umem_bufsize;
static uint32_t opt_xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int stop_workers = 0;
static uint32_t opt_xdp_bind_flags = XDP_USE_NEED_WAKEUP;
static struct xsknfv_config conf = {
	.working_mode = MODE_AF_XDP,
	.xsk_frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
	.batch_size = 64,
	.workers = 1
};

struct xsk_socket_info {
	struct worker *worker;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_socket *xsk;
	struct xsknfv_socket_stats stats;
	uint32_t outstanding_tx;
};

struct worker {
	unsigned id;
	pthread_t thread;
	struct xsk_socket_info *xsks;
	struct xsk_umem *umem;
	void *buffer;
} __attribute__((aligned(64)));

static unsigned num_sockets;
static int *ifindexes;
static struct worker *workers;
static struct bpf_object *obj;

static int xsk_get_xdp_stats(int fd, struct xsknfv_socket_stats *stats)
{
	struct xdp_statistics xdp_stats;
	socklen_t optlen;
	int err;

	optlen = sizeof(stats);
	err = getsockopt(fd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen);
	if (err)
		return err;

	if (optlen == sizeof(struct xdp_statistics)) {
		stats->rx_dropped_npkts = xdp_stats.rx_dropped;
		stats->rx_invalid_npkts = xdp_stats.rx_invalid_descs;
		stats->tx_invalid_npkts = xdp_stats.tx_invalid_descs;
		stats->rx_full_npkts = xdp_stats.rx_ring_full;
		stats->rx_fill_empty_npkts = xdp_stats.rx_fill_ring_empty_descs;
		stats->tx_empty_npkts = xdp_stats.tx_ring_empty_descs;
		return 0;
	}

	return -EINVAL;
}

static void __exit_with_error(int error, const char *file, const char *func,
			      int line)
{
	fprintf(stderr, "%s:%s:%i: errno: %d/\"%s\"\n", file, func,
		line, error, strerror(error));

	xsknfv_cleanup();

	exit(EXIT_FAILURE);
}

#define exit_with_error(error) __exit_with_error(error, __FILE__, __func__, __LINE__)

static void xsk_configure_socket(char *iface, unsigned queue,
		struct xsk_socket_info *xsk)
{
	struct xsk_socket_config cfg;
	int ret, sock_opt;
	uint32_t idx;

	cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	if (conf.working_mode & MODE_XDP) {
		cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	} else {
		cfg.libbpf_flags = 0;
	}
	cfg.xdp_flags = opt_xdp_flags;
	cfg.bind_flags = opt_xdp_bind_flags;

	ret = xsk_socket__create_shared(&xsk->xsk, iface, queue, xsk->worker->umem, 
			&xsk->rx, &xsk->tx, &xsk->fq, &xsk->cq, &cfg);
	if (ret)
		exit_with_error(-ret);

	/* Enable and configure busy poll */
	if (conf.busy_poll) {
		sock_opt = 1;
		if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET,
				SO_PREFER_BUSY_POLL, (void *)&sock_opt, sizeof(sock_opt)) < 0)
			exit_with_error(errno);

		sock_opt = 20;
		if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL,
				(void *)&sock_opt, sizeof(sock_opt)) < 0)
			exit_with_error(errno);

		sock_opt = conf.batch_size;
		if (setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET,
				SO_BUSY_POLL_BUDGET, (void *)&sock_opt, sizeof(sock_opt)) < 0)
			exit_with_error(errno);
	}

	/* Populate the fill ring */
	ret = xsk_ring_prod__reserve(&xsk->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
			&idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2)
		exit_with_error(-ret);
	for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
		*xsk_ring_prod__fill_addr(&xsk->fq, idx++) = i * conf.xsk_frame_size;
	xsk_ring_prod__submit(&xsk->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);
}

static void load_xdp_program(char *path, struct bpf_object **obj)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type      = BPF_PROG_TYPE_XDP,
	};
	int prog_fd;

	prog_load_attr.file = path;

	if (bpf_prog_load_xattr(&prog_load_attr, obj, &prog_fd))
		exit(EXIT_FAILURE);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(prog_fd));
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < conf.num_interfaces; i++) {
		if (bpf_set_link_xdp_fd(ifindexes[0], prog_fd, opt_xdp_flags) < 0) {
			fprintf(stderr, "ERROR: link set xdp fd failed\n");
			exit(EXIT_FAILURE);
		}
	}	
}

static void kick_tx(struct xsk_socket_info *xsk)
{
	int ret;

	ret = sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN ||
	    errno == EBUSY || errno == ENETDOWN)
		return;
	exit_with_error(errno);
}

static inline void complete_tx_l2fwd(struct xsk_socket_info *xsk)
{
	uint32_t idx_cq = 0, idx_fq = 0;
	unsigned int rcvd;
	size_t ndescs;

	if (!xsk->outstanding_tx)
		return;

	/* 
	 * In copy mode, Tx is driven by a syscall so we need to use e.g. sendto()
	 * to really send the packets. In zero-copy mode we do not have to do this,
	 * since Tx is driven by the NAPI loop. So as an optimization, we do not
	 * have to call sendto() all the time in zero-copy mode for l2fwd.
	 */
	if (opt_xdp_bind_flags & XDP_COPY) {
		xsk->stats.copy_tx_sendtos++;
		kick_tx(xsk);
	}

	ndescs = (xsk->outstanding_tx > conf.batch_size) ? conf.batch_size :
		xsk->outstanding_tx;

	/* re-add completed Tx buffers */
	rcvd = xsk_ring_cons__peek(&xsk->cq, ndescs, &idx_cq);
	if (rcvd > 0) {
		unsigned int i;
		int ret;

		xsk->stats.tx_npkts += rcvd;

		ret = xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq);
		while (ret != rcvd) {
			if (ret < 0)
				exit_with_error(-ret);
			if (conf.busy_poll || xsk_ring_prod__needs_wakeup(&xsk->fq)) {
				xsk->stats.fill_fail_polls++;
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			}
			ret = xsk_ring_prod__reserve(&xsk->fq, rcvd, &idx_fq);
		}

		for (i = 0; i < rcvd; i++)
			*xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) =
				*xsk_ring_cons__comp_addr(&xsk->cq, idx_cq++);

		xsk_ring_prod__submit(&xsk->fq, rcvd);
		xsk_ring_cons__release(&xsk->cq, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

struct pkt_info {
	uint64_t addr;
	uint32_t len;
};

// #include <net/ethernet.h>

// static int swap_mac_addresses(void *pkt, unsigned len)
// {
// 	struct ether_header *eth = (struct ether_header *)pkt;
// 	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
// 	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
// 	struct ether_addr tmp;

// 	tmp = *src_addr;
// 	*src_addr = *dst_addr;
// 	*dst_addr = tmp;

// 	return 0;
// }

static void l2fwd(struct xsk_socket_info *xsk)
{
	struct pkt_info to_drop[conf.batch_size], to_tx[conf.batch_size];
	unsigned ndrop = 0, ntx = 0;
	unsigned int rcvd, i;
	uint32_t idx_rx = 0, idx_fq = 0, idx_tx = 0;
	int ret;

	complete_tx_l2fwd(xsk);

	rcvd = xsk_ring_cons__peek(&xsk->rx, conf.batch_size, &idx_rx);
	if (!rcvd) {
		if (conf.busy_poll || xsk_ring_prod__needs_wakeup(&xsk->fq)) {
			xsk->stats.rx_empty_polls++;
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					NULL);
		}
		return;
	}

	for (i = 0; i < rcvd; i++) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		uint64_t orig = addr;

		addr = xsk_umem__add_offset_to_addr(addr);
		void *pkt = xsk_umem__get_data(xsk->worker->buffer, addr);

		if (xsknfv_packet_processor(pkt, len) == -1) {
			to_drop[ndrop].addr = orig;
			to_drop[ndrop++].len = len;
		} else {
			to_tx[ntx].addr = orig;
			to_tx[ntx++].len = len;
		}
	}

	xsk_ring_cons__release(&xsk->rx, rcvd);

	/* Handle packets to drop */
	if (ndrop) {
		ret = xsk_ring_prod__reserve(&xsk->fq, ndrop, &idx_fq);
		while (ret != ndrop) {
			if (ret < 0)
				exit_with_error(-ret);
			if (conf.busy_poll || xsk_ring_prod__needs_wakeup(&xsk->fq)) {
				xsk->stats.fill_fail_polls++;
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
						NULL);
			}
			ret = xsk_ring_prod__reserve(&xsk->fq, ndrop, &idx_fq);
		}

		for (i = 0; i < ndrop; i++) {
			*xsk_ring_prod__fill_addr(&xsk->fq, idx_fq++) = to_drop[i].addr;
		}

		xsk_ring_prod__submit(&xsk->fq, ndrop);
	}

	/* Handle packets to transmit */
	if (ntx) {
		ret = xsk_ring_prod__reserve(&xsk->tx, ntx, &idx_tx);
		while (ret != ntx) {
			if (ret < 0)
				exit_with_error(-ret);
			complete_tx_l2fwd(xsk);
			if (conf.busy_poll || xsk_ring_prod__needs_wakeup(&xsk->tx)) {
				xsk->stats.tx_wakeup_sendtos++;
				kick_tx(xsk);
			}
			ret = xsk_ring_prod__reserve(&xsk->tx, ntx, &idx_tx);
		}

		for (i = 0; i < rcvd; i++) {
			xsk_ring_prod__tx_desc(&xsk->tx, idx_tx)->addr = to_tx[i].addr;
			xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++)->len = to_tx[i].len;
		}

		xsk_ring_prod__submit(&xsk->tx, ntx);
	}

	xsk->stats.rx_npkts += rcvd;
	xsk->outstanding_tx += rcvd;
}

static void *worker_loop(void *arg)
{
	struct worker *worker = (struct worker *)arg;
	struct pollfd fds[XSKNFV_MAX_INTERFACES] = {};
	int i, ret;

	while (!stop_workers) {
		if (conf.poll) {
			for (i = 0; i < conf.num_interfaces; i++) {
				fds[i].fd = xsk_socket__fd(worker->xsks[i].xsk);
				fds[i].events = POLLIN;
				worker->xsks[i].stats.opt_polls++;
			}
			ret = poll(fds, conf.num_interfaces, POLL_TIMEOUT_MS);
			if (ret <= 0)
				continue;
		}

		for (i = 0; i < conf.num_interfaces; i++)
			l2fwd(&worker->xsks[i]);
	}
}

static struct option long_options[] = {
	{"interfaces", required_argument, 0, 'i'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"zero-copy", no_argument, 0, 'z'},
	{"copy", no_argument, 0, 'c'},
	{"frame-size", required_argument, 0, 'f'},
	{"unaligned", no_argument, 0, 'u'},
	{"force", no_argument, 0, 'F'},
	{"batch-size", required_argument, 0, 'b'},
	{"busy-poll", no_argument, 0, 'B'},
	{"mode", required_argument, 0, 'M'},
	{"workers", required_argument, 0, 'w'},
	{0, 0, 0, 0}
};

static void usage()
{
	const char *str =
		"  xsknfv options:\n"
		"  -i, --interfaces=n  Comma-separated list of interfaces\n"
		"  -p, --poll          Use poll syscall\n"
		"  -S, --xdp-skb=n     Use XDP skb-mod\n"
		"  -N, --xdp-native=n  Enforce XDP native mode\n"
		"  -z, --zero-copy     Force zero-copy mode.\n"
		"  -c, --copy          Force copy mode.\n"
		"  -f, --frame-size=n  Set the frame size (must be a power of two in aligned mode, default is %d).\n"
		"  -u, --unaligned     Enable unaligned chunk placement\n"
		"  -F, --force         Force loading the XDP prog\n"
		"  -b, --batch-size=n  Batch size for sending or receiving\n"
		"                      packets. Default: %d\n"
		"  -B, --busy-poll     Busy poll.\n"
		"  -M  --mode          Working mode (AF_XDP, XDP, COMBINED)\n"
		"  -w  --workers=n     Number of packet processing workers\n"
		"\n";
	fprintf(stderr, str, XSK_UMEM__DEFAULT_FRAME_SIZE, conf.batch_size);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "Fi:pSNczf:ub:BM:w:", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'i':;
			char *iface;
			iface = strtok(optarg, ",");
			if (iface == NULL) {
				fprintf(stderr, "ERROR: at least one interface is needed\n");
				usage();
			}
			conf.interfaces[conf.num_interfaces++] = iface;
			while ((iface = strtok(NULL, ",")) != NULL) {
				conf.interfaces[conf.num_interfaces++] = iface;
			}
			break;
		case 'p':
			conf.poll = 1;
			break;
		case 'S':
			opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'N':
			/* default, set below */
			break;
		case 'z':
			opt_xdp_bind_flags |= XDP_ZEROCOPY;
			break;
		case 'c':
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'u':
			conf.unaligned_chunks = 1;
			break;
		case 'F':
			opt_xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'f':
			conf.xsk_frame_size = atoi(optarg);
			break;
		case 'b':
			conf.batch_size = atoi(optarg);
			break;
		case 'B':
			conf.busy_poll = 1;
			break;
		case 'M':
			if (strcmp(optarg, "AF_XDP") == 0) {
				conf.working_mode = MODE_AF_XDP;
			} else if (strcmp(optarg, "XDP") == 0) {
				conf.working_mode = MODE_XDP;
			} else if (strcmp(optarg, "COMBINED") == 0) {
				conf.working_mode = MODE_COMBINED;
			} else {
				fprintf(stderr, "ERROR: unknown working mode %s\n", optarg);
				usage();
			}
			break;
		case 'w':
			conf.workers = atoi(optarg);
			if (conf.workers < 1) {
				fprintf(stderr, "ERROR: Invalid number of workers %u",
						conf.workers);
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (!(opt_xdp_flags & XDP_FLAGS_SKB_MODE))
		opt_xdp_flags |= XDP_FLAGS_DRV_MODE;

	if ((conf.xsk_frame_size & (conf.xsk_frame_size - 1)) &&
	    !conf.unaligned_chunks) {
		fprintf(stderr, "--frame-size=%d is not a power of two\n",
			conf.xsk_frame_size);
		usage();
	}
}

int xsknfv_init(int argc, char **argv, struct xsknfv_config *config,
		struct bpf_object **bpf_obj)
{
	parse_command_line(argc, argv);

	ifindexes = malloc(conf.num_interfaces * sizeof(int));
	if (!ifindexes) {
		exit_with_error(errno);
	}

	for (int i = 0; i < conf.num_interfaces; i++) {
		ifindexes[i] = if_nametoindex(conf.interfaces[i]);
		if (!ifindexes[i]) {
			fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
					conf.interfaces[i]);
			exit(1);
		}
	}

	num_sockets = conf.workers * conf.num_interfaces;

	if (conf.working_mode & MODE_AF_XDP) {
		/* Allocate workers */
		workers = calloc(conf.workers, sizeof(struct worker));
		if (!workers) {
			exit_with_error(errno);
		}

		for (int wrk_idx = 0; wrk_idx < conf.workers; wrk_idx++) {
			workers[wrk_idx].id = wrk_idx;

			workers[wrk_idx].xsks = calloc(conf.num_interfaces,
					sizeof(struct xsk_socket_info));
			if (!workers[wrk_idx].xsks) {
				exit_with_error(errno);
			}

			/*
			 * Reserve memory for the umem. Use hugepages if unaligned chunk
			 * mode
			 */
			umem_bufsize = FRAMES_PER_SOCKET * conf.num_interfaces
					* conf.xsk_frame_size;
			int flags = MAP_PRIVATE | MAP_ANONYMOUS
					| (conf.unaligned_chunks ? MAP_HUGETLB : 0);
			workers[wrk_idx].buffer = mmap(NULL, umem_bufsize,
					PROT_READ | PROT_WRITE, flags, -1, 0);
			if (workers[wrk_idx].buffer == MAP_FAILED) {
				exit_with_error(errno);
				exit(EXIT_FAILURE);
			}

			/* Configure the UMEM */
			struct xsk_umem_config cfg = {
				.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
				.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
				.frame_size = conf.xsk_frame_size,
				.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
				.flags = conf.unaligned_chunks ?
						XDP_UMEM_UNALIGNED_CHUNK_FLAG : 0
			};
			int ret = xsk_umem__create(&workers[wrk_idx].umem, 
					workers[wrk_idx].buffer, umem_bufsize,
					&workers[wrk_idx].xsks[0].fq, &workers[wrk_idx].xsks[0].cq,
					&cfg);
			if (ret) {
				exit_with_error(-ret);
			}

			/* Create sockets */
			for (int if_idx = 0; if_idx < conf.num_interfaces; if_idx++) {
				workers[wrk_idx].xsks[if_idx].worker = &workers[wrk_idx];
				xsk_configure_socket(conf.interfaces[if_idx], wrk_idx,
						&workers[wrk_idx].xsks[if_idx]);
			}
		}
	}
	
	if (conf.working_mode & MODE_XDP) {
		sprintf(conf.xdp_filename, "%s_kern.o", argv[0]);
		printf("Loading custom XDP program...\n");
		load_xdp_program(conf.xdp_filename, &obj);
		*bpf_obj = obj;
		printf("Program loaded\n");
	} else {
		*bpf_obj = NULL;
	}

	memcpy(config, &conf, sizeof(struct xsknfv_config));

	return 0;
}

int xsknfv_cleanup()
{
	xsknfv_stop_workers();

	if (conf.working_mode & MODE_AF_XDP) {
		for (int wrk_idx = 0; wrk_idx < conf.workers; wrk_idx++) {
			for (int if_idx = 0; if_idx < conf.num_interfaces; if_idx++) {
				xsk_socket__delete(workers[wrk_idx].xsks[if_idx].xsk);
			}
			xsk_umem__delete(workers[wrk_idx].umem);
			munmap(workers[wrk_idx].buffer, umem_bufsize);
			free(workers[wrk_idx].xsks);
		}
		free(workers);
	}

	if (conf.working_mode & MODE_XDP) {
		for (int i = 0; i < conf.num_interfaces; i++) {
			bpf_set_link_xdp_fd(ifindexes[i], -1, opt_xdp_flags);
		}
	}

	free(ifindexes);
}

int xsknfv_start_workers()
{
	stop_workers = 0;

	if (conf.working_mode & MODE_AF_XDP) {
		for (int i = 0; i < conf.workers; i++) {
			int ret = pthread_create(&workers[i].thread, NULL, worker_loop,
					&workers[i]);
			if (ret)
				exit_with_error(ret);
		}
	}

	return 0;
}

int xsknfv_stop_workers()
{
	stop_workers = 1;

	if (conf.working_mode & MODE_AF_XDP) {
		for (int i = 0; i < conf.workers; i++)
			pthread_join(workers[i].thread, NULL);
	}

	return 0;
}

int xsknfv_get_socket_stats(unsigned worker_idx, unsigned iface_idx,
		struct xsknfv_socket_stats *stats)
{
	xsk_get_xdp_stats(xsk_socket__fd(workers[worker_idx].xsks[iface_idx].xsk),
			&workers[worker_idx].xsks[iface_idx].stats);

	memcpy(stats, &workers[worker_idx].xsks[iface_idx].stats,
			sizeof(struct xsknfv_socket_stats));

	return 0;
}