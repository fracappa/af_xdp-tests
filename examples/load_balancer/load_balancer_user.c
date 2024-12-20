#include "load_balancer.h"
#include "../common/khashmap.h"
#include "../common/statistics.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <unistd.h>
#include <xsknfv.h>
#ifdef MONITOR_LOOKUP_TIME
#include <time.h>
#endif

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
static unsigned opt_passthrough = 0;
static unsigned opt_local = 0;
#ifdef MONITOR_LOOKUP_TIME
volatile unsigned long lookup_time = 0;
#endif

struct bpf_object *obj;
struct xsknfv_config config;

#define IP_STRLEN 16
#define PROTO_STRLEN 4
#define IFNAME_STRLEN 256

struct service_entry {
	struct service_id key;
	struct service_info value;
};

struct backend_entry {
	struct backend_id key;
	struct backend_info value;
};

struct session_entry {
	struct session_id key;
	struct replace_info value;
};

struct service_entry *service_entries;
struct khashmap services;
struct backend_entry *backend_entries;
struct khashmap backends;
/* 
 * This map should be handled in a LRU way, clearing older sessions when the map
 * is full. This is not done for simplicity.
 * In the eBPF LRU_HASH_MAP every bucket is handled as a LRU queue, this is
 * possible since it has a static size
 */
struct khashmap active_sessions;

static size_t hash_fn(const void *key, void *ctx)
{
	return (size_t)jhash(key, (uint32_t)(long)ctx, 0);
}

static bool equal_fn(const void *key1, const void *key2, void *ctx)
{
	return !memcmp(key1, key2, (uint32_t)(long)ctx);
}

static int ifname_to_app_idx(char *ifname)
{
    for (int i = 0; i < config.num_interfaces; i++) {
        if (strcmp(ifname, config.interfaces[i]) == 0) {
            return i;
        }
    }

    return -1;
}

static int ifname_to_kern_idx(char *ifname)
{
    return if_nametoindex(ifname);
}

void store_session(struct session_id *sid, struct replace_info *rep, int mapfd)
{
	if (config.working_mode & MODE_XDP) {
		if (bpf_map_update_elem(mapfd, sid, rep, 0)) {
			fprintf(stderr, "ERROR: unable to add session to bpf map\n");
			exit(EXIT_FAILURE);
		}

	} else {  /* config.working_mode == MODE_AF_XDP */
		struct session_entry *entry = malloc(sizeof(struct session_entry));
		if (!entry) {
			fprintf(stderr, "ERROR: malloc()\n");
			exit(EXIT_FAILURE);
		}
		entry->key = *sid;
		entry->value = *rep;
		if (khashmap_update_elem(&active_sessions, &entry->key, &entry->value,
				0)) {
			fprintf(stderr, "ERROR: unable to add session to map\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void load_services(const char *services_path)
{
	char srv_addr[IP_STRLEN], bkd_addr[IP_STRLEN], proto[PROTO_STRLEN],
            ifname[IFNAME_STRLEN];
	unsigned srv_port, bkd_port;
    uint8_t mac_addr[6];
	FILE *f;
	struct service_info *srv_info;
	struct service_entry *srv_entry;
	struct backend_entry *bkd_entry;
	struct in_addr addr;
	unsigned nservices, nbackends, service_first_free = 0;
	int i, ret, ifindex;

	printf("Loading services...\n");

	f = fopen(services_path, "r");
	if (f == NULL) {
		exit_with_error(errno);
	}

	/* The first line shall contain the number of services and backends */
	if(fscanf(f, "%u %u\n", &nservices, &nbackends) != 2) {
		fprintf(stderr, "ERROR: wrong services file format\n");
		exit_with_error(-1);
	}

    printf("Reading %u services and %u backends\n", nservices, nbackends);

	service_entries = malloc(sizeof(struct service_entry) * nservices);
	backend_entries = malloc(sizeof(struct backend_entry) * nbackends);
	khashmap_init(&services, sizeof(struct service_id),
			sizeof(struct service_info), MAX_SERVICES);

	i = 0;
	while ((ret = fscanf(f, " %s %u %s %s %u"
            " %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx %s", srv_addr, &srv_port,
            proto, bkd_addr, &bkd_port, &mac_addr[0], &mac_addr[1],
            &mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5], ifname))
            != EOF) {
        if (ret < 12) {
            fprintf(stderr, "ERROR: wrong services file format\n");
		    exit(EXIT_FAILURE);
        }

		bkd_entry = &backend_entries[i];
		inet_aton(srv_addr, &addr);
		bkd_entry->key.service.vaddr = addr.s_addr;
		bkd_entry->key.service.vport = htons(srv_port);
		if (strcmp(proto, "TCP") == 0) {
			bkd_entry->key.service.proto = IPPROTO_TCP;
		} else if (strcmp(proto, "UDP") == 0) {
			bkd_entry->key.service.proto = IPPROTO_UDP;
		} else {
			fprintf(stderr, "ERROR: Unexpected L4 protocol: %s\n", proto);
			exit(-1);
		}

		inet_aton(bkd_addr, &addr);
		bkd_entry->value.addr = addr.s_addr;
		bkd_entry->value.port = htons(bkd_port);
        __builtin_memcpy(&bkd_entry->value.mac_addr, mac_addr,
                sizeof(mac_addr));

		if (config.working_mode & MODE_XDP) {
			/* Traffic is processed only in XDP so use the kernel ifindex */
			ifindex = ifname_to_kern_idx(ifname);
		} else {
			/* Traffic is processed only in AF_XDP so use the app ifindex */
			ifindex = ifname_to_app_idx(ifname);
		}
        if (ifindex == -1) {
            fprintf(stderr, "ERROR: Parsed unknown interface %s\n", ifname);
            exit(EXIT_FAILURE);
        }
		bkd_entry->value.ifindex = ifindex;

		srv_info = khashmap_lookup_elem(&services, &bkd_entry->key.service);
		if (!srv_info) {
			srv_entry = &service_entries[service_first_free];
			srv_entry->key = bkd_entry->key.service;
			srv_entry->value.backends = 0;
			srv_info = &srv_entry->value;
			service_first_free++;

			if (khashmap_update_elem(&services, &srv_entry->key,
					&srv_entry->value, 0)) {
				fprintf(stderr, "ERROR: unable to add service to hash map\n");
				exit(EXIT_FAILURE);
			}
		}
		bkd_entry->key.index = srv_info->backends;
		srv_info->backends++;

		i++;
	}

	if (i != nbackends || service_first_free != nservices) {
		fprintf(stderr,
				"ERROR: incorrent input file: mismatch in items number\n");
		exit(-1);
	}

	if (config.working_mode == MODE_AF_XDP) {
		khashmap_init(&active_sessions, sizeof(struct session_id),
				sizeof(struct replace_info), MAX_SESSIONS);
		khashmap_init(&backends, sizeof(struct backend_id),
				sizeof(struct backend_info), MAX_BACKENDS);

		for (int i = 0; i < nbackends; i++) {
			/*
			 * Backend ifindexes are wrong (they are kernel indexes) but it is
			 * not a problem since no packet is effectively processed in AF_XDP
			 */
			if (khashmap_update_elem(&backends, &backend_entries[i].key,
					&backend_entries[i].value, 0)) {
				fprintf(stderr, "ERROR: unable to add backend to hash map\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	if (config.working_mode & MODE_XDP) {
		struct bpf_map *map;
		int i, mapfd;

		map = bpf_object__find_map_by_name(obj, "services");
		mapfd = bpf_map__fd(map);
		if (mapfd < 0) {
			fprintf(stderr, "ERROR: no services map found: %s\n",
					strerror(mapfd));
			exit(EXIT_FAILURE);
		}
		for (int i = 0; i < nservices; i++) {
			if (bpf_map_update_elem(mapfd, &service_entries[i].key,
					&service_entries[i].value, 0)) {
				fprintf(stderr, "ERROR: unable to add service to bpf map %d\n",
						i);
				exit(EXIT_FAILURE);
			}
		}

		map = bpf_object__find_map_by_name(obj, "backends");
		mapfd = bpf_map__fd(map);
		if (mapfd < 0) {
			fprintf(stderr, "ERROR: no backends map found: %s\n",
					strerror(mapfd));
			exit(EXIT_FAILURE);
		}
		for (int i = 0; i < nbackends; i++) {
			if (bpf_map_update_elem(mapfd, &backend_entries[i].key,
					&backend_entries[i].value, 0)) {
				fprintf(stderr, "ERROR: unable to add backend to bpf map %d\n",
						i);
				exit(EXIT_FAILURE);
			}
		}
	}

	printf("Added %u services and %u backends\n", nservices, nbackends);

	if (opt_passthrough > 0) {
		struct bpf_map *map;
		int mapfd = 0;
		struct session_id sid;

		if (config.working_mode & MODE_XDP) {
			map = bpf_object__find_map_by_name(obj, "active_sessions");
			mapfd = bpf_map__fd(map);
			if (mapfd < 0) {
				fprintf(stderr, "ERROR: no active_sessions map found: %s\n",
						strerror(mapfd));
				exit(EXIT_FAILURE);
			}
		}

		/* 
		 * Round-robin assign backends. For testing purposes it doesn't matter
		 * if it's not coherent with the load-balancing logic
		 */
		for (int i = 0; i < opt_passthrough; i++) {
			sid.saddr = 0x0a | htonl((uint32_t)i);  // 10.i
			sid.daddr = service_entries[0].key.vaddr;
			sid.sport = htons(5000);
			sid.dport = service_entries[0].key.vport;
			sid.proto = service_entries[0].key.proto;

			/* Store the forward session */
			struct replace_info rep;
			rep.dir = DIR_TO_BACKEND;
			rep.addr = backend_entries[i % nbackends].value.addr;
			rep.port = backend_entries[i % nbackends].value.port;
            __builtin_memcpy(&rep.mac_addr,
                    &backend_entries[i % nbackends].value.mac_addr,
                    sizeof(rep.mac_addr));
            rep.ifindex = backend_entries[i % nbackends].value.ifindex;
			store_session(&sid, &rep, mapfd);
			
			/* Store the backward session */
			sid.daddr = sid.saddr;
			sid.saddr = rep.addr;
			sid.dport = sid.sport;
			sid.sport = rep.port;
			rep.dir = DIR_TO_CLIENT;
			rep.addr = service_entries[0].key.vaddr;
			rep.port = service_entries[0].key.vport;
            __builtin_memset(&rep.mac_addr, 0, sizeof(rep.mac_addr));
            rep.ifindex = config.working_mode & MODE_XDP ?
					ifname_to_kern_idx(config.interfaces[0]) : 0;
			store_session(&sid, &rep, mapfd);
		}

		printf("Added %d pass-through sessions\n", opt_passthrough);
	
	} else if (opt_local > 0) {
		struct bpf_map *map;
		int mapfd = 0;
		struct session_id sid;

		if (config.working_mode & MODE_XDP) {
			map = bpf_object__find_map_by_name(obj, "active_sessions");
			mapfd = bpf_map__fd(map);
			if (mapfd < 0) {
				fprintf(stderr, "ERROR: no active_sessions map found: %s\n",
						strerror(mapfd));
				exit(EXIT_FAILURE);
			}
		}

		/* The entry to the memcached backend is expected at the first place */
		for (int i = 0; i < opt_local; i++) {
			sid.saddr = 0x0100000a;  /* 10.0.0.1 */
			sid.daddr = service_entries[0].key.vaddr;
			sid.sport = htons(5000 + i);
			sid.dport = service_entries[0].key.vport;
			sid.proto = service_entries[0].key.proto;

			/* Store the forward session */
			struct replace_info rep;
			rep.dir = DIR_TO_BACKEND;
			rep.addr = backend_entries[0].value.addr;
			rep.port = backend_entries[0].value.port;
            __builtin_memcpy(&rep.mac_addr, &backend_entries[0].value.mac_addr,
                    sizeof(rep.mac_addr));
            rep.ifindex = backend_entries[0].value.ifindex;
			store_session(&sid, &rep, mapfd);
			
			/* Store the backward session */
			sid.daddr = sid.saddr;
			sid.saddr = rep.addr;
			sid.dport = sid.sport;
			sid.sport = rep.port;
			rep.dir = DIR_TO_CLIENT;
			rep.addr = service_entries[0].key.vaddr;
			rep.port = service_entries[0].key.vport;
			/* This is awful even for a test, need to find a better way */
			uint8_t src_mac[6] = {0x3c, 0xfd, 0xfe, 0xaf, 0xec, 0x48};
            __builtin_memcpy(&rep.mac_addr, src_mac, sizeof(rep.mac_addr));
            rep.ifindex = config.working_mode & MODE_XDP ?
					ifname_to_kern_idx(config.interfaces[0]) : 0;
			store_session(&sid, &rep, mapfd);
		}

		printf("Added %d local sessions\n", opt_local);

	}

	return;
}

static void clear_maps()
{
	if (config.working_mode == MODE_AF_XDP) {
		khashmap_clear(&active_sessions);
		khashmap_clear(&backends);
	}

	khashmap_clear(&services);

	free(backend_entries);
	free(service_entries);
}

int xsknfv_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
        /* 
         * Temporary, send the packet back on the interface. What to do? Can't
         * rely on kernel stack
         */
		return ingress_ifindex;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > pkt_end) {
		return -1;
	}

	void *next = (void *)iph + (iph->ihl << 2);
	uint16_t *sport, *dport, *l4check;

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > pkt_end) {
			return -1;
		}

		sport = &tcph->source;
		dport = &tcph->dest;
		l4check = &tcph->check;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > pkt_end) {
			return -1;
		}

		sport = &udph->source;
		dport = &udph->dest;
		l4check = &udph->check;

		break;

	default:
        /* 
         * Temporary, send the packet back on the interface. What to do? Can't
         * rely on kernel stack
         */
		return ingress_ifindex;
	}

	struct session_id sid = {0};
	sid.saddr = iph->saddr;
	sid.daddr = iph->daddr;
	sid.proto = iph->protocol;
	sid.sport = *sport;
	sid.dport = *dport;

    /* Used for checksum update before forward */
	uint32_t old_addr, new_addr;
	uint16_t old_port, new_port;

    unsigned output = -1;

	/* Look for known sessions */
	struct replace_info *rep = NULL;
#ifdef MONITOR_LOOKUP_TIME
    struct timespec tp_before, tp_after;
    clock_gettime(CLOCK_MONOTONIC, &tp_before);
#endif
    rep = khashmap_lookup_elem(&active_sessions, &sid);
#ifdef MONITOR_LOOKUP_TIME
    clock_gettime(CLOCK_MONOTONIC, &tp_after);
    lookup_time += tp_after.tv_nsec + tp_after.tv_sec * 1000000000
			- (tp_before.tv_nsec + tp_before.tv_sec * 1000000000);
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
        __builtin_memcpy(&eth->h_dest, &rep->mac_addr, sizeof(eth->h_dest));
        output = rep->ifindex;

		goto FORWARD;
	}

	/* New session, apply load balancing logic */
	struct service_id srvid = {
		.vaddr = iph->daddr,
		.vport = *dport,
		.proto = iph->protocol
	};
	struct service_info *srvinfo = khashmap_lookup_elem(&services, &srvid);
	if (!srvinfo) {
		/* Destination is not a virtual service */
        /* 
         * Temporary, send the packet back on the interface. What to do? Can't
         * rely on kernel stack
         */
		printf("Not a virtual service\n");
		return ingress_ifindex;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = jhash(&sid, sizeof(struct session_id), 0) % srvinfo->backends
	};
	struct backend_info *bkdinfo = khashmap_lookup_elem(&backends, &bkdid);
	if (!bkdinfo) {
		fprintf(stderr, "ERROR: missing backend\n");
		return -1;
	}

	old_addr = iph->daddr;
	iph->daddr = bkdinfo->addr;
	new_addr = bkdinfo->addr;
	old_port = *dport;
	*dport = bkdinfo->port;
	new_port = bkdinfo->port;
    __builtin_memcpy(&eth->h_dest, &bkdinfo->mac_addr, sizeof(eth->h_dest));
    output = bkdinfo->ifindex;

	/* Store the forward session */
	struct session_entry *entry = malloc(sizeof(struct session_entry));
	if (!entry) {
		fprintf(stderr, "ERROR: malloc()\n");
		goto FORWARD;
	}
	entry->value.dir = DIR_TO_BACKEND;
	entry->value.addr = bkdinfo->addr;
	entry->value.port = bkdinfo->port;
    __builtin_memcpy(&entry->value.mac_addr, &bkdinfo->mac_addr,
            sizeof(bkdinfo->mac_addr));
    entry->value.ifindex = bkdinfo->ifindex;
	entry->key = sid;
	if (khashmap_update_elem(&active_sessions, &entry->key, &entry->value, 0)) {
		fprintf(stderr, "ERROR: unable to add forward session to map\n");
		goto FORWARD;
	}

	/* Store the backward session */
	entry = malloc(sizeof(struct session_entry));
	if (!entry) {
		fprintf(stderr, "ERROR: malloc()\n");
		goto FORWARD;
	}
	entry->value.dir = DIR_TO_CLIENT;
	entry->value.addr = srvid.vaddr;
	entry->value.port = srvid.vport;
    __builtin_memcpy(&entry->value.mac_addr, &eth->h_source,
            sizeof(eth->h_source));
    entry->value.ifindex = ingress_ifindex;
	entry->key = (struct session_id) {
		.saddr = bkdinfo->addr,
		.daddr = sid.saddr,
		.sport = bkdinfo->port,
		.dport = sid.sport,
		.proto = sid.proto
	};
	if (khashmap_update_elem(&active_sessions, &entry->key, &entry->value, 0)) {
		fprintf(stderr, "ERROR: unable to add backward session to map\n");
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

    /* Should also update the source mac address */

	return output;
}

static struct option long_options[] = {
	{"quiet", no_argument, 0, 'q'},
	{"extra-stats", no_argument, 0, 'x'},
	{"app-stats", no_argument, 0, 'a'},
	{"passthrough", no_argument, 0, 'p'},
	{"local", no_argument, 0, 'l'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [XSKNFV_OPTIONS] -- [APP_OPTIONS]\n"
		"  App options:\n"
		"  -q, --quiet		Do not display any stats.\n"
		"  -x, --extra-stats	Display extra statistics.\n"
		"  -a, --app-stats	Display application (syscall) statistics.\n"
		"  -p, --passthrough=n	Populate the table of active sessions with n sessions for the pass-through test.\n"
		"  -l, --local=n		Populate the table of active sessions with n sessions for the local test.\n!"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "qxap:l:", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'q':
			opt_quiet = 1;
			break;
		case 'x':
			opt_extra_stats = 1;
			break;
		case 'a':
			opt_app_stats = 1;
			break;
		case 'p':
			if (opt_local > 0) {
				fprintf(stderr,
						"ERROR: can not set both pass-through and local test");
				usage(basename(app_path));
			}
			opt_passthrough = atoi(optarg);
			break;
		case 'l':
			if (opt_passthrough > 0) {
				fprintf(stderr,
						"ERROR: can not set both pass-through and local test");
				usage(basename(app_path));
			}
			opt_local = atoi(optarg);
			break;
		default:
			usage(basename(app_path));
		}
	}
}

static void int_exit(int sig)
{
	benchmark_done = 1;
}

static void int_usr(int sig)
{
	print_stats(&config, obj);
}

int main(int argc, char **argv)
{
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
	signal(SIGUSR1, int_usr);

	xsknfv_init(argc, argv, &config, &obj);

	parse_command_line(argc, argv, argv[0]);

	load_services("/home/test1b/git/af_xdp-tests/examples/load_balancer/services.txt");

	xsknfv_start_workers();

	init_stats();

	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
			dump_stats(config, obj, opt_extra_stats, opt_app_stats);

#ifdef MONITOR_LOOKUP_TIME
			unsigned long rx_npkts = 0;

			if (config.working_mode == MODE_AF_XDP) {
				struct xsknfv_socket_stats stats;

				for (int i = 0; i < config.workers; i++) {
					for (int j = 0; j < config.num_interfaces; j++) {
						xsknfv_get_socket_stats(i, j, &stats);
						rx_npkts += stats.rx_npkts;
					}
				}

			} else {
				unsigned int nr_cpus = libbpf_num_possible_cpus();
				struct xdp_cpu_stats values[nr_cpus];
				int i, map_fd, zero = 0;
				struct bpf_map *map;

				map = bpf_object__find_map_by_name(obj, "xdp_stats");
				map_fd = bpf_map__fd(map);
				if (map_fd < 0) {
					fprintf(stderr, "ERROR: no xdp_stats map found: %s\n",
						strerror(map_fd));
						exit(EXIT_FAILURE);
				}

				if ((bpf_map_lookup_elem(map_fd, &zero, values)) != 0) {
					fprintf(stderr,
							"ERROR: bpf_map_lookup_elem failed key:0x%X\n",
							zero);
					exit(EXIT_FAILURE);
				}

				for (int i = 0; i < nr_cpus; i++) {
					rx_npkts += values[i].rx_npkts;
				}

				map = bpf_object__find_map_by_name(obj, "lookup_time");
				map_fd = bpf_map__fd(map);
				if (map_fd < 0) {
					fprintf(stderr, "ERROR: no lookup_time map found: %s\n",
						strerror(map_fd));
						exit(EXIT_FAILURE);
				}

				unsigned long xdp_lookup_time;
				if ((bpf_map_lookup_elem(map_fd, &zero,
						&xdp_lookup_time)) != 0) {
					fprintf(stderr,
							"ERR: bpf_map_lookup_elem failed key:0x%X\n", zero);
					exit(EXIT_FAILURE);
				}

				lookup_time = xdp_lookup_time;
			}

			printf("Average lookup time %lu\n",
						rx_npkts == 0 ? 0 : lookup_time / rx_npkts);
#endif  // MONITOR_LOOKUP_TIME
		}
	}

	xsknfv_cleanup();

	clear_maps();

	return 0;
}