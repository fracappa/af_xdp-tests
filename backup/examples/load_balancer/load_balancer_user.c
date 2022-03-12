#include "load_balancer.h"
#include "../common/statistics.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/hashmap.h>
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
static unsigned opt_pre_populate = 0;
#ifdef MONITOR_LOOKUP_TIME
volatile unsigned long lookup_time = 0;
#endif

struct bpf_object *obj;
struct xsknfv_config config;

#define IP_STRLEN 16
#define PROTO_STRLEN 4

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
struct hashmap services;
struct backend_entry *backend_entries;
struct hashmap backends;
/* 
 * This map should be handled in a LRU way, clearing older sessions when the map
 * is full. This is not done for simplicity.
 * In the eBPF LRU_HASH_MAP every bucket is handled as a LRU queue, this is
 * possible since it has a static size
 */
struct hashmap active_sessions;

static size_t hash_fn(const void *key, void *ctx)
{
	return (size_t)jhash(key, (uint32_t)(long)ctx, 0);
}

static bool equal_fn(const void *key1, const void *key2, void *ctx)
{
	return !memcmp(key1, key2, (uint32_t)(long)ctx);
}

void store_session(struct session_id *sid, struct replace_info *rep, int mapfd)
{
	if (config.working_mode & MODE_XDP) {
		if (bpf_map_update_elem(mapfd, sid, rep, 0)) {
			fprintf(stderr, "ERROR: unable to add session to bpf map\n");
			exit(EXIT_FAILURE);
		}

	} else {  // config.working_mode == MODE_AF_XDP
		struct session_entry *entry = malloc(sizeof(struct session_entry));
		if (!entry) {
			fprintf(stderr, "ERROR: malloc()\n");
			exit(EXIT_FAILURE);
		}
		entry->key = *sid;
		entry->value = *rep;
		if (hashmap__set(&active_sessions, &entry->key, &entry->value, NULL,
				NULL)) {
			fprintf(stderr, "ERROR: unable to add session to map\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void load_services(const char *services_path)
{
	char srv_addr[IP_STRLEN], bkd_addr[IP_STRLEN], proto[PROTO_STRLEN];
	unsigned srv_port, bkd_port;
	FILE *f;
	struct service_info *srv_info;
	struct service_entry *srv_entry;
	struct backend_entry *bkd_entry;
	struct in_addr addr;
	unsigned nservices, nbackends, service_first_free = 0;
	int i, ret;

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

	service_entries = malloc(sizeof(struct service_entry) * nservices);
	backend_entries = malloc(sizeof(struct backend_entry) * nbackends);
	hashmap__init(&services, hash_fn, equal_fn,
			(void *)sizeof(struct service_id));

	i = 0;
	while (fscanf(f, " %s %u %s %s %u ", srv_addr, &srv_port, proto, bkd_addr,
			&bkd_port) != EOF) {
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

		if (!hashmap__find(&services, &bkd_entry->key.service,
				(void **)&srv_info)) {
			srv_entry = &service_entries[service_first_free];
			srv_entry->key = bkd_entry->key.service;
			srv_entry->value.backends = 0;
			srv_info = &srv_entry->value;
			service_first_free++;

			if (hashmap__set(&services, &srv_entry->key, &srv_entry->value,
					NULL, NULL)) {
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
		hashmap__init(&active_sessions, hash_fn, equal_fn,
				(void *)sizeof(struct session_id));
		hashmap__init(&backends, hash_fn, equal_fn,
				(void *)sizeof(struct backend_id));

		for (int i = 0; i < nbackends; i++) {
			if (hashmap__set(&backends, &backend_entries[i].key,
					&backend_entries[i].value, NULL, NULL)) {
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

	if (opt_pre_populate > 0) {
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
		for (int i = 0; i < opt_pre_populate; i++) {
			sid.saddr = 0x0a | htonl((uint32_t)i);  // 10.i
			sid.daddr = service_entries[0].key.vaddr;
			sid.sport = htons(5000);
			sid.dport = service_entries[0].key.vport;
			sid.proto = service_entries[0].key.proto;

			/* Store the forward session */
			struct replace_info rep = {
				.dir = DIR_TO_BACKEND,
				.addr = backend_entries[i % nbackends].value.addr,
				.port = backend_entries[i % nbackends].value.port
			};
			store_session(&sid, &rep, mapfd);
			
			/* Store the backward session */
			sid.daddr = sid.saddr;
			sid.saddr = rep.addr;
			sid.dport = sid.sport;
			sid.sport = rep.port;
			rep.dir = DIR_TO_CLIENT;
			rep.addr = 0x000000ac;  // 172.0.0.0
			rep.port = htons(80);
			store_session(&sid, &rep, mapfd);
		}

		printf("Added %d sessions\n", opt_pre_populate);
	}

	return;
}

static void clear_maps()
{
	if (config.working_mode == MODE_AF_XDP) {
		struct hashmap_entry *cur;
		size_t bkt;
		struct hashmap *map = &active_sessions;

		hashmap__for_each_entry(map, cur, bkt) {
			free((void *)cur->key);
		}

		hashmap__clear(&active_sessions);
		hashmap__clear(&backends);
	}

	hashmap__clear(&services);

	free(backend_entries);
	free(service_entries);
}

int xsknfv_packet_processor(void *pkt, unsigned len)
{
	void *pkt_end = pkt + len;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return 0;
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
			return XDP_ABORTED;
		}

		sport = &tcph->source;
		dport = &tcph->dest;
		l4check = &tcph->check;

		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > pkt_end) {
			return XDP_ABORTED;
		}

		sport = &udph->source;
		dport = &udph->dest;
		l4check = &udph->check;

		break;

	default:
		return 0;
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
	struct replace_info *rep = NULL;
#ifdef MONITOR_LOOKUP_TIME
    struct timespec tp_before, tp_after;
    clock_gettime(CLOCK_MONOTONIC, &tp_before);
#endif
    hashmap__find(&active_sessions, &sid, (void **)&rep);
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

		goto FORWARD;
	}

	/* New session, apply load balancing logic */
	struct service_id srvid = {
		.vaddr = iph->daddr,
		.vport = *dport,
		.proto = iph->protocol
	};
	struct service_info *srvinfo;
	if (!hashmap__find(&services, &srvid, (void **)&srvinfo)) {
		/* Destination is not a virtual service */
		return 0;
	}

	struct backend_id bkdid = {
		.service = srvid,
		.index = jhash(&sid, sizeof(struct session_id), 0) % srvinfo->backends
	};
	struct backend_info *bkdinfo;
	if (!hashmap__find(&backends, &bkdid, (void **)&bkdinfo)) {
		fprintf(stderr, "ERROR: missing backend\n");
		return 0;
	}

	old_addr = iph->daddr;
	iph->daddr = bkdinfo->addr;
	new_addr = bkdinfo->addr;
	old_port = *dport;
	*dport = bkdinfo->port;
	new_port = bkdinfo->port;

	/* Store the forward session */
	struct session_entry *entry = malloc(sizeof(struct session_entry));
	if (!entry) {
		fprintf(stderr, "ERROR: malloc()\n");
		goto FORWARD;
	}
	entry->value = (struct replace_info) {
		.dir = DIR_TO_BACKEND,
		.addr = bkdinfo->addr,
		.port = bkdinfo->port
	};
	entry->key = sid;
	if (hashmap__set(&active_sessions, &entry->key, &entry->value, NULL,
			NULL)) {
		fprintf(stderr, "ERROR: unable to add forward session to map\n");
		goto FORWARD;
	}

	/* Store the backward session */
	entry = malloc(sizeof(struct session_entry));
	if (!entry) {
		fprintf(stderr, "ERROR: malloc()\n");
		goto FORWARD;
	}
	entry->value = (struct replace_info) {
		.dir = DIR_TO_CLIENT,
		.addr = srvid.vaddr,
		.port = srvid.vport
	};
	entry->key = (struct session_id) {
		.saddr = bkdinfo->addr,
		.daddr = sid.saddr,
		.sport = bkdinfo->port,
		.dport = sid.sport,
		.proto = sid.proto
	};
	if (hashmap__set(&active_sessions, &entry->key, &entry->value, NULL,
			NULL)) {
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

    /* Should update MAC addresses here */

	return 0;
}

static struct option long_options[] = {
	{"quiet", no_argument, 0, 'q'},
	{"extra-stats", no_argument, 0, 'x'},
	{"app-stats", no_argument, 0, 'a'},
	{"pre-populate", no_argument, 0, 'p'},
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
		"  -p, --pre-populate=n	Pre-populate the table of active sessions with n sessions.\n"
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "qxap:", long_options, &option_index);
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
			opt_pre_populate = atoi(optarg);
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

	load_services("/home/polycube/src/af_xdp-tests/examples/load_balancer/services.txt");

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