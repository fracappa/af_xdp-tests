#include "policer_wc.h"

#include "../common/khashmap.h"
#include "../common/my_hashmap.h"
#include "../common/statistics.h"

#include <bpf/bpf.h>
#include <arpa/inet.h>
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
#include <time.h>
#include <pthread.h>
#include <sys/sysinfo.h>

static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;
#ifdef MONITOR_LOOKUP_TIME
volatile unsigned long lookup_time = 0;
#endif

struct bpf_object *obj, *obj_user;
int contracts_map, contracts_user_map;
struct xsknfv_config config;

unsigned nrules;
pthread_t refill_thread;
pthread_spinlock_t lock;


#define IP_STRLEN 16
#define PROTO_STRLEN 4


struct contract_entry{
	struct session_id key;
	struct contract contract;	// Policy to be applied to the session key
    int size;
};

struct khashmap contracts;
struct contract_entry *entries;

void *refill_counter(void *args){
	struct contract_entry *entries;
	entries = (struct contract_entry *)args;
	int ret,i;
    while(1){
		for(i=0; i < nrules; i++){
			// pthread_spin_lock(&lock);
			entries[i].contract.counter = entries[i].contract.rate * entries[i].contract.window_size;
			// pthread_spin_unlock(&lock);
			ret = bpf_map_update_elem(contracts_map, &entries[i].key, &entries[i].contract, BPF_ANY);
			// ret = bpf_map_update_elem(contracts_user_map, &entries[i].key, &entries[i].contract, BPF_ANY);
			if (ret) {
				fprintf(stderr, "ERROR: bpf_map_update_elem.\n");
			}
		}
		usleep(1000000);
    }
    pthread_exit(0);
}


static inline unsigned limit_rate(void *pkt,unsigned len, struct contract *contract){
	void *pkt_end = pkt + len;
    uint64_t size = (pkt_end - pkt) * 8;

    if(contract->counter < size){
        return -1;
    }
    __sync_fetch_and_add(&contract->counter, -size);
    return 0;

}

int xsknfv_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;
	struct session_id key;
	struct contract contract;
	int ret;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return 0;
	}

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > pkt_end) {
		return 0;
	}

	void *next = (void *)iph + (iph->ihl << 2);

	switch (iph->protocol) {
	case IPPROTO_TCP:;
		struct tcphdr *tcph = next;
		if ((void *)(tcph + 1) > pkt_end) {
			return -1;
		}
		key.sport = tcph->source;
		key.dport = tcph->dest;
		break;

	case IPPROTO_UDP:;
		struct udphdr *udph = next;
		if ((void *)(udph + 1) > pkt_end) {
			return -1;
		}
		key.sport = udph->source;
		key.dport = udph->dest;
		break;

	}

	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.proto = iph->protocol;


	// ret = bpf_map_lookup_elem(contracts_user_map, &key, &contract);

	ret = bpf_map_lookup_elem(contracts_map, &key, &contract);


	if (ret) {
		printf("No contract..\n");
		return -1;
	}

  switch (contract.action) {
    case ACTION_PASS:
      return 0;
      break;

    case ACTION_LIMIT:
    	return limit_rate(pkt, len, &contract);
      break;

    case ACTION_DROP:
      return -1;
      break;
  }
  return 0;
}

static void init_contracts(const char *conctracts_path)
{
	char saddr[IP_STRLEN], daddr[IP_STRLEN], proto[PROTO_STRLEN];
	unsigned sport, dport;
	unsigned action, local;
	uint64_t rate, window_size;
	FILE *f = fopen(conctracts_path, "r");
	struct in_addr addr;
	struct contract_entry *entry;
	int i, ret;

	printf("Loading the contracts...\n");
	if (f == NULL) {
		exit_with_error(errno);
	}

	/* The first line shall contain the number of rules */
	if(fscanf(f, "%u", &nrules) != 1) {
		exit_with_error(-1);
	}

	entries = (struct contract_entry *)malloc(nrules * sizeof(struct contract_entry));

	i = 0;
	while(fscanf(f, "%s %s %u %u %s %u %u %lu %lu",
	 	saddr, daddr, &sport, &dport, proto, &action, &local, &rate, &window_size) != EOF){
		entry = &entries[i];

		inet_aton(saddr, &addr);
		entry->key.saddr = addr.s_addr;

		inet_aton(daddr, &addr);
		entry->key.daddr = addr.s_addr;

		entry->key.sport = htons(sport);
		entry->key.dport = htons(dport);
	


		if (strcmp(proto, "TCP") == 0) {
			entry->key.proto = IPPROTO_TCP;
		} else if (strcmp(proto, "UDP") == 0) {
			entry->key.proto = IPPROTO_UDP;
		}else if (strcmp(proto, "ICMP") == 0) {
			entry->key.proto = IPPROTO_ICMP;
		}
		else {
			fprintf(stderr, "Unexpected L4 protocol: %s\n", proto);
			exit(-1);
		}

		/* initialize contract attributes associated to the session key */
		entry->contract.action = action;
		entry->contract.local = local;
        entry->contract.rate = rate;
        entry->contract.window_size = window_size;
        entry->contract.counter = 0;						// initially empty

    
		i++;

		// if (config.working_mode & MODE_XDP) {
			struct bpf_map *map;

			map = bpf_object__find_map_by_name(obj, "contracts");
			contracts_map = bpf_map__fd(map);
			if (contracts_map < 0) {
				fprintf(stderr, "ERROR: no contracts map found: %s\n",
					strerror(contracts_map));
				exit(EXIT_FAILURE);
			}
			ret = bpf_map_update_elem(contracts_map, &entry->key, &entry->contract, BPF_ANY);
			if (ret) {
				fprintf(stderr, "ERROR: bpf_map_update_elem.\n");
				exit(EXIT_FAILURE);
			}
		// }
		// if(config.working_mode & MODE_AF_XDP){
			// struct bpf_map *map_user;

			// map_user = bpf_object__find_map_by_name(obj_user, "contracts_user");
			// contracts_user_map = bpf_map__fd(map_user);

			// if (contracts_user_map < 0) {
			// 	fprintf(stderr, "ERROR: no contracts map found: %s\n",
			// 		strerror(contracts_map));
			// 	exit(EXIT_FAILURE);
			// }
			// ret = bpf_map_update_elem(contracts_user_map, &entry->key, &entry->contract, BPF_ANY);
			// if (ret) {
			// 	fprintf(stderr, "ERROR: bpf_map_update_elem.\n");
			// 	exit(EXIT_FAILURE);
			// }
		// }
	}

	if (i != nrules) {
		fprintf(stderr, "Incorrent input file: mismatch in rules number\n");
		exit(-1);
	}
	

	// if (config.working_mode & MODE_AF_XDP) {
	// 	khashmap_init(&contracts, sizeof(struct session_id), sizeof(struct contract), MAX_CONTRACTS);
	// 	// my_hashmap__init(&acl, nrules, sizeof(struct session_id), sizeof(int));
	// 	for(int i = 0; i < nrules; i++){
	// 		if(khashmap_update_elem(&contracts, &entries[i].key,
	// 				&entries[i].contract, 0)){
	// 			fprintf(stderr, "Error adding elemetn to hash map\n");
	// 			exit(EXIT_FAILURE);
	// 		}
	// 	}
	// }
    pthread_create(&refill_thread, NULL, refill_counter, entries);
	printf("Contract loaded..\n");
    return;
}


static struct option long_options[] = {
	{"quiet", no_argument, 0, 'q'},
	{"extra-stats", no_argument, 0, 'x'},
	{"app-stats", no_argument, 0, 'a'},
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
		"\n";
	fprintf(stderr, str, prog);

	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv, char *app_path)
{
	int option_index, c;

	for (;;) {
		c = getopt_long(argc, argv, "qxa", long_options, &option_index);
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

	setlocale(LC_ALL, "");

	init_contracts("./contracts");

	printf("Clock thread launched..\n");

	xsknfv_start_workers();

	init_stats();


	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
			//dump_stats(config, obj, opt_extra_stats, opt_app_stats);

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
#endif  /* MONITOR_LOOKUP_TIME */
		}
	}

	xsknfv_cleanup();

	return 0;
}