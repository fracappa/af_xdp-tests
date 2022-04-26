#include "../common/statistics.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/hashmap.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <locale.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <xsknfv.h>

#include "shared_counter.skel.h"


static int benchmark_done;
static int opt_quiet;
static int opt_extra_stats;
static int opt_app_stats;

unsigned long user_counter = 0;

struct bpf_object *obj;
struct xsknfv_config config;

struct shared_counter_kern *skeleton;


int xsknfv_packet_processor(void *pkt, unsigned len, unsigned ingress_ifindex)
{
	void *pkt_end = pkt + len;

	struct ethhdr *eth = pkt;
	if ((void *)(eth + 1) > pkt_end) {
		return -1;
	}

    user_counter++;
    skeleton->bss->global_counter++;

    // __sync_fetch_and_add(&user_counter, 1);
    // __sync_fetch_and_add(&skeleton->bss->global_counter, 1);



	// swap_mac_addresses_v2(pkt);

	return 0;
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


int main(int argc, char **argv)
{
    int err; 

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);
	signal(SIGUSR1, int_usr);

	xsknfv_init(argc, argv, &config, &obj);

    if(config.working_mode & MODE_XDP){
		libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
		libbpf_set_print(libbpf_print_fn);

		skeleton = shared_counter_kern__open();

		err = shared_counter_kern__load(skeleton);
			if (err) {
				fprintf(stderr, "Failed to load and verify BPF skeleton\n");
				return 1;
		}
		int if_index = if_nametoindex(config.interfaces[0]);
		printf("Interface index: %d\n", if_index);
		if(!if_index){
			printf("get ifindex from interface name failed\n");
			return EXIT_FAILURE;
		}
		skeleton->links.shared_counter = bpf_program__attach_xdp(skeleton->progs.shared_counter, if_index);
		if(!skeleton->links.shared_counter){
			printf("unable to attach xdp program\n");
			return EXIT_FAILURE;
		}

		if (config.working_mode & MODE_AF_XDP) {
			enter_xsks_into_map(skeleton->obj);
		}

		printf("Skeleton OK\n");
	}

	parse_command_line(argc, argv, argv[0]);

	setlocale(LC_ALL, "");

	xsknfv_start_workers();

    init_stats();

	while (!benchmark_done) {
		sleep(1);
		if (!opt_quiet) {
            printf("XDP receeived pkts: -> %lu\n", skeleton->bss->xdp_counter);
            printf("AF_XDP received pkts: -> %lu\n", user_counter);
            printf("Total received pkts: -> %lu\n", skeleton->bss->global_counter);
            if(skeleton->bss->xdp_counter + user_counter == skeleton->bss->global_counter){
                printf("Numbers are OK\n");
            }
			//dump_stats(config, obj, opt_extra_stats, opt_app_stats);
		}
	}

	xsknfv_cleanup();

	return 0;
}