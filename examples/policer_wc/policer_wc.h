#include <stdint.h>


#define MAX_CONTRACTS 100000

enum {
    ACTION_PASS,
    ACTION_LIMIT,
    ACTION_DROP
};

struct contract{
    int8_t action;
    int8_t local;
    int64_t rate;
    int64_t window_size;
    int64_t counter;
};

struct session_id {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
} __attribute__((packed));


