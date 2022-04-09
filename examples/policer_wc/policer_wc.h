#include <stdint.h>


#define MAX_CONTRACTS 10

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
    uint64_t counter;
    uint64_t last_update;
};

struct session_id {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
};

struct policy{
    unsigned key;
    struct contract contract;
};
