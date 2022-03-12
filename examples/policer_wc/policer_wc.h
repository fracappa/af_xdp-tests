#include <stdint.h>

#define MAX_CONTRACTS 100000

enum action_type{
    ACTION_PASS,
    ACTION_LIMIT,
    ACTION_DROP
};

struct session_id {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
} __attribute__((packed));

struct contract{
    uint8_t action;
    uint8_t local;
    int64_t counter;
};
