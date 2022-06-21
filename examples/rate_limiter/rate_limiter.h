#include <stdint.h>

enum {
  ACTION_PASS,
  ACTION_LIMIT,
  ACTION_DROP
};

struct bucket {
  int64_t tokens;         /* tokens currently available */
  uint64_t refill_rate;   /* refill rate/ms */
  uint64_t capacity;    /* maximum bucket size */
  uint64_t last_refill;   /* timestamp last refill */
};

// struct contract {
//   int8_t action;
//   struct bucket bucket;
//   struct bpf_spin_lock lock;
// } /*__attribute__((packed))*/;

struct contract {
  int8_t action;
  int8_t local;
  struct bucket bucket;
};

struct session_id {
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
} __attribute__((packed));

struct mapping{
  unsigned hash_key;
  struct contract contract;
};

#define MAX_CONTRACTS 20