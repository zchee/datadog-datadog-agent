#ifndef __POSTGRES_MAPS_H
#define __POSTGRES_MAPS_H

#include "conn_tuple.h"                // for conn_tuple_t
#include "map-defs.h"                  // for BPF_HASH_MAP, BPF_PERCPU_ARRAY_MAP
#include "protocols/postgres/types.h"  // for postgres_event_t, postgres_transaction_t

// Keeps track of in-flight Postgres transactions
BPF_HASH_MAP(postgres_in_flight, conn_tuple_t, postgres_transaction_t, 0)

// Acts as a scratch buffer for Postgres events, for preparing events before they are sent to userspace.
BPF_PERCPU_ARRAY_MAP(postgres_scratch_buffer, postgres_event_t, 1)

#endif
