#ifndef __KAFKA_PARSING_MAPS_H
#define __KAFKA_PARSING_MAPS_H

#include "conn_tuple.h"             // for conn_tuple_t
#include "map-defs.h"               // for BPF_HASH_MAP, BPF_ARRAY_MAP, BPF_PERCPU_ARRAY_MAP
#include "protocols/kafka/types.h"  // for kafka_info_t, kafka_response_context_t, kafka_telemetry_t, kafka_transact...

BPF_PERCPU_ARRAY_MAP(kafka_heap, kafka_info_t, 1)

BPF_HASH_MAP(kafka_in_flight, kafka_transaction_key_t, kafka_transaction_t, 0)
BPF_HASH_MAP(kafka_response, conn_tuple_t, kafka_response_context_t, 0)

/*
 * This BPF map is utilized for kernel-space telemetry.
 * Only key 0 is utilized, and its corresponding value is a Kafka telemetry object.
 */
BPF_ARRAY_MAP(kafka_telemetry, kafka_telemetry_t, 1)

#endif
