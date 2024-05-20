#ifndef __KAFKA_USM_EVENTS
#define __KAFKA_USM_EVENTS

#include "protocols/events-types.h"  // for BATCH_PAGES_PER_CPU
#include "protocols/events.h"        // for USM_EVENTS_INIT
#include "protocols/kafka/defs.h"    // for KAFKA_BATCH_SIZE
#include "protocols/kafka/types.h"   // for kafka_event_t

USM_EVENTS_INIT(kafka, kafka_event_t, KAFKA_BATCH_SIZE);

#endif
