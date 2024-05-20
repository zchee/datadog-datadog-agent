#ifndef __HTTP2_USM_EVENTS_H
#define __HTTP2_USM_EVENTS_H

#include "conn_tuple.h"                     // for conn_tuple_t
#include "protocols/events-types.h"         // for BATCH_PAGES_PER_CPU
#include "protocols/events.h"               // for USM_EVENTS_INIT
#include "protocols/http2/decoding-defs.h"  // for http2_event_t, HTTP2_BATCH_SIZE, HTTP2_TERMINATED_BATCH_SIZE

USM_EVENTS_INIT(http2, http2_event_t, HTTP2_BATCH_SIZE);

USM_EVENTS_INIT(terminated_http2, conn_tuple_t, HTTP2_TERMINATED_BATCH_SIZE);

#endif
