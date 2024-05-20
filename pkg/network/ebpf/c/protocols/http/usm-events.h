#ifndef __HTTP_USM_EVENTS_H
#define __HTTP_USM_EVENTS_H

#include "protocols/events-types.h"  // for BATCH_PAGES_PER_CPU
#include "protocols/events.h"        // for USM_EVENTS_INIT
#include "protocols/http/types.h"    // for http_event_t, HTTP_BATCH_SIZE

USM_EVENTS_INIT(http, http_event_t, HTTP_BATCH_SIZE);

#endif
