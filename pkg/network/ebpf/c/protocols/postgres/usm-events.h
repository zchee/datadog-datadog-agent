#ifndef __POSTGRES_USM_EVENTS_H
#define __POSTGRES_USM_EVENTS_H

#include "protocols/events-types.h"    // for BATCH_PAGES_PER_CPU
#include "protocols/events.h"          // for USM_EVENTS_INIT
#include "protocols/postgres/types.h"  // for postgres_event_t, POSTGRES_BAT...

USM_EVENTS_INIT(postgres, postgres_event_t, POSTGRES_BATCH_SIZE);

#endif
