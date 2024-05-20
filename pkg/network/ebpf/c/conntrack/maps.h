#ifndef __CONNTRACK_MAPS_H
#define __CONNTRACK_MAPS_H

#include "conntrack/types.h"  // for conntrack_tuple_t
#include "map-defs.h"         // for BPF_HASH_MAP

/* This map is used for tracking conntrack entries
 */
BPF_HASH_MAP(conntrack, conntrack_tuple_t, conntrack_tuple_t, 1)

#endif
