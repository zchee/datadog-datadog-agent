#ifndef __PROTOCOL_CLASSIFICATION_MAPS_H
#define __PROTOCOL_CLASSIFICATION_MAPS_H

#include "ktypes.h"                            // for bool
#include "map-defs.h"                          // for BPF_HASH_MAP
#include "protocols/classification/structs.h"  // for mongo_key

// A set (map from a key to a const bool value, we care only if the key exists in the map, and not its value) to
// mark if we've seen a specific mongo request, so we can eliminate false-positive classification on responses.
BPF_HASH_MAP(mongo_request_id, mongo_key, bool, 1024)

#endif
