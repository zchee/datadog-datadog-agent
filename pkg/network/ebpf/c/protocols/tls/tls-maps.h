#ifndef __TLS_MAPS_H
#define __TLS_MAPS_H

#include "map-defs.h"                       // for BPF_PERCPU_ARRAY_MAP
#include "protocols/classification/defs.h"  // for CLASSIFICATION_MAX_BUFFER

BPF_PERCPU_ARRAY_MAP(tls_classification_heap, char[CLASSIFICATION_MAX_BUFFER], 1)

#endif
