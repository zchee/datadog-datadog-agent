#ifndef __HTTP_BUFFER_H
#define __HTTP_BUFFER_H

#include "bpf_telemetry.h"                  // for FN_INDX_bpf_probe_read_user
#include "protocols/classification/defs.h"  // for CLASSIFICATION_MAX_BUFFER
#include "protocols/http/types.h"           // for HTTP_BUFFER_SIZE
#include "protocols/read_into_buffer.h"     // for READ_INTO_USER_BUFFER

READ_INTO_USER_BUFFER(http, HTTP_BUFFER_SIZE)
READ_INTO_USER_BUFFER(classification, CLASSIFICATION_MAX_BUFFER)

READ_INTO_BUFFER(skb, HTTP_BUFFER_SIZE, BLK_SIZE)

#endif
