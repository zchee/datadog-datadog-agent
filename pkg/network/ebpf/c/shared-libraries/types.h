#ifndef __SHARED_LIBRARIES_TYPES_H
#define __SHARED_LIBRARIES_TYPES_H

#include "ktypes.h"

#define LIB_SO_SUFFIX_SIZE 9
#define LIB_PATH_MAX_SIZE 120

typedef struct {
    __u32 pid;
    __u32 len;
    char buf[LIB_PATH_MAX_SIZE];
} lib_path_t;

#endif
