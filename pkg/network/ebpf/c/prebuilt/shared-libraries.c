#include "bpf_helpers.h"  // for SEC
#include "shared-libraries/maps.h" // IWYU pragma: keep
// all probes are shared among prebuilt and runtime, and can be found here
#include "shared-libraries/probes.h" // IWYU pragma: keep

char _license[] SEC("license") = "GPL";
