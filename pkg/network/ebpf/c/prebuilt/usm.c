#ifndef COMPILE_CORE
#include "kconfig.h"
#include <net/sock.h>                                     // for sock
#endif

#include "bpf_helpers.h"                                  // for SEC, __sk_buff, log_debug
#include "bpf_tracing.h"                                  // for pt_regs, BPF_KPROBE, ___bpf_kprobe_args1, user_pt_regs
#include "protocols/classification/dispatcher-helpers.h"  // for dispatch_kafka, protocol_dispatcher_entrypoint
#include "protocols/http/usm-events.h"                    // for http_batch_flush
#include "protocols/http2/usm-events.h"                   // for http2_batch_flush, terminated_http2_batch_flush
#include "protocols/kafka/usm-events.h"                   // for kafka_batch_flush
#include "protocols/postgres/usm-events.h"                // for postgres_batch_flush
#include "protocols/tls/https.h"                          // for map_ssl_ctx_to_sock, tls_dispatch_kafka

// includes kept below because they declare eBPF program entrypoints
#include "protocols/http/http.h"                          // IWYU pragma: keep
#include "protocols/http2/decoding.h"                     // IWYU pragma: keep
#include "protocols/http2/decoding-tls.h"                 // IWYU pragma: keep
#include "protocols/kafka/kafka-parsing.h"                // IWYU pragma: keep
#include "protocols/postgres/decoding.h"                  // IWYU pragma: keep
#include "protocols/sockfd-probes.h"                      // IWYU pragma: keep
#include "protocols/tls/java/erpc_dispatcher.h"           // IWYU pragma: keep
#include "protocols/tls/java/erpc_handlers.h"             // IWYU pragma: keep
#include "protocols/tls/native-tls.h"                     // IWYU pragma: keep

SEC("socket/protocol_dispatcher")
int socket__protocol_dispatcher(struct __sk_buff *skb) {
    protocol_dispatcher_entrypoint(skb);
    return 0;
}

// This entry point is needed to bypass a memory limit on socket filters
// See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Known-issues
SEC("socket/protocol_dispatcher_kafka")
int socket__protocol_dispatcher_kafka(struct __sk_buff *skb) {
    dispatch_kafka(skb);
    return 0;
}

SEC("uprobe/tls_protocol_dispatcher_kafka")
int uprobe__tls_protocol_dispatcher_kafka(struct pt_regs *ctx) {
    tls_dispatch_kafka(ctx);
    return 0;
};

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe__tcp_sendmsg, struct sock *sk) {
    log_debug("kprobe/tcp_sendmsg: sk=%p", sk);
    // map connection tuple during SSL_do_handshake(ctx)
    map_ssl_ctx_to_sock(sk);

    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net__netif_receive_skb(struct pt_regs* ctx) {
    log_debug("tracepoint/net/netif_receive_skb");
    // flush batch to userspace
    // because perf events can't be sent from socket filter programs
    http_batch_flush(ctx);
    http2_batch_flush(ctx);
    terminated_http2_batch_flush(ctx);
    kafka_batch_flush(ctx);
    postgres_batch_flush(ctx);
    return 0;
}

char _license[] SEC("license") = "GPL";
