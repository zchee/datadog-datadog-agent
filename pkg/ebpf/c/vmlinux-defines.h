#ifndef __VMLINUX_DEFINES_H__
#define __VMLINUX_DEFINES_H__
#ifdef COMPILE_CORE

// this file contains defines from the kernel that are not captured in BTF/vmlinux.h

// source include/linux/socket.h
#define AF_INET 2 /* Internet IP Protocol */
#define AF_INET6 10 /* IP version 6 */
#define MSG_PEEK 2

// source include/uapi/linux/if_ether.h
#define ETH_HLEN 14 /* Total octets in header. */
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook */

// source include/net/inet_sock.h
#define inet_daddr sk.__sk_common.skc_daddr
#define inet_rcv_saddr sk.__sk_common.skc_rcv_saddr
#define inet_dport sk.__sk_common.skc_dport
#define inet_num sk.__sk_common.skc_num

// source include/net/sock.h
#define sk_num __sk_common.skc_num
#define sk_dport __sk_common.skc_dport
#define sk_v6_rcv_saddr __sk_common.skc_v6_rcv_saddr
#define sk_v6_daddr __sk_common.skc_v6_daddr
#define sk_daddr __sk_common.skc_daddr
#define sk_rcv_saddr __sk_common.skc_rcv_saddr
#define sk_family __sk_common.skc_family

// source include/net/flow.h
#define fl4_sport uli.ports.sport
#define fl4_dport uli.ports.dport
#define fl6_sport uli.ports.sport
#define fl6_dport uli.ports.dport

// source include/net/tcp.h
#define TCPHDR_FIN 0x01
#define TCPHDR_RST 0x04
#define TCPHDR_ACK 0x10

// source include/linux/err.h
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static __attribute__((always_inline)) __attribute__((__unused__)) bool IS_ERR_OR_NULL(const void *ptr)
{
    return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#endif
#endif
