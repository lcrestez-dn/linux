/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_TCP_STATS_H
#define _LINUX_TCP_STATS_H

#include <net/snmp.h>
#include <trace/events/tcp.h>

static inline void tcpext_inc_stats(const struct sock *sk, int field)
{ 
    SNMP_INC_STATS(sock_net(sk)->mib.net_statistics, field);
    trace_tcpext_mib(sk, field, +1);
}

static inline void __tcpext_inc_stats(const struct sock *sk, int field)
{ 
    __SNMP_INC_STATS(sock_net(sk)->mib.net_statistics, field);
    trace_tcpext_mib(sk, field, +1);
}

static inline void tcpext_add_stats(const struct sock *sk, int field, int value)
{ 
    SNMP_ADD_STATS(sock_net(sk)->mib.net_statistics, field, value);
    trace_tcpext_mib(sk, field, value);
}

static inline void __tcpext_add_stats(const struct sock *sk, int field, int value)
{ 
    __SNMP_ADD_STATS(sock_net(sk)->mib.net_statistics, field, value);
    trace_tcpext_mib(sk, field, value);
}

#endif /* _LINUX_TCP_STATS_H */
