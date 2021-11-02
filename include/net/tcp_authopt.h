/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_TCP_AUTHOPT_H
#define _LINUX_TCP_AUTHOPT_H

#include <uapi/linux/tcp.h>
#include <linux/livepatch.h>

/* According to RFC5925 the length of the authentication option varies based on
 * the signature algorithm. Linux only implements the algorithms defined in
 * RFC5926 which have a constant length of 16.
 *
 * This is used in stack allocation of tcp option buffers for output. It is
 * shorter than the length of the MD5 option.
 *
 * Input packets can have authentication options of different lengths but they
 * will always be flagged as invalid (since no such algorithms are supported).
 */
#define TCPOLEN_AUTHOPT_OUTPUT	16

struct tcp_authopt_alg_imp;

/**
 * struct tcp_authopt_key_info - Representation of a Master Key Tuple as per RFC5925
 *
 * Key structure lifetime is only protected by RCU so readers needs to hold a
 * single rcu_read_lock until they're done with the key.
 */
struct tcp_authopt_key_info {
	struct hlist_node node;
	struct rcu_head rcu;
	u32 flags;
	/* Wire identifiers */
	u8 send_id, recv_id;
	u8 alg_id;
	u8 keylen;
	u8 key[TCP_AUTHOPT_MAXKEYLEN];
	struct sockaddr_storage addr;
	struct tcp_authopt_alg_imp *alg;
};

/**
 * struct tcp_authopt_info - Per-socket information regarding tcp_authopt
 *
 * This is lazy-initialized in order to avoid increasing memory usage for
 * regular TCP sockets. Once created it is only destroyed on socket close.
 */
struct tcp_authopt_info {
	/** @head: List of tcp_authopt_key_info */
	struct hlist_head head;
	struct rcu_head rcu;
	/**
	 * @send_keyid - Current key used for sending, cached.
	 *
	 * Once a key is found it only changes by user or remote request.
	 */
	struct tcp_authopt_key_info *send_key;
	u32 flags;
	u8 send_keyid;
	u8 send_rnextkeyid;
	u8 recv_keyid;
	u8 recv_rnextkeyid;
	u32 src_isn;
	u32 dst_isn;
};

/* Do not use tcp_authopt_info itself as shadow to allow transfer from live to timewait socket. */
struct tcp_authopt_sock_shadow {
	struct tcp_authopt_info *info;
};

#define TCP_AUTHOPT_SOCK_SHADOW 19861023

static inline struct tcp_authopt_sock_shadow* get_tcp_authopt_shadow(struct sock *sk) {
	return klp_shadow_get(sk, TCP_AUTHOPT_SOCK_SHADOW);
}

static inline struct tcp_authopt_info* get_tcp_authopt_info(struct tcp_sock *tp) {
	struct tcp_authopt_sock_shadow* shadow = get_tcp_authopt_shadow((struct sock *)tp);
	return shadow ? shadow->info : NULL;
}

static inline struct tcp_authopt_info* get_tcp_tw_authopt_info(struct tcp_timewait_sock *tw) {
	struct tcp_authopt_sock_shadow* shadow = get_tcp_authopt_shadow((struct sock *)tw);
	return shadow ? shadow->info : NULL;
}

#ifdef CONFIG_TCP_AUTHOPT
extern int sysctl_tcp_authopt;
extern int tcp_authopt_needed;

void tcp_authopt_free(struct sock *sk, struct tcp_authopt_info *info);
void tcp_authopt_clear(struct sock *sk);
int tcp_set_authopt(struct sock *sk, char __user *optval, unsigned int optlen);
int tcp_get_authopt_val(struct sock *sk, struct tcp_authopt *key);
int tcp_set_authopt_key(struct sock *sk, char __user *optval, unsigned int optlen);
struct tcp_authopt_key_info *__tcp_authopt_select_key(
		const struct sock *sk,
		struct tcp_authopt_info *info,
		const struct sock *addr_sk,
		u8 *rnextkeyid,
		bool locked);
static inline struct tcp_authopt_key_info *tcp_authopt_select_key(
		const struct sock *sk,
		const struct sock *addr_sk,
		u8 *rnextkeyid)
{
	if (tcp_authopt_needed) {
		struct tcp_authopt_info *info = get_tcp_authopt_info(tcp_sk(sk));

		if (info)
			return __tcp_authopt_select_key(sk, info, addr_sk, rnextkeyid, true);
	}
	return NULL;
}
int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk, struct sk_buff *skb);
int tcp_v4_authopt_hash_reply(
		char *hash_location,
		struct tcp_authopt_info *info,
		struct tcp_authopt_key_info *key,
		__be32 saddr,
		__be32 daddr,
		struct tcphdr *th);
int __tcp_authopt_openreq(struct sock *newsk, const struct sock *oldsk, struct request_sock *req);
static inline int tcp_authopt_openreq(
		struct sock *newsk,
		const struct sock *oldsk,
		struct request_sock *req)
{
	if (!get_tcp_authopt_info(tcp_sk(oldsk)))
		return 0;
	else
		return __tcp_authopt_openreq(newsk, oldsk, req);
}
void __tcp_authopt_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp);
static inline void tcp_authopt_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp)
{
	if (tcp_authopt_needed)
		return __tcp_authopt_time_wait(tcptw, tp);
}
int __tcp_authopt_inbound_check(
		struct sock *sk,
		struct sk_buff *skb,
		struct tcp_authopt_info *info);
/** tcp_authopt_inbound_check - check for valid TCP-AO signature.
 *
 * Return negative ERRNO on error, 0 if not present and 1 if present and valid
 * If both TCP-AO and MD5 signatures are found this is reported as an error.
 */
static inline int tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb)
{
	if (tcp_authopt_needed) {
		struct tcp_authopt_info *info = get_tcp_authopt_info(tcp_sk(sk));

		if (info)
			return __tcp_authopt_inbound_check(sk, skb, info);
	}

	return 0;
}
#else
static inline int tcp_set_authopt(struct sock *sk, char __user *optval, unsigned int optlen)
{
	return -ENOPROTOOPT;
}
static inline int tcp_get_authopt_val(struct sock *sk, struct tcp_authopt *key)
{
	return -ENOPROTOOPT;
}
static inline void tcp_authopt_free(struct sock *sk, struct tcp_authopt_info *info)
{
}
static inline void tcp_authopt_clear(struct sock *sk)
{
}
static inline int tcp_set_authopt_key(struct sock *sk, char __user *optval, unsigned int optlen)
{
	return -ENOPROTOOPT;
}
static inline struct tcp_authopt_key_info *tcp_authopt_select_key(
		const struct sock *sk,
		const struct sock *addr_sk,
		u8 *rnextkeyid)
{
	return NULL;
}
static inline int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct sock *sk, struct sk_buff *skb)
{
	return -EINVAL;
}
static inline int tcp_authopt_openreq(struct sock *newsk,
				      const struct sock *oldsk,
				      struct request_sock *req)
{
	return 0;
}
static inline void tcp_authopt_time_wait(
		struct tcp_timewait_sock *tcptw,
		struct tcp_sock *tp);
{
}
static inline int tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}
#endif

#endif /* _LINUX_TCP_AUTHOPT_H */
