/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_TCP_AUTHOPT_H
#define _LINUX_TCP_AUTHOPT_H

#ifndef __GENKSYMS__

#include <uapi/linux/tcp.h>
#include <net/netns/tcp_authopt.h>
#include <linux/tcp.h>
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
 * Key structure lifetime is protected by RCU so send/recv code needs to hold a
 * single rcu_read_lock until they're done with the key.
 *
 * Global keys can be cached in sockets, this requires increasing kref.
 */
struct tcp_authopt_key_info {
	/** @node: node in &netns_tcp_authopt.head list */
	struct hlist_node node;
	/** @rcu: for kfree_rcu */
	struct rcu_head rcu;
	/** @ref: for kref_put */
	struct kref ref;
	/** @flags: Combination of &enum tcp_authopt_key_flag */
	u32 flags;
	/** @send_id: Same as &tcp_authopt_key.send_id */
	u8 send_id;
	/** @recv_id: Same as &tcp_authopt_key.recv_id */
	u8 recv_id;
	/** @alg_id: Same as &tcp_authopt_key.alg */
	u8 alg_id;
	/** @keylen: Same as &tcp_authopt_key.keylen */
	u8 keylen;
	/** @key: Same as &tcp_authopt_key.key */
	u8 key[TCP_AUTHOPT_MAXKEYLEN];
	/** @l3index: Same as &tcp_authopt_key.ifindex */
	int l3index;
	/** @prefix: Length of addr match (default full) */
	int prefixlen;
	/** @addr: Same as &tcp_authopt_key.addr */
	struct sockaddr_storage addr;
	/** @alg: Algorithm implementation matching alg_id */
	struct tcp_authopt_alg_imp *alg;
};

/**
 * struct tcp_authopt_info - Per-socket information regarding tcp_authopt
 *
 * This is lazy-initialized in order to avoid increasing memory usage for
 * regular TCP sockets. Once created it is only destroyed on socket close.
 */
struct tcp_authopt_info {
	/** @rcu: for kfree_rcu */
	struct rcu_head rcu;
	/** @flags: Combination of &enum tcp_authopt_key_flag */
	u32 flags;
	/** @src_isn: Local Initial Sequence Number */
	u32 src_isn;
	/** @dst_isn: Remote Initial Sequence Number */
	u32 dst_isn;
	/** @rcv_sne: Recv-side Sequence Number Extension tracking tcp_sock.rcv_nxt */
	u32 rcv_sne;
	/** @snd_sne: Send-side Sequence Number Extension tracking tcp_sock.snd_nxt */
	u32 snd_sne;

	/**
	 * @send_keyid: keyid currently being sent
	 *
	 * This is controlled by userspace by userspace if
	 * TCP_AUTHOPT_FLAG_LOCK_KEYID, otherwise we try to match recv_rnextkeyid
	 */
	u8 send_keyid;
	/**
	 * @send_rnextkeyid: rnextkeyid currently being sent
	 *
	 * This is controlled by userspace if TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID is set
	 */
	u8 send_rnextkeyid;
	/**
	 * @recv_keyid: last keyid received from remote
	 *
	 * This is reported to userspace but has no other special behavior attached.
	 */
	u8 recv_keyid;
	/**
	 * @recv_rnextkeyid: last rnextkeyid received from remote
	 *
	 * Linux tries to honor this unless TCP_AUTHOPT_FLAG_LOCK_KEYID is set
	 */
	u8 recv_rnextkeyid;

	/**
	 * @send_key: Current key used for sending, cached.
	 *
	 * Once a key is found it only changes by user or remote request.
	 *
	 * Field is protected by the socket lock and holds a kref to the key.
	 */
	struct tcp_authopt_key_info __rcu *send_key;
};

/* TCP authopt as found in header */
struct tcphdr_authopt {
	u8 num;
	u8 len;
	u8 keyid;
	u8 rnextkeyid;
	u8 mac[0];
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

struct tcp_authopt_net_shadow {
	struct netns_tcp_authopt tcp_authopt;
	atomic64_t fail_count;
};
#define TCP_AUTHOPT_NET_SHADOW 19861024

static inline struct tcp_authopt_net_shadow* get_tcp_authopt_net_shadow(struct net *net) {
	return klp_shadow_get(net, TCP_AUTHOPT_NET_SHADOW);
}

#ifdef CONFIG_TCP_AUTHOPT
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
		struct tcp_authopt_info **info,
		u8 *rnextkeyid)
{
	if (tcp_authopt_needed) {
		*info = get_tcp_authopt_info(tcp_sk(sk));

		if (*info)
			return __tcp_authopt_select_key(sk, *info, addr_sk, rnextkeyid, true);
	}
	return NULL;
}
int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct tcp_authopt_info *info,
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
void __tcp_authopt_finish_connect(struct sock *sk, struct sk_buff *skb,
				  struct tcp_authopt_info *info);
static inline void tcp_authopt_finish_connect(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_authopt_info *info;

	if (tcp_authopt_needed) {
		info = get_tcp_authopt_info(tcp_sk(sk));

		if (info)
			__tcp_authopt_finish_connect(sk, skb, info);
	}
}
void __tcp_authopt_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp);
static inline void tcp_authopt_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp)
{
	if (tcp_authopt_needed)
		return __tcp_authopt_time_wait(tcptw, tp);
}
/** tcp_authopt_inbound_check - check for valid TCP-AO signature.
 *
 * Return negative ERRNO on error, 0 if not present and 1 if present and valid.
 *
 * If the AO signature is present and valid then caller skips MD5 check.
 */
int __tcp_authopt_inbound_check(
		struct sock *sk,
		struct sk_buff *skb,
		struct tcp_authopt_info *info,
		const u8 *opt);
static inline int tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb, const u8 *opt)
{
	if (tcp_authopt_needed) {
		struct tcp_authopt_info *info = get_tcp_authopt_info(tcp_sk(sk));

		if (info)
			return __tcp_authopt_inbound_check(sk, skb, info, opt);
	}
	return 0;
}
static inline int tcp_authopt_inbound_check_req(struct request_sock *req, struct sk_buff *skb,
						const u8 *opt)
{
	if (tcp_authopt_needed) {
		struct sock *lsk = req->rsk_listener;
		struct tcp_authopt_info *info = get_tcp_authopt_info(tcp_sk(lsk));

		if (info)
			return __tcp_authopt_inbound_check((struct sock *)req, skb, info, opt);
	}
	return 0;
}
void __tcp_authopt_update_rcv_sne(struct tcp_sock *tp, struct tcp_authopt_info *info, u32 seq);
static inline void tcp_authopt_update_rcv_sne(struct tcp_sock *tp, u32 seq)
{
	struct tcp_authopt_info *info;

	if (tcp_authopt_needed) {
		info = get_tcp_authopt_info(tp);
		if (info)
			__tcp_authopt_update_rcv_sne(tp, info, seq);
	}
}
void __tcp_authopt_update_snd_sne(struct tcp_sock *tp, struct tcp_authopt_info *info, u32 seq);
static inline void tcp_authopt_update_snd_sne(struct tcp_sock *tp, u32 seq)
{
	struct tcp_authopt_info *info;

	if (tcp_authopt_needed) {
		info = get_tcp_authopt_info(tp);
		if (info)
			__tcp_authopt_update_snd_sne(tp, info, seq);
	}
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
static inline int tcp_authopt_hash(
		char *hash_location,
		struct tcp_authopt_key_info *key,
		struct tcp_authopt_key *info,
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
static inline void tcp_authopt_finish_connect(struct sock *sk, struct sk_buff *skb)
{
}
static inline void tcp_authopt_time_wait(
		struct tcp_timewait_sock *tcptw,
		struct tcp_sock *tp)
{
}
static inline int tcp_authopt_inbound_check(struct sock *sk, struct sk_buff *skb, const u8 *opt)
{
	return 0;
}
static inline int tcp_authopt_inbound_check_req(struct request_sock *sk, struct sk_buff *skb,
						const u8 *opt)
{
	return 0;
}
static inline void tcp_authopt_update_rcv_sne(struct tcp_sock *tp, u32 seq)
{
}
static inline void tcp_authopt_update_snd_sne(struct tcp_sock *tp, u32 seq)
{
}
#endif

#endif /* __GENKSYMS__ */
#endif /* _LINUX_TCP_AUTHOPT_H */
