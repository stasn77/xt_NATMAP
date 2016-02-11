/*
 *
 * Based on xt_ratelimit + xt_NETMAP.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/pkt_sched.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/netfilter/nf_nat.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include "xt_NATMAP.h"

#define XT_NATMAP_VERSION "0.1.6"
#include "version.h"
#ifdef GIT_VERSION
# undef XT_NATMAP_VERSION
# define XT_NATMAP_VERSION GIT_VERSION
#endif

MODULE_AUTHOR("<stasn77@gmail.com>");
MODULE_DESCRIPTION("iptables NATMAP module");
MODULE_LICENSE("GPL");
MODULE_VERSION(XT_NATMAP_VERSION);
MODULE_ALIAS("ipt_NATMAP");

static unsigned int hashsize __read_mostly = 1024;
static unsigned int disable_log __read_mostly = 0;
module_param(hashsize, uint, 0400);
MODULE_PARM_DESC(hashsize,
		" inital hash size used to look up IPs (default: 1024)");
module_param(disable_log, uint, S_IRUSR);
MODULE_PARM_DESC(disable_log,
		" disables logging of bind/timeout events (default: 0)");

static DEFINE_MUTEX(natmap_mutex);	/* htable lists management */

struct prenat_ent {
	__be32 addr;
	u32 cidr;
};

struct postnat_ent {
	__be32 from, to;
	u32 cidr;
};

/* set entity: prenat=postnat pairs */
struct natmap_ent {
	struct hlist_node node;		/* hash bucket list */
	spinlock_t lock_bh;
	struct prenat_ent  prenat;	/* prenat addr/cidr */
	struct postnat_ent postnat;	/* postnat from[-to|/cidr] range */
	struct {
		u32 pkts;
		u64 bytes;
	} stat;				/* stats for each entry */
	struct natmap_post_ent *post_ent;/* pointer to postnat ent */
	struct rcu_head rcu;		/* destruction call list */
};

struct natmap_post_ent {
	struct hlist_node node;		/* hash bucket list */
	spinlock_t lock_bh;
//	__be32 postnat_addr;		/* postnat addr */
	struct natmap_ent *ent;		/* pointer to prenat ent */
	struct rcu_head rcu;		/* destruction call list */
};

/* per-net named hash table, locked with natmap_mutex */
struct xt_natmap_htable {
	struct hlist_node node;		/* all htables */
	int use;			/* references from iptables */
	__u8 mode;			/* src or skb mode, pers & drop */
	spinlock_t lock;		/* write access to hash */
	unsigned int ent_count;		/* currently entities linked */
	unsigned int hsize;		/* hash array size */
	unsigned int cidr_map[33];	/* count of prefixes */
	struct net *net;		/* for destruction */
	struct proc_dir_entry *pde;
	char name[XT_NATMAP_NAME_LEN];
	struct hlist_head *hash;	/* rcu lists array of prenat_ent's */
	struct hlist_head *post;	/* rcu lists array of postnat_ent's */
};

/* net namespace support */
struct natmap_net {
	struct hlist_head	htables;
	struct proc_dir_entry	*ipt_natmap;
};

static int natmap_net_id;
/* return pointer to per-net-namespace struct */
static inline struct
natmap_net *natmap_pernet(struct net *net)
{
	return net_generic(net, natmap_net_id);
}

/* need to declare this at the top */
static const struct file_operations natmap_fops;

const __be32 cidr2mask[33] = {
	0x00000000, 0x00000080, 0x000000C0, 0x000000E0,
	0x000000F0, 0x000000F8, 0x000000FC, 0x000000FE,
	0x000000FF, 0x000080FF, 0x0000C0FF, 0x0000E0FF,
	0x0000F0FF, 0x0000F8FF, 0x0000FCFF, 0x0000FEFF,
	0x0000FFFF, 0x0080FFFF, 0x00C0FFFF, 0x00E0FFFF,
	0x00F0FFFF, 0x00F8FFFF, 0x00FCFFFF, 0x00FEFFFF,
	0x00FFFFFF, 0x80FFFFFF, 0xC0FFFFFF, 0xE0FFFFFF,
	0xF0FFFFFF, 0xF8FFFFFF, 0xFCFFFFFF, 0xFEFFFFFF,
	0xFFFFFFFF,
};
/*
static inline u32 cidr2mask(const int cidr) {
	return htonl(cidr ? ~0U << (32 - cidr) : 0);
}
*/
static inline u32
hash_addr(unsigned int hsize, const __be32 addr)
{
	return reciprocal_scale(jhash_1word(addr, 0), hsize);
}

static inline u32
hash_addr_mask(unsigned int hsize, const __be32 addr, const u32 cidr)
{
	return reciprocal_scale(jhash_2words(addr, cidr2mask[cidr], 0), hsize);
}

static struct natmap_ent *
natmap_ent_zalloc(void)
{
	struct natmap_ent *ent;
	unsigned int sz = sizeof(struct natmap_ent);

	if (sz <= PAGE_SIZE)
		ent = kzalloc(sz, GFP_KERNEL);
	else
		ent = vzalloc(sz);
	/* will not need INIT_HLIST_NODE because ent's are zeroized */

	return ent;
}

static struct natmap_post_ent *
natmap_post_ent_zalloc(void)
{
	struct natmap_post_ent *post_ent;
	unsigned int sz = sizeof(struct natmap_post_ent);

	if (sz <= PAGE_SIZE)
		post_ent = kzalloc(sz, GFP_KERNEL);
	else
		post_ent = vzalloc(sz);
	/* will not need INIT_HLIST_NODE because ent's are zeroized */

	return post_ent;
}

static struct hlist_head *
natmap_hash_zalloc(unsigned int hsize)
{
	struct hlist_head *hash;
	unsigned int sz = hsize * sizeof(struct hlist_head);

	if (sz <= PAGE_SIZE)
		hash = kzalloc(sz, GFP_KERNEL);
	else
		hash = vzalloc(sz);
	/* will not need INIT_HLIST_NODE because elements's are zeroized */

	return hash;
}

static void
natmap_hash_grow(struct xt_natmap_htable *ht)
{
	struct natmap_ent *ent;
	struct natmap_post_ent *post_ent;
	struct hlist_node *n;
	struct hlist_head *nhash, *ohash;
	unsigned int nsize, osize, i;

	nsize = ht->hsize * 2;
	nhash = natmap_hash_zalloc(nsize);
	if (nhash == NULL)
		return;
	ohash = ht->hash;
	osize = ht->hsize;
	ht->hsize = nsize;
	for (i = 0; i < osize; i++) {
		hlist_for_each_entry_safe(ent, n, &ohash[i], node) {
			spin_lock_bh(&ent->lock_bh);
			hlist_add_head_rcu(&ent->node, &nhash[hash_addr_mask(
			    nsize, ent->prenat.addr, ent->prenat.cidr)]);
			spin_unlock_bh(&ent->lock_bh);
		}
	}
	ht->hash = nhash;
	kvfree(ohash);

	nhash = natmap_hash_zalloc(nsize);
	if (nhash == NULL)
		return;
	ohash = ht->post;
	for (i = 0; i < osize; i++) {
		hlist_for_each_entry_safe(post_ent, n, &ohash[i], node) {
			spin_lock_bh(&post_ent->lock_bh);
			hlist_add_head_rcu(&post_ent->node, &nhash[hash_addr(
			    nsize, post_ent->ent->postnat.from)]);
			spin_unlock_bh(&post_ent->lock_bh);
		}
	}
	ht->post = nhash;
	kvfree(ohash);
}

/* register entry into hash table */
static void
natmap_ent_add(struct xt_natmap_htable *ht, struct natmap_ent *ent)
	/* under ht->lock */
{
	/* add each address into htable hash */
	hlist_add_head_rcu(&ent->node, &ht->hash[hash_addr_mask(
		ht->hsize, ent->prenat.addr, ent->prenat.cidr)]);

	ht->cidr_map[ent->prenat.cidr]++;
	ht->ent_count++;
}

static void
natmap_post_ent_add(struct xt_natmap_htable *ht, struct natmap_post_ent *post_ent)
	/* under ht->lock */
{
	/* add each address into htable hash */
	hlist_add_head_rcu(&post_ent->node, &ht->post[hash_addr(
		ht->hsize, post_ent->ent->postnat.from)]);
}

/* get entity by prenat address */
static inline struct natmap_ent *
natmap_ent_find(const struct xt_natmap_htable *ht,
const __be32 prenat_addr, const u32 cidr)
{
	u32 h, c;
	__be32 a;

	for (c = 32; c >= cidr; c--)
		if (ht->cidr_map[c]) {
			a = prenat_addr & cidr2mask[c];
			h = hash_addr_mask(ht->hsize, a, c);

			if (!hlist_empty(&ht->hash[h])) {
				struct natmap_ent *ent = NULL;

				hlist_for_each_entry_rcu(ent,
				    &ht->hash[h], node)
					if ((ent->prenat.cidr == c) &&
					    (ent->prenat.addr == a))
						return ent;
			}
		}

	return NULL;
}

/* reverse get entity by postnat address */
static inline struct natmap_ent *
natmap_ent_rfind(const struct xt_natmap_htable *ht,
const __be32 postnat_addr)
{
	u32 h;
	struct natmap_post_ent *post_ent = NULL;

	h = hash_addr(ht->hsize, postnat_addr);
	if (!hlist_empty(&ht->post[h]))
		hlist_for_each_entry_rcu(post_ent, &ht->post[h], node)
				if (post_ent->ent->postnat.from == postnat_addr)
					return post_ent->ent;

	return NULL;
}

/* allocate named hash table, register its proc entry */
static int
htable_create(struct net *net, struct xt_natmap_tginfo *tinfo)
	/* rule insertion chain, under natmap_mutex */
{
	struct natmap_net *natmap_net = natmap_pernet(net);
	struct xt_natmap_htable *ht;
	unsigned int hsize = hashsize;	/* (entities) */
	unsigned int sz;		/* (bytes) */

	if (hsize < 256 || hsize > 1000000)
		hsize = 1024;

	sz = sizeof(struct xt_natmap_htable);
	if (sz <= PAGE_SIZE)
		ht = kzalloc(sz, GFP_KERNEL);
	else
		ht = vzalloc(sz);
	if (ht == NULL)
		return -ENOMEM;

	ht->hash = natmap_hash_zalloc(hsize);
	if (ht->hash == NULL) {
		kvfree(ht);
		return -ENOMEM;
	}

	ht->post = natmap_hash_zalloc(hsize);
	if (ht->post == NULL) {
		kvfree(ht->hash);
		kvfree(ht);
		return -ENOMEM;
	}

	tinfo->ht = ht;

	ht->use = 1;
	ht->hsize = hsize;
	ht->ent_count = 0;
	ht->mode = tinfo->mode;
	strcpy(ht->name, tinfo->name);

	spin_lock_init(&ht->lock);

	ht->pde = proc_create_data(tinfo->name, 0644, natmap_net->ipt_natmap,
		    &natmap_fops, ht);
	if (ht->pde == NULL) {
		kvfree(ht->hash);
		kvfree(ht->post);
		kvfree(ht);
		return -ENOMEM;
	}
	ht->net = net;

	hlist_add_head(&ht->node, &natmap_net->htables);

	pr_info("Create target: %s (%s%s%s%s%s%s)\n", tinfo->name,
	    (tinfo->mode & XT_NATMAP_PRIO) ? "mode: prio"    : "",
	    (tinfo->mode & XT_NATMAP_MARK) ? "mode: mark"    : "",
	    (tinfo->mode & XT_NATMAP_ADDR) ? "mode: addr"    : "",
	    (tinfo->mode & XT_NATMAP_PERS) ? ", +persistent" : "",
	    (tinfo->mode & XT_NATMAP_DROP) ? ", +hotdrop"    : "",
	    (tinfo->mode & XT_NATMAP_CGNT) ? ", +cg-nat"     : "");

	return 0;
}

static void
natmap_ent_free_rcu(struct rcu_head *head)
{
	struct natmap_ent *ent = container_of(head, struct natmap_ent, rcu);

	kvfree(ent);
}

static void
natmap_post_ent_free_rcu(struct rcu_head *head)
{
	struct natmap_post_ent *post_ent = container_of(head, struct natmap_post_ent, rcu);

	kvfree(post_ent);
}

/* remove natmap entry, called from proc interface */
static void
natmap_ent_del(struct xt_natmap_htable *ht, struct natmap_ent *ent)
	/* htable_cleanup, under natmap_mutex */
	/* under ht->lock */
{
	ht->cidr_map[ent->prenat.cidr]--;

	hlist_del_rcu(&ent->node);

	call_rcu(&ent->rcu, natmap_ent_free_rcu);

	BUG_ON(ht->ent_count == 0);
	ht->ent_count--;
}

static void
natmap_post_ent_del(struct xt_natmap_htable *ht, struct natmap_post_ent *post_ent)
	/* htable_cleanup, under natmap_mutex */
	/* under ht->lock */
{
	hlist_del_rcu(&post_ent->node);

	call_rcu(&post_ent->rcu, natmap_post_ent_free_rcu);
}

/* destroy linked content of hash table */
static void
htable_cleanup(struct xt_natmap_htable *ht, const bool stat,
const struct postnat_ent *postnat)
	/* under natmap_mutex */
{
	unsigned int i;

	for (i = 0; i < ht->hsize; i++) {
		struct natmap_ent *ent;
		struct natmap_post_ent *post_ent;
		struct hlist_node *n;

		spin_lock(&ht->lock);
		if (!postnat)
			hlist_for_each_entry_safe(ent, n, &ht->hash[i], node)
				if (stat) {
					memset(&ent->stat, 0, sizeof(ent->stat));
				} else {
					if (ent->post_ent)
						natmap_post_ent_del(ht, ent->post_ent);
					natmap_ent_del(ht, ent);
				}
		else
			hlist_for_each_entry_safe(post_ent, n, &ht->post[i], node)
				if (stat) {
					memset(&post_ent->ent->stat, 0, sizeof(post_ent->ent->stat));
				} else {
					if (post_ent->ent &&
					    (memcmp(&post_ent->ent->postnat, postnat,
						sizeof(struct postnat_ent)) == 0)) {
						natmap_ent_del(ht, post_ent->ent);
						natmap_post_ent_del(ht, post_ent);
					}
				}

		spin_unlock(&ht->lock);
		cond_resched();
	}
}

static void
natmap_table_flush(struct xt_natmap_htable *ht, const bool stat)
{
	mutex_lock(&natmap_mutex);
	htable_cleanup(ht, stat, NULL);
	mutex_unlock(&natmap_mutex);
}

static void
natmap_postnat_del(struct xt_natmap_htable *ht,
const struct postnat_ent *postnat)
{
	mutex_lock(&natmap_mutex);
	htable_cleanup(ht, false, postnat);
	mutex_unlock(&natmap_mutex);
}

static void
htable_destroy(struct xt_natmap_htable *ht)
	/* caller htable_put, iptables rule deletion chain */
	/* under natmap_mutex */
{
	struct natmap_net *natmap_net = natmap_pernet(ht->net);

	/* natmap_net_exit() can independently unregister
	 * proc entries */
	if (natmap_net->ipt_natmap)
		remove_proc_entry(ht->name, natmap_net->ipt_natmap);

	htable_cleanup(ht, false, NULL);
	BUG_ON(ht->ent_count != 0);
	kvfree(ht->post);
	kvfree(ht->hash);
	kvfree(ht);
}

/* allocate htable caused by target insertion with iptables */
static int
htable_get(struct net *net, struct xt_natmap_tginfo *tinfo)
	/* iptables rule addition chain */
	/* under natmap_mutex */
{
	struct natmap_net *natmap_net = natmap_pernet(net);
	struct xt_natmap_htable *ht;

	hlist_for_each_entry(ht, &natmap_net->htables, node) {
		if (!strcmp(tinfo->name, ht->name)) {
			ht->use++;
			tinfo->ht = ht;
			return 0;
		}
	}
	return htable_create(net, tinfo);
}

/* remove htable caused by target rule deletion with iptables */
static void
htable_put(struct xt_natmap_htable *ht)
	/* caller natmap_mt_destroy, iptables rule deletion */
	/* under natmap_mutex */
{
	if (--ht->use == 0 && (!(ht->mode & XT_NATMAP_PERS))) {
		hlist_del(&ht->node);
		htable_destroy(ht);
	}
}

/* check the packet */
static unsigned int
natmap_tg(struct sk_buff *skb, const struct xt_action_param *par)
	/* under bh */
{
	const struct xt_natmap_tginfo *tginfo = par->targinfo;
	struct xt_natmap_htable *ht = tginfo->ht;
	const struct nf_nat_range *mr = &tginfo->range;
	struct nf_nat_range newrange;
	struct natmap_ent *ent;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int ret = XT_CONTINUE;
	__be32 prenat_addr, postnat_addr;

	NF_CT_ASSERT(par->hooknum == NF_INET_POST_ROUTING ||
		     par->hooknum == NF_INET_PRE_ROUTING);
	ct = nf_ct_get(skb, &ctinfo);

	rcu_read_lock();
	if (par->hooknum == NF_INET_PRE_ROUTING) {
		if (!(ht->mode & XT_NATMAP_2WAY))
			goto unlock;

		postnat_addr = ip_hdr(skb)->daddr;

		ent = natmap_ent_rfind(ht, postnat_addr);
		if (ent) {
			spin_lock(&ent->lock_bh);
			prenat_addr = ent->prenat.addr;
			spin_unlock(&ent->lock_bh);

			pr_info("Postnat found: %pI4 -> %pI4\n",
			    &postnat_addr, &prenat_addr);
			memset(&newrange, 0, sizeof(newrange));
			newrange.flags = mr->flags | NF_NAT_RANGE_MAP_IPS;
			newrange.min_addr.ip = prenat_addr;
			newrange.max_addr.ip = prenat_addr;
			newrange.min_proto = mr->min_proto;
			newrange.max_proto = mr->max_proto;
			ret = nf_nat_setup_info(ct, &newrange,
					 HOOK2MANIP(par->hooknum));
		}
		goto unlock;
	}

	if (tginfo->mode & XT_NATMAP_PRIO)
		prenat_addr = skb->priority;
	else if (tginfo->mode & XT_NATMAP_MARK)
		prenat_addr = skb->mark;
	else
		prenat_addr = ip_hdr(skb)->saddr;

	ent = natmap_ent_find(ht, prenat_addr, 1);
	if (ent) {
		memset(&newrange, 0, sizeof(newrange));
		newrange.flags = mr->flags
		    | NF_NAT_RANGE_MAP_IPS
		    | NF_NAT_RANGE_PERSISTENT;

		spin_lock(&ent->lock_bh);
		if (ent->postnat.cidr) {
			__be32 netmask;

			prenat_addr = ip_hdr(skb)->saddr;
			netmask = ~(ent->postnat.from ^ ent->postnat.to);
			newrange.min_addr.ip = (prenat_addr & ~netmask)
				| (ent->postnat.from & netmask);
			newrange.max_addr.ip = newrange.min_addr.ip;

			if (ht->mode & XT_NATMAP_CGNT) {
				u32 addrs;
				u16 min_port = 1536, ports = 64000;

				addrs = (1U << (32 - ent->prenat.cidr)) /
				    (htonl(ent->postnat.to
				    ^ ent->postnat.from) + 1);
				if (addrs) {
					if (!(ports /= addrs))
						ports = 1;
					min_port += ((htonl(prenat_addr
					    ^ ent->prenat.addr)
					    % addrs)) * ports;
				}
				newrange.min_proto.all = htons(min_port);
				newrange.max_proto.all = htons(min_port
							    + ports - 1);
/*				pr_info("addrs: %u, ports: %u, %u, %u, %u, min: %u, max: %u\n",
				    addrs, ports, addrs, htonl(prenat_addr ^ ent->prenat.addr), (htonl(prenat_addr ^ ent->prenat.addr) % addrs),
				    ntohs(newrange.min_proto.all),
				    ntohs(newrange.max_proto.all));
*/				newrange.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
			} else {
				newrange.min_proto = mr->min_proto;
				newrange.max_proto = mr->max_proto;
			}
		} else {
			newrange.min_addr.ip = ent->postnat.from;
			newrange.max_addr.ip = ent->postnat.to;
			newrange.min_proto = mr->min_proto;
			newrange.max_proto = mr->max_proto;
			newrange.flags |= NF_NAT_RANGE_PROTO_RANDOM_FULLY;
		}
		ent->stat.pkts++;
		ent->stat.bytes += skb->len;
		spin_unlock(&ent->lock_bh);

		ret = nf_nat_setup_info(ct, &newrange, HOOK2MANIP(par->hooknum));
		if (ret != NF_ACCEPT)
			pr_err("No free tuples to setup nat\n");
	} else if (ht->mode & XT_NATMAP_DROP)
		ret = NF_DROP;

unlock:
	rcu_read_unlock();
	return ret;
}

/* check and init target rule, allocating htable */
static int
natmap_tg_check(const struct xt_tgchk_param *par)
	/* iptables rule addition chain */
{
	struct net *net = par->net;
	struct xt_natmap_tginfo *tginfo = par->targinfo;
	const struct nf_nat_range *mr = &tginfo->range;
	int ret = 0;

	if (!(mr->flags & NF_NAT_RANGE_MAP_IPS)) {
		pr_debug("NATMAP: bad MAP_IPS.\n");
		return -EINVAL;
	}

	if (tginfo->name[sizeof(tginfo->name) - 1] != '\0')
		return -EINVAL;

//	if (!(par->hook_mask & (1 << NF_INET_PRE_ROUTING))) {
		mutex_lock(&natmap_mutex);
		ret = htable_get(net, tginfo);
		mutex_unlock(&natmap_mutex);
//	}
	return ret;
}

/* remove iptables target rule */
static void
natmap_tg_destroy(const struct xt_tgdtor_param *par)
	/* iptables rule deletion chain */
{
	const struct xt_natmap_tginfo *tginfo = par->targinfo;

	mutex_lock(&natmap_mutex);
	htable_put(tginfo->ht);
	mutex_unlock(&natmap_mutex);
}

static struct xt_target natmap_tg_reg[] __read_mostly = {
	{
		.name		= "NATMAP",
		.family		= NFPROTO_IPV4,
		.target		= natmap_tg,
		.targetsize	= sizeof(struct xt_natmap_tginfo),
		.table		= "nat",
		.hooks		= (1 << NF_INET_POST_ROUTING) |
				  (1 << NF_INET_PRE_ROUTING),
		.checkentry	= natmap_tg_check,
		.destroy	= natmap_tg_destroy,
		.me		= THIS_MODULE,
	},
};

/* PROC stuff */
static int
natmap_seq_ent_show(struct natmap_ent *ent, int mode, struct seq_file *s)
{
	/* lock for consistent reads from the counters */
	spin_lock_bh(&ent->lock_bh);

	if (mode & XT_NATMAP_ADDR)
		seq_printf(s, "%16pI4/%-2u",
		    &ent->prenat.addr, ent->prenat.cidr);
	else if (mode & XT_NATMAP_PRIO)
		seq_printf(s, "%04x:%04x",
		    TC_H_MAJ(ent->prenat.addr)>>16,
		    TC_H_MIN(ent->prenat.addr));
	else
		seq_printf(s, "0x%08x",
		    ent->prenat.addr);

	if (ent->postnat.cidr)
		seq_printf(s, " => %15pI4/%-15u",
		    &ent->postnat.from, ent->postnat.cidr);
	else
		seq_printf(s, " => %15pI4-%-15pI4",
		    &ent->postnat.from, &ent->postnat.to);

	seq_printf(s, "  stat: %u/%llu",
	    ent->stat.pkts, ent->stat.bytes);
	seq_puts(s, "\n");

	spin_unlock_bh(&ent->lock_bh);
	return seq_has_overflowed(s);
}

static int
natmap_seq_show(struct seq_file *s, void *v)
{
	struct xt_natmap_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct natmap_ent *ent;

	/* print everything from the bucket at once */
	if (!hlist_empty(&ht->hash[*bucket]))
		hlist_for_each_entry(ent, &ht->hash[*bucket], node)
			if (natmap_seq_ent_show(ent, ht->mode, s))
				return -1;

	return 0;
}

static void *
natmap_seq_start(struct seq_file *s, loff_t *pos)
	__acquires(&ht->lock)
{
	struct xt_natmap_htable *ht = s->private;
	unsigned int *bucket;

	spin_lock_bh(&ht->lock);
	if (*pos >= ht->hsize)
		return NULL;

	bucket = kmalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);
	*bucket = *pos;

	seq_printf(s, "# name: %s; entities: %u; hash size: %u; mode: %s%s%s; flags: %s%s%s%s\n",
	    ht->name, ht->ent_count, ht->hsize,
	    (ht->mode & XT_NATMAP_PRIO) ? "prio"  : "",
	    (ht->mode & XT_NATMAP_MARK) ? "mark"  : "",
	    (ht->mode & XT_NATMAP_ADDR) ? "addr"  : "",
	    (ht->mode & XT_NATMAP_PERS) ? "+persistent" : "-persistent",
	    (ht->mode & XT_NATMAP_DROP) ? ", +hotdrop"  : ", -hotdrop",
	    (ht->mode & XT_NATMAP_CGNT) ? ", +cg-nat"   : ", -cg-nat",
	    (ht->mode & XT_NATMAP_2WAY) ? ", +two-way"  : ", -two-way");

	return bucket;
}

static void *
natmap_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct xt_natmap_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos >= ht->hsize) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void
natmap_seq_stop(struct seq_file *s, void *v)
	__releases(&ht->lock)
{
	struct xt_natmap_htable *ht = s->private;
	unsigned int *bucket = (unsigned int *)v;

	if (!IS_ERR(bucket))
		kfree(bucket);
	spin_unlock_bh(&ht->lock);
}

static const struct seq_operations natmap_seq_ops = {
	.start		= natmap_seq_start,
	.show		= natmap_seq_show,
	.next		= natmap_seq_next,
	.stop		= natmap_seq_stop,
};

static int
natmap_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &natmap_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;

		sf->private = PDE_DATA(inode);
	}

	return ret;
}

static int
parse_rule(struct xt_natmap_htable *ht, char *c1, size_t size)
{
	char * const buf = c1;			/* for logging only */
	const char *c2;
	struct prenat_ent  prenat;
	struct postnat_ent postnat;
	struct natmap_ent *ent;			/* new entry  */
	struct natmap_post_ent *post_ent;	/* new entry  */
	struct natmap_ent *ent_chk = NULL;	/* old entry  */
	bool warn = true;
	int add;

	/* make sure that size is enough for two decrements */
	if (size < 2 || !c1 || !ht)
		return -EINVAL;

	/* strip trailing newline for better formatting of error messages */
	c1[--size] = '\0';

	/* rule format is: [@]+prenat_addr[/cidr]=postnat_from[-postnat_to]
	 *             or: [@]+0xFWMARK=postnat_from[-postnat_to]
	 *             or: [@]+MAJ:MIN=postnat_from[-postnat_to]
	*/
	if (*c1 == '@') {
		warn = false; /* hide redundant deletion warning */
		++c1;
		--size;
	}
	if (size < 1)
		return -EINVAL;

	switch (*c1) {
	case '\n':
	case '#':
		return 0;
	case '/': /* flush table */
		natmap_table_flush(ht, false);
		pr_info("Flushing table <%s>\n", ht->name);
		return 0;
	case ':': /* clear stats */
		natmap_table_flush(ht, true);
		pr_info("Clearing stats of table <%s>\n", ht->name);
		return 0;
	case '-':
		if (strcmp(c1, "-hotdrop") == 0) {
			ht->mode &= ~XT_NATMAP_DROP;
			pr_info("Hotdrop    OFF: <%s>\n", ht->name);
			return 0;
		} else if (strcmp(c1, "-persistent") == 0) {
			ht->mode &= ~XT_NATMAP_PERS;
			pr_info("Persistent OFF: <%s>\n", ht->name);
			return 0;
		} else if (strcmp(c1, "-cgnat") == 0) {
			ht->mode &= ~XT_NATMAP_CGNT;
			pr_info("CG-NAT     OFF: <%s>\n", ht->name);
			return 0;
		} else if ((c2 = strchr(c1, '='))) {
			if ((c2 - 1) == c1) {
				add = -2;
				break;
			}
		}
		add = -1;
		break;
	case '+':
		if (strcmp(c1, "+hotdrop") == 0) {
			ht->mode |= XT_NATMAP_DROP;
			pr_info("Hotprop     ON: <%s>\n", ht->name);
			return 0;
		} else if (strcmp(c1, "+persistent") == 0) {
			ht->mode |= XT_NATMAP_PERS;
			pr_info("Persistent  ON: <%s>\n", ht->name);
			return 0;
		} else if (strcmp(c1, "+cgnat") == 0) {
			ht->mode |= XT_NATMAP_CGNT;
			pr_info("CG-NAT     OFF: <%s>\n", ht->name);
			return 0;
		}
		add = 1;
		break;
	default:
		pr_err("Rule should start with '+', '-', or '/', (cmd: %s)\n", buf);
		return -EINVAL;
	}

	c2 = strchr(c1, '=');
	if (((add == 1) || (add == -2)) && !c2) {
		pr_err("This op must contain '=' in the rule, (cmd: %s)\n", buf);
		return -EINVAL;
	}
	++c1;
	++c2;

	/* Parse prenat, postnat addresses */
	memset(&postnat, 0, sizeof(postnat));
	if (add == 1 || add == -2) {
		if (!in4_pton(c2, strlen(c2), (u8 *)&postnat.from, -1, &c2)) {
			pr_err("Invalid postnat IPv4 address format, (cmd: %s)\n", buf);
			return -EINVAL;
		}
		if (strchr(c2, '-')) {
			++c2;
			if (!in4_pton(c2, strlen(c2), (u8 *)&postnat.to, -1, NULL)) {
				pr_err("Invalid postnat IPv4 address format, (cmd: %s)\n", buf);
				return -EINVAL;
			} else if (postnat.from > postnat.to) {
				pr_err("Second postnat IPv4 address must be > than first one, (cmd: %s)\n", buf);
				return -EINVAL;
			}
		} else if (strchr(c2, '/')) {
			if (sscanf(c2, "/%u", &postnat.cidr) == 1) {
				if (postnat.cidr < 1 || postnat.cidr > 32) {
					pr_err("Prefix must be in range - 1..32, (cmd: %s)\n", buf);
					return -EINVAL;
				}
			}
			postnat.from &= cidr2mask[postnat.cidr];
			postnat.to = postnat.from ^ ~cidr2mask[postnat.cidr];
		} else
			postnat.to = postnat.from;
	}

	prenat.addr = 0;
	prenat.cidr = 32;
	if (add == -2) {
		if (!disable_log) {
			if (postnat.cidr)
				pr_info("Del all entries where postnat = %pI4/%u\n",
				    &postnat.from, postnat.cidr);
			else
				pr_info("Del all entries where postnat = %pI4-%pI4\n",
				    &postnat.from, &postnat.to);
		}
		natmap_postnat_del(ht, &postnat);
		return 0;
	} else if (ht->mode & XT_NATMAP_ADDR) {
		if (!in4_pton(c1, strlen(c1), (u8 *)&prenat.addr, -1, &c2)) {
			pr_err("Invalid prenat IPv4 address format, (cmd: %s)\n", buf);
			return -EINVAL;
		}

		if (sscanf(c2, "/%u", &prenat.cidr) == 1) {
			if (prenat.cidr < 1 || prenat.cidr > 32) {
				pr_err("Prefix must be in range - 1..32, (cmd: %s)\n", buf);
				return -EINVAL;
			}
			prenat.addr &= cidr2mask[prenat.cidr];
		}
		if (!disable_log)
			pr_info("%s %pI4/%2u -> %pI4-%pI4, <%s>\n",
			    (add == 1) ? "Add" : "Del", &prenat.addr, prenat.cidr,
				&postnat.from, &postnat.to, ht->name);
	} else if (ht->mode & XT_NATMAP_MARK) {
		if (sscanf(c1, "0x%x", &prenat.addr) != 1) {
			pr_err("Invalid skb mark format, it should be: 0xMARK, (cmd: %s)\n", buf);
			return -EINVAL;
		}
		if (!disable_log)
			pr_info("%s 0x%x -> %pI4-%pI4, <%s>\n",
			    (add == 1) ? "Add" : "Del", prenat.addr,
				&postnat.from, &postnat.to, ht->name);
	} else if (ht->mode & XT_NATMAP_PRIO) {
		unsigned maj, min;

		if (sscanf(c1, "%x:%x", &maj, &min) != 2) {
			pr_err("Invalid skb prio format, it should be: MAJ:MIN, (cmd: %s)\n", buf);
			return -EINVAL;
		}
		prenat.addr = ((uint32_t)maj << 16) | (min & 0xffff);
		if (!disable_log)
			pr_info("%s %04x:%04x -> %pI4-%pI4, <%s>\n",
			    (add == 1) ? "Add" : "Del", maj, min,
				&postnat.from, &postnat.to, ht->name);
	}

	/* prepare ent */
	ent = natmap_ent_zalloc();
	if (!ent)
		return -ENOMEM;

	post_ent = natmap_post_ent_zalloc();
	if (!post_ent)
		return -ENOMEM;

	spin_lock_init(&ent->lock_bh);

	spin_lock(&ht->lock);

	/* check existence of these IPs */
	ent_chk = natmap_ent_find(ht, prenat.addr, prenat.cidr);

	if (add == 1) {
		/* add op should not reference any existing entries */
		/* unless it's update op (which is quiet add) */
		if (warn && ent_chk) {
			pr_err("Add op references existing address, (cmd: %s)\n", buf);
			goto unlock_einval;
		}
	} else if (add == -1) {
		/* delete op should reference something */
		if (warn && !ent_chk) {
			pr_err("Del op doesn't reference any existing address, (cmd: %s)\n", buf);
			goto unlock_einval;
		}
	}

	if (add == 1) {
		if (ent_chk) {
			/* update */
			spin_lock_bh(&ent_chk->lock_bh);
			ent_chk->postnat.from = postnat.from;
			ent_chk->postnat.to = postnat.to;
			ent_chk->postnat.cidr = postnat.cidr;
			natmap_post_ent_del(ht, ent_chk->post_ent);
			ent_chk->post_ent = post_ent;
			post_ent->ent = ent_chk;
			natmap_post_ent_add(ht, ent_chk->post_ent);
			spin_unlock_bh(&ent_chk->lock_bh);
		} else {
			ent->prenat.addr = prenat.addr;
			ent->prenat.cidr = prenat.cidr;
			ent->postnat.from = postnat.from;
			ent->postnat.to = postnat.to;
			ent->postnat.cidr = postnat.cidr;
			ent->post_ent = post_ent;
			post_ent->ent = ent;

			/* Rehash when load factor exceeds 0.75 */
			if (ht->ent_count * 4 > ht->hsize * 3) {
				pr_info("Growing hash size %u -> %u\n",
				    ht->hsize, ht->hsize * 2);
				natmap_hash_grow(ht);
			}
			natmap_ent_add(ht, ent);
			natmap_post_ent_add(ht, post_ent);
			ent = NULL;
			post_ent = NULL;
		}
	} else if (ent_chk) {
		if (ent_chk->post_ent)
			natmap_post_ent_del(ht, ent_chk->post_ent);
		natmap_ent_del(ht, ent_chk);
	}

	spin_unlock(&ht->lock);

	if (post_ent)
		kvfree(post_ent);
	if (ent)
		kvfree(ent);
	return 0;

unlock_einval:
	spin_unlock(&ht->lock);
	kvfree(post_ent);
	kvfree(ent);
	return -EINVAL;
}

static char proc_buf[100];

static ssize_t
natmap_proc_write(struct file *file, const char __user *input,
size_t size, loff_t *loff)
{
	struct xt_natmap_htable *ht = PDE_DATA(file_inode(file));
	char *p;

	if (!size || !input | !ht)
		return 0;
	if (size > sizeof(proc_buf))
		size = sizeof(proc_buf);
	if (copy_from_user(proc_buf, input, size) != 0)
		return -EFAULT;

	for (p = proc_buf; p < &proc_buf[size]; ) {
		char *str = p;

		while (p < &proc_buf[size] && *p != '\n')
			++p;
		if (p == &proc_buf[size] || *p != '\n') {
			/* unterminated command */
			if (str == proc_buf) {
				pr_err("Rule should end with '\\n'\n");
				return -EINVAL;
			} else {
				/* Rewind to the beginning of incomplete
				 * command for smarter writers, this doesn't
				 * help for `cat`, though. */
				p = str;
				break;
			}
		}
		++p;
		if (parse_rule(ht, str, p - str))
			return -EINVAL;
	}

	*loff += p - proc_buf;
	return p - proc_buf;
}

static const struct file_operations natmap_fops = {
	.owner		= THIS_MODULE,
	.open		= natmap_proc_open,
	.read		= seq_read,
	.write		= natmap_proc_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* net creation/destruction callbacks */
static int
__net_init natmap_net_init(struct net *net)
{
	struct natmap_net *natmap_net = natmap_pernet(net);

	INIT_HLIST_HEAD(&natmap_net->htables);
	natmap_net->ipt_natmap = proc_mkdir("ipt_NATMAP", net->proc_net);
	if (!natmap_net->ipt_natmap)
		return -ENOMEM;
	return 0;
}

/* unregister all htables from this net */
static void
__net_exit natmap_net_exit(struct net *net)
{
	struct natmap_net *natmap_net = natmap_pernet(net);
	struct xt_natmap_htable *ht;

	mutex_lock(&natmap_mutex);
	hlist_for_each_entry(ht, &natmap_net->htables, node)
		remove_proc_entry(ht->name, natmap_net->ipt_natmap);
	natmap_net->ipt_natmap = NULL; /* for htable_destroy() */
	mutex_unlock(&natmap_mutex);

	remove_proc_entry("ipt_NATMAP", net->proc_net); /* dir */
}

static struct pernet_operations natmap_net_ops = {
	.init   = natmap_net_init,
	.exit   = natmap_net_exit,
	.id     = &natmap_net_id,
	.size   = sizeof(struct natmap_net),
};

static int
__init natmap_tg_init(void)
{
	int err;

	err = register_pernet_subsys(&natmap_net_ops);
	if (err)
		return err;
	err = xt_register_targets(natmap_tg_reg, ARRAY_SIZE(natmap_tg_reg));
	if (err)
		unregister_pernet_subsys(&natmap_net_ops);
	pr_info(XT_NATMAP_VERSION " load %s, (hashsize=%u)\n",
	    err ? "error" : "success", hashsize);
	return err;
}

static void
__exit natmap_tg_exit(void)
{
	pr_info("unload.\n");
	xt_unregister_targets(natmap_tg_reg, ARRAY_SIZE(natmap_tg_reg));
	unregister_pernet_subsys(&natmap_net_ops);
}

module_init(natmap_tg_init);
module_exit(natmap_tg_exit);
