/*
 * Implementation of the access vector table type.
 *
 * Author : Stephen Smalley, <sds@tycho.nsa.gov>
 */

/* Updated: Frank Mayer <mayerf@tresys.com> and Karl MacMillan <kmacmillan@tresys.com>
 *
 *	Added conditional policy language extensions
 *
 * Copyright (C) 2003 Tresys Technology, LLC
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, version 2.
 *
 * Updated: Yuichi Nakamura <ynakam@hitachisoft.jp>
 *	Tuned number of hash slots for avtab to reduce memory usage
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include "avtab.h"
#include "policydb.h"
#include "hashtab.h"

static struct kmem_cache *avtab_node_cachep __ro_after_init;
static struct kmem_cache *avtab_trans_cachep __ro_after_init;
static struct kmem_cache *avtab_xperms_cachep __ro_after_init;

/* Based on MurmurHash3, written by Austin Appleby and placed in the
 * public domain.
 */
static inline int avtab_hash(const struct avtab_key *keyp, u32 mask)
{
	static const u32 c1 = 0xcc9e2d51;
	static const u32 c2 = 0x1b873593;
	static const u32 r1 = 15;
	static const u32 r2 = 13;
	static const u32 m  = 5;
	static const u32 n  = 0xe6546b64;

	u32 hash = 0;

#define mix(input) do { \
		u32 v = input; \
		v *= c1; \
		v = (v << r1) | (v >> (32 - r1)); \
		v *= c2; \
		hash ^= v; \
		hash = (hash << r2) | (hash >> (32 - r2)); \
		hash = hash * m + n; \
	} while (0)

	mix(keyp->target_class);
	mix(keyp->target_type);
	mix(keyp->source_type);

#undef mix

	hash ^= hash >> 16;
	hash *= 0x85ebca6b;
	hash ^= hash >> 13;
	hash *= 0xc2b2ae35;
	hash ^= hash >> 16;

	return hash & mask;
}

static struct avtab_node*
avtab_insert_node(struct avtab *h, int hvalue,
		  struct avtab_node *prev,
		  const struct avtab_key *key, const struct avtab_datum *datum)
{
	struct avtab_node *newnode;
	struct avtab_trans *trans;
	struct avtab_extended_perms *xperms;
	newnode = kmem_cache_zalloc(avtab_node_cachep, GFP_KERNEL);
	if (newnode == NULL)
		return NULL;
	newnode->key = *key;

	if (key->specified & AVTAB_XPERMS) {
		xperms = kmem_cache_zalloc(avtab_xperms_cachep, GFP_KERNEL);
		if (xperms == NULL) {
			kmem_cache_free(avtab_node_cachep, newnode);
			return NULL;
		}
		*xperms = *(datum->u.xperms);
		newnode->datum.u.xperms = xperms;
	} else if (key->specified & AVTAB_TRANSITION) {
		trans = kmem_cache_zalloc(avtab_trans_cachep, GFP_KERNEL);
		if (!trans) {
			kmem_cache_free(avtab_node_cachep, newnode);
			return NULL;
		}
		*trans = *datum->u.trans;
		newnode->datum.u.trans = trans;
	} else {
		newnode->datum.u.data = datum->u.data;
	}

	if (prev) {
		newnode->next = prev->next;
		prev->next = newnode;
	} else {
		struct avtab_node **n = &h->htable[hvalue];

		newnode->next = *n;
		*n = newnode;
	}

	h->nel++;
	return newnode;
}

static int avtab_insert(struct avtab *h, const struct avtab_key *key,
			const struct avtab_datum *datum)
{
	int hvalue;
	struct avtab_node *prev, *cur, *newnode;
	u16 specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h || !h->nslot)
		return -EINVAL;

	hvalue = avtab_hash(key, h->mask);
	for (prev = NULL, cur = h->htable[hvalue];
	     cur;
	     prev = cur, cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified)) {
			/* extended perms may not be unique */
			if (specified & AVTAB_XPERMS)
				break;
			return -EEXIST;
		}
		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	newnode = avtab_insert_node(h, hvalue, prev, key, datum);
	if (!newnode)
		return -ENOMEM;

	return 0;
}

/* Unlike avtab_insert(), this function allow multiple insertions of the same
 * key/specified mask into the table, as needed by the conditional avtab.
 * It also returns a pointer to the node inserted.
 */
struct avtab_node *avtab_insert_nonunique(struct avtab *h,
					  const struct avtab_key *key,
					  const struct avtab_datum *datum)
{
	int hvalue;
	struct avtab_node *prev, *cur;
	u16 specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h || !h->nslot)
		return NULL;
	hvalue = avtab_hash(key, h->mask);
	for (prev = NULL, cur = h->htable[hvalue];
	     cur;
	     prev = cur, cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			break;
		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}
	return avtab_insert_node(h, hvalue, prev, key, datum);
}

struct avtab_datum *avtab_search(struct avtab *h, const struct avtab_key *key)
{
	int hvalue;
	struct avtab_node *cur;
	u16 specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h || !h->nslot)
		return NULL;

	hvalue = avtab_hash(key, h->mask);
	for (cur = h->htable[hvalue]; cur;
	     cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return &cur->datum;

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}

	return NULL;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_search);

/* This search function returns a node pointer, and can be used in
 * conjunction with avtab_search_next_node()
 */
struct avtab_node *avtab_search_node(struct avtab *h,
				     const struct avtab_key *key)
{
	int hvalue;
	struct avtab_node *cur;
	u16 specified = key->specified & ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);

	if (!h || !h->nslot)
		return NULL;

	hvalue = avtab_hash(key, h->mask);
	for (cur = h->htable[hvalue]; cur;
	     cur = cur->next) {
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return cur;

		if (key->source_type < cur->key.source_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type < cur->key.target_type)
			break;
		if (key->source_type == cur->key.source_type &&
		    key->target_type == cur->key.target_type &&
		    key->target_class < cur->key.target_class)
			break;
	}
	return NULL;
}

struct avtab_node*
avtab_search_node_next(struct avtab_node *node, int specified)
{
	struct avtab_node *cur;

	if (!node)
		return NULL;

	specified &= ~(AVTAB_ENABLED|AVTAB_ENABLED_OLD);
	for (cur = node->next; cur; cur = cur->next) {
		if (node->key.source_type == cur->key.source_type &&
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class == cur->key.target_class &&
		    (specified & cur->key.specified))
			return cur;

		if (node->key.source_type < cur->key.source_type)
			break;
		if (node->key.source_type == cur->key.source_type &&
		    node->key.target_type < cur->key.target_type)
			break;
		if (node->key.source_type == cur->key.source_type &&
		    node->key.target_type == cur->key.target_type &&
		    node->key.target_class < cur->key.target_class)
			break;
	}
	return NULL;
}

static int avtab_trans_destroy_helper(void *k, void *d, void *args)
{
	kfree(k);
	kfree(d);
	return 0;
}

static void avtab_trans_destroy(struct avtab_trans *trans)
{
	hashtab_map(&trans->name_trans.table, avtab_trans_destroy_helper, NULL);
	hashtab_destroy(&trans->name_trans.table);
	hashtab_map(&trans->prefix_trans.table, avtab_trans_destroy_helper,
		    NULL);
	hashtab_destroy(&trans->prefix_trans.table);
	hashtab_map(&trans->suffix_trans.table, avtab_trans_destroy_helper,
		    NULL);
	hashtab_destroy(&trans->suffix_trans.table);
}

void avtab_destroy(struct avtab *h)
{
	int i;
	struct avtab_node *cur, *temp;

	if (!h)
		return;

	for (i = 0; i < h->nslot; i++) {
		cur = h->htable[i];
		while (cur) {
			temp = cur;
			cur = cur->next;
			if (temp->key.specified & AVTAB_XPERMS) {
				kmem_cache_free(avtab_xperms_cachep,
						temp->datum.u.xperms);
			} else if (temp->key.specified & AVTAB_TRANSITION) {
				avtab_trans_destroy(temp->datum.u.trans);
				kmem_cache_free(avtab_trans_cachep,
						temp->datum.u.trans);
			}
			kmem_cache_free(avtab_node_cachep, temp);
		}
	}
	kvfree(h->htable);
	h->htable = NULL;
	h->nel = 0;
	h->nslot = 0;
	h->mask = 0;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_destroy);

void avtab_init(struct avtab *h)
{
	h->htable = NULL;
	h->nel = 0;
	h->nslot = 0;
	h->mask = 0;
}

static int avtab_alloc_common(struct avtab *h, u32 nslot)
{
	if (!nslot)
		return 0;

	h->htable = kvcalloc(nslot, sizeof(void *), GFP_KERNEL);
	if (!h->htable)
		return -ENOMEM;

	h->nslot = nslot;
	h->mask = nslot - 1;
	return 0;
}

int avtab_alloc(struct avtab *h, u32 nrules)
{
	int rc;
	u32 nslot = 0;

	if (nrules != 0) {
		u32 shift = 1;
		u32 work = nrules >> 3;
		while (work) {
			work >>= 1;
			shift++;
		}
		nslot = 1 << shift;
		if (nslot > MAX_AVTAB_HASH_BUCKETS)
			nslot = MAX_AVTAB_HASH_BUCKETS;

		rc = avtab_alloc_common(h, nslot);
		if (rc)
			return rc;
	}

	pr_debug("SELinux: %d avtab hash slots, %d rules.\n", nslot, nrules);
	return 0;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_alloc);

int avtab_alloc_dup(struct avtab *new, const struct avtab *orig)
{
	return avtab_alloc_common(new, orig->nslot);
}

void avtab_hash_eval(struct avtab *h, const char *tag)
{
	int i, chain_len, slots_used, max_chain_len;
	unsigned long long chain2_len_sum;
	struct avtab_node *cur;

	slots_used = 0;
	max_chain_len = 0;
	chain2_len_sum = 0;
	for (i = 0; i < h->nslot; i++) {
		cur = h->htable[i];
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = cur->next;
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
			chain2_len_sum += chain_len * chain_len;
		}
	}

	pr_debug("SELinux: %s:  %d entries and %d/%d buckets used, "
	       "longest chain length %d sum of chain length^2 %llu\n",
	       tag, h->nel, slots_used, h->nslot, max_chain_len,
	       chain2_len_sum);
}

static const uint16_t spec_order[] = {
	AVTAB_ALLOWED,
	AVTAB_AUDITDENY,
	AVTAB_AUDITALLOW,
	AVTAB_TRANSITION,
	AVTAB_CHANGE,
	AVTAB_MEMBER,
	AVTAB_XPERMS_ALLOWED,
	AVTAB_XPERMS_AUDITALLOW,
	AVTAB_XPERMS_DONTAUDIT
};

static int avtab_trans_read_name_trans(struct policydb *pol,
					   struct symtab *target, void *fp)
{
	int rc;
	__le32 buf32[2];
	u32 nfnts, i, len, *fnt_otype = NULL;
	char *name = NULL;

	/* read number of name transitions */
	rc = next_entry(buf32, fp, sizeof(u32));
	if (rc)
		return rc;
	nfnts = le32_to_cpu(buf32[0]);

	rc = symtab_init(target, nfnts);
	if (rc)
		return rc;

	/* read name transitions */
	for (i = 0; i < nfnts; i++) {
		rc = -ENOMEM;
		fnt_otype = kmalloc(sizeof(u32), GFP_KERNEL);
		if (!fnt_otype)
			goto exit;

		/* read name transition otype and name length */
		rc = next_entry(buf32, fp, sizeof(u32) * 2);
		if (rc)
			goto exit;
		*fnt_otype = le32_to_cpu(buf32[0]);
		len = le32_to_cpu(buf32[1]);
		if (!policydb_type_isvalid(pol, *fnt_otype)) {
			pr_err("SELinux: avtab: invalid filename transition "
			       "type\n");
			rc = -EINVAL;
			goto exit;
		}

		/* read the name */
		rc = str_read(&name, GFP_KERNEL, fp, len);
		if (rc)
			goto exit;

		/* insert to the table */
		rc = symtab_insert(target, name, fnt_otype);
		if (rc)
			goto exit;
		name = NULL;
		fnt_otype = NULL;
	}

exit:
	kfree(fnt_otype);
	kfree(name);
	return rc;
}

static int avtab_trans_read(void *fp, struct policydb *pol,
			    struct avtab_trans *trans)
{
	int rc;
	__le32 buf32[1];

	if (pol->policyvers < POLICYDB_VERSION_AVTAB_FTRANS) {
		rc = next_entry(buf32, fp, sizeof(u32));
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		trans->otype = le32_to_cpu(*buf32);
		return 0;
	}

	/* read default otype */
	rc = next_entry(buf32, fp, sizeof(u32));
	if (rc)
		return rc;
	trans->otype = le32_to_cpu(buf32[0]);

	rc = avtab_trans_read_name_trans(pol, &trans->name_trans, fp);
	if (rc)
		goto bad;


	if (pol->policyvers >= POLICYDB_VERSION_PREFIX_SUFFIX) {
		rc = avtab_trans_read_name_trans(pol, &trans->prefix_trans, fp);
		if (rc)
			goto bad;
		rc = avtab_trans_read_name_trans(pol, &trans->suffix_trans, fp);
		if (rc)
			goto bad;
	}
	return 0;

bad:
	avtab_trans_destroy(trans);
	return rc;
}

int avtab_read_item(struct avtab *a, void *fp, struct policydb *pol,
		    int (*insertf)(struct avtab *a, const struct avtab_key *k,
				   const struct avtab_datum *d, void *p),
		    void *p)
{
	__le16 buf16[4];
	u16 enabled;
	u32 otype, items, items2, val, vers = pol->policyvers;
	struct avtab_key key;
	struct avtab_datum datum;
	struct avtab_trans trans;
	struct avtab_extended_perms xperms;
	__le32 buf32[ARRAY_SIZE(xperms.perms.p)];
	int i, rc;
	unsigned set;

	memset(&key, 0, sizeof(struct avtab_key));
	memset(&datum, 0, sizeof(struct avtab_datum));

	if (vers < POLICYDB_VERSION_AVTAB) {
		rc = next_entry(buf32, fp, sizeof(u32));
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		items2 = le32_to_cpu(buf32[0]);
		if (items2 > ARRAY_SIZE(buf32)) {
			pr_err("SELinux: avtab: entry overflow\n");
			return -EINVAL;

		}
		rc = next_entry(buf32, fp, sizeof(u32)*items2);
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		items = 0;

		val = le32_to_cpu(buf32[items++]);
		key.source_type = (u16)val;
		if (key.source_type != val) {
			pr_err("SELinux: avtab: truncated source type\n");
			return -EINVAL;
		}
		val = le32_to_cpu(buf32[items++]);
		key.target_type = (u16)val;
		if (key.target_type != val) {
			pr_err("SELinux: avtab: truncated target type\n");
			return -EINVAL;
		}
		val = le32_to_cpu(buf32[items++]);
		key.target_class = (u16)val;
		if (key.target_class != val) {
			pr_err("SELinux: avtab: truncated target class\n");
			return -EINVAL;
		}

		val = le32_to_cpu(buf32[items++]);
		enabled = (val & AVTAB_ENABLED_OLD) ? AVTAB_ENABLED : 0;

		if (!(val & (AVTAB_AV | AVTAB_TYPE))) {
			pr_err("SELinux: avtab: null entry\n");
			return -EINVAL;
		}
		if ((val & AVTAB_AV) &&
		    (val & AVTAB_TYPE)) {
			pr_err("SELinux: avtab: entry has both access vectors and types\n");
			return -EINVAL;
		}
		if (val & AVTAB_XPERMS) {
			pr_err("SELinux: avtab: entry has extended permissions\n");
			return -EINVAL;
		}

		for (i = 0; i < ARRAY_SIZE(spec_order); i++) {
			if (val & spec_order[i]) {
				key.specified = spec_order[i] | enabled;
				if (key.specified & AVTAB_TRANSITION) {
					memset(&trans, 0,
					       sizeof(struct avtab_trans));
					trans.otype =
						le32_to_cpu(buf32[items++]);
					datum.u.trans = &trans;
				} else {
					datum.u.data =
						le32_to_cpu(buf32[items++]);
				}
				rc = insertf(a, &key, &datum, p);
				if (rc)
					return rc;
			}
		}

		if (items != items2) {
			pr_err("SELinux: avtab: entry only had %d items, expected %d\n",
			       items2, items);
			return -EINVAL;
		}
		return 0;
	}

	rc = next_entry(buf16, fp, sizeof(u16)*4);
	if (rc) {
		pr_err("SELinux: avtab: truncated entry\n");
		return rc;
	}

	items = 0;
	key.source_type = le16_to_cpu(buf16[items++]);
	key.target_type = le16_to_cpu(buf16[items++]);
	key.target_class = le16_to_cpu(buf16[items++]);
	key.specified = le16_to_cpu(buf16[items++]);

	if (!policydb_type_isvalid(pol, key.source_type) ||
	    !policydb_type_isvalid(pol, key.target_type) ||
	    !policydb_class_isvalid(pol, key.target_class)) {
		pr_err("SELinux: avtab: invalid type or class\n");
		return -EINVAL;
	}

	set = 0;
	for (i = 0; i < ARRAY_SIZE(spec_order); i++) {
		if (key.specified & spec_order[i])
			set++;
	}
	if (!set || set > 1) {
		pr_err("SELinux:  avtab:  more than one specifier\n");
		return -EINVAL;
	}

	if ((vers < POLICYDB_VERSION_XPERMS_IOCTL) &&
			(key.specified & AVTAB_XPERMS)) {
		pr_err("SELinux:  avtab:  policy version %u does not "
				"support extended permissions rules and one "
				"was specified\n", vers);
		return -EINVAL;
	} else if (key.specified & AVTAB_XPERMS) {
		memset(&xperms, 0, sizeof(struct avtab_extended_perms));
		rc = next_entry(&xperms.specified, fp, sizeof(u8));
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		rc = next_entry(&xperms.driver, fp, sizeof(u8));
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		rc = next_entry(buf32, fp, sizeof(u32)*ARRAY_SIZE(xperms.perms.p));
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		for (i = 0; i < ARRAY_SIZE(xperms.perms.p); i++)
			xperms.perms.p[i] = le32_to_cpu(buf32[i]);
		datum.u.xperms = &xperms;
	} else if (key.specified & AVTAB_TRANSITION) {
		memset(&trans, 0, sizeof(struct avtab_trans));
		rc = avtab_trans_read(fp, pol, &trans);
		if (rc)
			return rc;
		datum.u.trans = &trans;
	} else {
		rc = next_entry(buf32, fp, sizeof(u32));
		if (rc) {
			pr_err("SELinux: avtab: truncated entry\n");
			return rc;
		}
		datum.u.data = le32_to_cpu(*buf32);
	}
	if (key.specified & AVTAB_TRANSITION) {
		/* if otype is set (non-zero), it must by a valid type */
		otype = datum.u.trans->otype;
		if (otype && !policydb_type_isvalid(pol, otype)) {
			pr_err("SELinux: avtab: invalid transition type\n");
			avtab_trans_destroy(&trans);
			return -EINVAL;
		}
		/*
		 * also each transition entry must meet at least one condition
		 * to be considered non-empty:
		 *  - set (non-zero) otype
		 *  - non-empty full name transitions table
		 *  - non-empty prefix name transitions table
		 *  - non-empty suffix name transitions table
		 */
		if (!otype &&
		    !datum.u.trans->name_trans.table.nel &&
		    !datum.u.trans->prefix_trans.table.nel &&
		    !datum.u.trans->suffix_trans.table.nel) {
			pr_err("SELinux: avtab: empty transition\n");
			avtab_trans_destroy(&trans);
			return -EINVAL;
		}
	} else if (key.specified & AVTAB_TYPE) {
		if (!policydb_type_isvalid(pol, datum.u.data)) {
			pr_err("SELinux: avtab: invalid type\n");
			return -EINVAL;
		}
	}
	rc = insertf(a, &key, &datum, p);
	if (rc && key.specified & AVTAB_TRANSITION)
		avtab_trans_destroy(&trans);
	return rc;
}

static int avtab_insertf(struct avtab *a, const struct avtab_key *k,
			 const struct avtab_datum *d, void *p)
{
	return avtab_insert(a, k, d);
}

int avtab_read(struct avtab *a, void *fp, struct policydb *pol)
{
	int rc;
	__le32 buf[1];
	u32 nel, i;


	rc = next_entry(buf, fp, sizeof(u32));
	if (rc < 0) {
		pr_err("SELinux: avtab: truncated table\n");
		goto bad;
	}
	nel = le32_to_cpu(buf[0]);
	if (!nel) {
		pr_err("SELinux: avtab: table is empty\n");
		rc = -EINVAL;
		goto bad;
	}

	rc = avtab_alloc(a, nel);
	if (rc)
		goto bad;

	for (i = 0; i < nel; i++) {
		rc = avtab_read_item(a, fp, pol, avtab_insertf, NULL);
		if (rc) {
			if (rc == -ENOMEM)
				pr_err("SELinux: avtab: out of memory\n");
			else if (rc == -EEXIST)
				pr_err("SELinux: avtab: duplicate entry\n");

			goto bad;
		}
	}

	rc = 0;
out:
	return rc;

bad:
	avtab_destroy(a);
	goto out;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_read);

static int avtab_trans_write_helper(void *k, void *d, void *fp)
{
	char *name = k;
	u32 *otype = d;
	int rc;
	__le32 buf32[2];
	u32 len;

	/* write filename transition otype and name length */
	len = strlen(name);
	buf32[0] = cpu_to_le32(*otype);
	buf32[1] = cpu_to_le32(len);
	rc = put_entry(buf32, sizeof(u32), 2, fp);
	if (rc)
		return rc;

	/* write filename transition name */
	rc = put_entry(name, sizeof(char), len, fp);
	if (rc)
		return rc;

	return 0;
}

static int avtab_trans_write(struct policydb *p, struct avtab_trans *cur,
			     void *fp)
{
	int rc;
	__le32 buf32[2];

	if (p->policyvers >= POLICYDB_VERSION_AVTAB_FTRANS) {
		/* write otype and number of name transitions */
		buf32[0] = cpu_to_le32(cur->otype);
		buf32[1] = cpu_to_le32(cur->name_trans.table.nel);
		rc = put_entry(buf32, sizeof(u32), 2, fp);
		if (rc)
			return rc;

		/* write name transitions */
		rc = hashtab_map(&cur->name_trans.table,
				 avtab_trans_write_helper, fp);
		if (rc)
			return rc;

		if (p->policyvers >= POLICYDB_VERSION_PREFIX_SUFFIX) {
			/* write number of prefix transitions */
			buf32[0] = cpu_to_le32(cur->prefix_trans.table.nel);
			rc = put_entry(buf32, sizeof(u32), 1, fp);
			if (rc)
				return rc;

			/* write prefix transitions */
			rc = hashtab_map(&cur->prefix_trans.table,
					 avtab_trans_write_helper, fp);
			if (rc)
				return rc;

			/* write number of suffix transitions */
			buf32[0] = cpu_to_le32(cur->suffix_trans.table.nel);
			rc = put_entry(buf32, sizeof(u32), 1, fp);
			if (rc)
				return rc;

			/* write suffix transitions */
			rc = hashtab_map(&cur->suffix_trans.table,
					 avtab_trans_write_helper, fp);
			if (rc)
				return rc;
		}
	} else if (cur->otype) {
		buf32[0] = cpu_to_le32(cur->otype);
		rc = put_entry(buf32, sizeof(u32), 1, fp);
		if (rc)
			return rc;
	}

	return 0;
}

int avtab_write_item(struct policydb *p, const struct avtab_node *cur, void *fp)
{
	__le16 buf16[4];
	__le32 buf32[ARRAY_SIZE(cur->datum.u.xperms->perms.p)];
	int rc;
	unsigned int i;

	if (p->policyvers < POLICYDB_VERSION_AVTAB_FTRANS &&
	    cur->key.specified & AVTAB_TRANSITION &&
	    !cur->datum.u.trans->otype)
		return 0;

	buf16[0] = cpu_to_le16(cur->key.source_type);
	buf16[1] = cpu_to_le16(cur->key.target_type);
	buf16[2] = cpu_to_le16(cur->key.target_class);
	buf16[3] = cpu_to_le16(cur->key.specified);
	rc = put_entry(buf16, sizeof(u16), 4, fp);
	if (rc)
		return rc;

	if (cur->key.specified & AVTAB_XPERMS) {
		rc = put_entry(&cur->datum.u.xperms->specified, sizeof(u8), 1, fp);
		if (rc)
			return rc;
		rc = put_entry(&cur->datum.u.xperms->driver, sizeof(u8), 1, fp);
		if (rc)
			return rc;
		for (i = 0; i < ARRAY_SIZE(cur->datum.u.xperms->perms.p); i++)
			buf32[i] = cpu_to_le32(cur->datum.u.xperms->perms.p[i]);
		rc = put_entry(buf32, sizeof(u32),
				ARRAY_SIZE(cur->datum.u.xperms->perms.p), fp);
	} else if (cur->key.specified & AVTAB_TRANSITION) {
		rc = avtab_trans_write(p, cur->datum.u.trans, fp);
	} else {
		buf32[0] = cpu_to_le32(cur->datum.u.data);
		rc = put_entry(buf32, sizeof(u32), 1, fp);
	}
	if (rc)
		return rc;
	return 0;
}

int avtab_write(struct policydb *p, struct avtab *a, void *fp)
{
	unsigned int i;
	int rc = 0;
	struct avtab_node *cur;
	__le32 buf[1];
	u32 nel;

	nel = a->nel;
	if (p->policyvers < POLICYDB_VERSION_AVTAB_FTRANS) {
		/*
		 * in older version, skip entries with only filename transition,
		 * as these are written out separately
		 */
		for (i = 0; i < a->nslot; i++) {
			for (cur = a->htable[i]; cur; cur = cur->next) {
				if (cur->key.specified & AVTAB_TRANSITION &&
				    !cur->datum.u.trans->otype)
					nel--;
			}
		}
	}
	buf[0] = cpu_to_le32(nel);
	rc = put_entry(buf, sizeof(u32), 1, fp);
	if (rc)
		return rc;

	for (i = 0; i < a->nslot; i++) {
		for (cur = a->htable[i]; cur;
		     cur = cur->next) {
			rc = avtab_write_item(p, cur, fp);
			if (rc)
				return rc;
		}
	}

	return rc;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_write);

void __init avtab_cache_init(void)
{
	avtab_node_cachep = kmem_cache_create("avtab_node",
					      sizeof(struct avtab_node),
					      0, SLAB_PANIC, NULL);
	avtab_trans_cachep = kmem_cache_create("avtab_trans",
					       sizeof(struct avtab_trans),
					       0, SLAB_PANIC, NULL);
	avtab_xperms_cachep = kmem_cache_create("avtab_extended_perms",
						sizeof(struct avtab_extended_perms),
						0, SLAB_PANIC, NULL);
}

/* policydb filename transitions compatibility */

static int avtab_insert_filename_trans(struct avtab *a,
				       const struct avtab_key *key,
				       char *name, u32 otype)
{
	int rc;
	struct avtab_node *node;
	struct avtab_trans new_trans = {0};
	struct avtab_datum new_datum = {.u.trans = &new_trans};
	struct avtab_datum *datum;
	u32 *otype_datum = NULL;

	datum = avtab_search(a, key);
	if (!datum) {
		/* 
		 * insert is acctually unique, but with this function we can get
		 * the inserted node and therefore the datum
		 */
		node = avtab_insert_nonunique(a, key, &new_datum);
		if (!node)
			return -ENOMEM;
		datum = &node->datum;
	}

	if (hashtab_is_empty(&datum->u.trans->name_trans.table)) {
		rc = symtab_init(&datum->u.trans->name_trans, 1 << 8);
		if (rc)
			return rc;
	}

	otype_datum = kmalloc(sizeof(u32), GFP_KERNEL);
	if (!otype_datum)
		return -ENOMEM;
	*otype_datum = otype;

	rc = symtab_insert(&datum->u.trans->name_trans, name, otype_datum);
	if (rc)
		kfree(otype_datum);

	return rc;
}

static int filename_trans_read_item(struct avtab *a, void *fp)
{
	int rc;
	__le32 buf32[4];
	u32 len, otype;
	char *name = NULL;
	struct avtab_key key;

	/* read length of the name */
	rc = next_entry(buf32, fp, sizeof(u32));
	if (rc)
		return rc;
	len = le32_to_cpu(buf32[0]);

	/* read the name */
	rc = str_read(&name, GFP_KERNEL, fp, len);
	if (rc)
		return rc;

	/* read stype, ttype, tclass and otype */
	rc = next_entry(buf32, fp, sizeof(u32) * 4);
	if (rc)
		goto bad;

	key.source_type = le32_to_cpu(buf32[0]);
	key.target_type = le32_to_cpu(buf32[1]);
	key.target_class = le32_to_cpu(buf32[2]);
	key.specified = AVTAB_TRANSITION;

	otype = le32_to_cpu(buf32[3]);

	rc = avtab_insert_filename_trans(a, &key, name, otype);
	if (rc)
		goto bad;

	return rc;

bad:
	kfree(name);
	return rc;
}

static int filename_trans_comp_read_item(struct avtab *a, void *fp)
{
	int rc;
	__le32 buf32[3];
	u32 len, ndatum, i, bit, otype;
	char *name = NULL, *name_copy = NULL;
	struct avtab_key key;
	struct ebitmap stypes;
	struct ebitmap_node *node;

	/* read length of the name */
	rc = next_entry(buf32, fp, sizeof(u32));
	if (rc)
		return rc;
	len = le32_to_cpu(*buf32);

	/* read the name */
	rc = str_read(&name, GFP_KERNEL, fp, len);
	if (rc)
		goto out;

	/* read target type, target class and number of elements for key */
	rc = next_entry(buf32, fp, sizeof(u32) * 3);
	if (rc)
		goto out;

	key.specified = AVTAB_TRANSITION;
	key.target_type = le32_to_cpu(buf32[0]);
	key.target_class = le32_to_cpu(buf32[1]);

	ndatum = le32_to_cpu(buf32[2]);
	if (ndatum == 0) {
		pr_err("SELinux:  Filename transition key with no datum\n");
		rc = -ENOENT;
		goto out;
	}

	for (i = 0; i < ndatum; i++) {
		rc = ebitmap_read(&stypes, fp);
		if (rc)
			goto out;

		rc = next_entry(buf32, fp, sizeof(u32));
		if (rc) {
			ebitmap_destroy(&stypes);
			goto out;
		}
		otype = le32_to_cpu(*buf32);

		ebitmap_for_each_positive_bit(&stypes, node, bit) {
			key.source_type = bit + 1;

			name_copy = kmemdup(name, len + 1, GFP_KERNEL);
			if (!name_copy) {
				ebitmap_destroy(&stypes);
				goto out;
			}

			rc = avtab_insert_filename_trans(a, &key, name_copy,
							 otype);
			if (rc) {
				ebitmap_destroy(&stypes);
				kfree(name_copy);
				goto out;
			}
		}

		ebitmap_destroy(&stypes);
	}
	rc = 0;

out:
	kfree(name);
	return rc;
}

int avtab_filename_trans_read(struct avtab *a, void *fp, struct policydb *p)
{
	int rc;
	__le32 buf[1];
	u32 nel, i;

	if (p->policyvers < POLICYDB_VERSION_FILENAME_TRANS)
		return 0;

	rc = next_entry(buf, fp, sizeof(u32));
	if (rc)
		return rc;
	nel = le32_to_cpu(buf[0]);

	if (p->policyvers < POLICYDB_VERSION_COMP_FTRANS) {
		for (i = 0; i < nel; i++) {
			rc = filename_trans_read_item(a, fp);
			if (rc)
				return rc;
		}
	} else {
		for (i = 0; i < nel; i++) {
			rc = filename_trans_comp_read_item(a, fp);
			if (rc)
				return rc;
		}
	}

	return 0;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_filename_trans_read);

struct filenametr_write_args {
	void *fp;
	struct avtab_key *key;
};

static int filenametr_write_helper(void *k, void *d, void *a)
{
	char *name = k;
	u32 *otype = d;
	struct filenametr_write_args *args = a;
	int rc;
	u32 len;
	__le32 buf32[4];

	len = strlen(name);
	buf32[0] = cpu_to_le32(len);
	rc = put_entry(buf32, sizeof(u32), 1, args->fp);
	if (rc)
		return rc;

	rc = put_entry(name, sizeof(char), len, args->fp);
	if (rc)
		return rc;

	buf32[0] = cpu_to_le32(args->key->source_type);
	buf32[1] = cpu_to_le32(args->key->target_type);
	buf32[2] = cpu_to_le32(args->key->target_class);
	buf32[3] = cpu_to_le32(*otype);

	rc = put_entry(buf32, sizeof(u32), 4, args->fp);
	if (rc)
		return rc;

	return 0;
}

struct filenametr_key {
	u32 ttype;		/* parent dir context */
	u16 tclass;		/* class of new object */
	const char *name;	/* last path component */
};

struct filenametr_datum {
	struct ebitmap stypes;	/* bitmap of source types for this otype */
	u32 otype;		/* resulting type of new object */
	struct filenametr_datum *next;	/* record for next otype*/
};

static int filenametr_comp_write_helper(void *k, void *d, void *fp)
{
	struct filenametr_key *key = k;
	struct filenametr_datum *datum = d;
	__le32 buf[3];
	int rc;
	u32 ndatum, len = strlen(key->name);
	struct filenametr_datum *cur;

	buf[0] = cpu_to_le32(len);
	rc = put_entry(buf, sizeof(u32), 1, fp);
	if (rc)
		return rc;

	rc = put_entry(key->name, sizeof(char), len, fp);
	if (rc)
		return rc;

	ndatum = 0;
	cur = datum;
	do {
		ndatum++;
		cur = cur->next;
	} while (unlikely(cur));

	buf[0] = cpu_to_le32(key->ttype);
	buf[1] = cpu_to_le32(key->tclass);
	buf[2] = cpu_to_le32(ndatum);
	rc = put_entry(buf, sizeof(u32), 3, fp);
	if (rc)
		return rc;

	cur = datum;
	do {
		rc = ebitmap_write(&cur->stypes, fp);
		if (rc)
			return rc;

		buf[0] = cpu_to_le32(cur->otype);
		rc = put_entry(buf, sizeof(u32), 1, fp);
		if (rc)
			return rc;

		cur = cur->next;
	} while (unlikely(cur));

	return 0;
}

static int filenametr_destroy(void *k, void *d, void *args)
{
	struct filenametr_key *key = k;
	struct filenametr_datum *datum = d;
	struct filenametr_datum *next;

	kfree(key);
	do {
		ebitmap_destroy(&datum->stypes);
		next = datum->next;
		kfree(datum);
		datum = next;
	} while (unlikely(datum));
	cond_resched();
	return 0;
}

static u32 filenametr_hash(const void *k)
{
	const struct filenametr_key *ft = k;
	unsigned long hash;
	unsigned int byte_num;
	unsigned char focus;

	hash = ft->ttype ^ ft->tclass;

	byte_num = 0;
	while ((focus = ft->name[byte_num++]))
		hash = partial_name_hash(focus, hash);
	return hash;
}

static int filenametr_cmp(const void *k1, const void *k2)
{
	const struct filenametr_key *ft1 = k1;
	const struct filenametr_key *ft2 = k2;
	int v;

	v = ft1->ttype - ft2->ttype;
	if (v)
		return v;

	v = ft1->tclass - ft2->tclass;
	if (v)
		return v;

	return strcmp(ft1->name, ft2->name);
}

static const struct hashtab_key_params filenametr_key_params = {
	.hash = filenametr_hash,
	.cmp = filenametr_cmp,
};

struct filenametr_tab_insert_args {
	struct avtab_key *key;
	struct hashtab *tab;
};

static int filenametr_tab_insert(void *k, void *d, void *a)
{
	char *name = k;
	u32 *otype = d;
	struct filenametr_tab_insert_args *args	= a;
	struct filenametr_key key, *ft = NULL;
	struct filenametr_datum *last, *datum = NULL;
	int rc;

	key.ttype = args->key->target_type;
	key.tclass = args->key->target_class;
	key.name = name;

	last = NULL;
	datum = hashtab_search(args->tab, &key, filenametr_key_params);
	while (datum) {
		if (unlikely(ebitmap_get_bit(&datum->stypes,
					     args->key->source_type - 1))) {
			/* conflicting/duplicate rules are ignored */
			datum = NULL;
			goto bad;
		}
		if (likely(datum->otype == *otype))
			break;
		last = datum;
		datum = datum->next;
	}
	if (!datum) {
		rc = -ENOMEM;
		datum = kmalloc(sizeof(*datum), GFP_KERNEL);
		if (!datum)
			goto bad;

		ebitmap_init(&datum->stypes);
		datum->otype = *otype;
		datum->next = NULL;

		if (unlikely(last)) {
			last->next = datum;
		} else {
			rc = -ENOMEM;
			ft = kmemdup(&key, sizeof(key), GFP_KERNEL);
			if (!ft)
				goto bad;

			ft->name = kmemdup(key.name, strlen(key.name) + 1,
					   GFP_KERNEL);
			if (!ft->name)
				goto bad;

			rc = hashtab_insert(args->tab, ft, datum,
					    filenametr_key_params);
			if (rc)
				goto bad;
		}
	}

	return ebitmap_set_bit(&datum->stypes, args->key->source_type - 1, 1);

bad:
	if (ft)
		kfree(ft->name);
	kfree(ft);
	kfree(datum);
	return rc;
}

int avtab_filename_trans_write(struct policydb *p, struct avtab *a, void *fp)
{
	int rc;
	__le32 buf32[1];
	u32 i, nel = 0;
	struct avtab_node *cur;
	struct hashtab fnts_tab;
	struct filenametr_tab_insert_args tab_insert_args = {.tab = &fnts_tab};
	struct filenametr_write_args write_args = {.fp = fp};

	if (p->policyvers < POLICYDB_VERSION_FILENAME_TRANS)
		return 0;

	/* count number of filename transitions */
	for (i = 0; i < a->nslot; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next) {
			if (cur->key.specified & AVTAB_TRANSITION)
				nel += cur->datum.u.trans->name_trans.table.nel;
		}
	}

	if (p->policyvers < POLICYDB_VERSION_COMP_FTRANS) {
		buf32[0] = cpu_to_le32(nel);
		rc = put_entry(buf32, sizeof(u32), 1, fp);
		if (rc)
			return rc;

		/* write filename transitions */
		for (i = 0; i < a->nslot; i++) {
			for (cur = a->htable[i]; cur; cur = cur->next) {
				if (cur->key.specified & AVTAB_TRANSITION) {
					write_args.key = &cur->key;
					rc = hashtab_map(&cur->datum.u.trans->name_trans.table,
							 filenametr_write_helper,
							 &write_args);
					if (rc)
						return rc;
				}
			}
		}

		return 0;
	}

	/* init temp filename transition table */
	rc = hashtab_init(&fnts_tab, nel);
	if (rc)
		return rc;

	for (i = 0; i < a->nslot; i++) {
		for (cur = a->htable[i]; cur; cur = cur->next) {
			if (cur->key.specified & AVTAB_TRANSITION) {
				tab_insert_args.key = &cur->key;
				rc = hashtab_map(&cur->datum.u.trans->name_trans.table,
						 filenametr_tab_insert,
						 &tab_insert_args);
				if (rc)
					goto out;
			}
		}
	}

	/* write compressed filename transitions */
	buf32[0] = cpu_to_le32(fnts_tab.nel);
	rc = put_entry(buf32, sizeof(u32), 1, fp);
	if (rc)
		goto out;

	rc = hashtab_map(&fnts_tab, filenametr_comp_write_helper, fp);

out:
	/* destroy temp filename transitions table */
	hashtab_map(&fnts_tab, filenametr_destroy, NULL);
	hashtab_destroy(&fnts_tab);

	return rc;
}

/* Export for avtab KUnit tests */
EXPORT_SYMBOL_GPL(avtab_filename_trans_write);
