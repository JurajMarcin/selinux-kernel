// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for access vector table type Implementation
 *
 * Author: Juraj Marcin <juraj@jurajmarcin.com>
 */

#include <kunit/test.h>
#include "policydb.h"
#include "security.h"
#include "avtab.h"

static void filename_trans_read__pre_filename_trans(struct kunit *test)
{
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_FILENAME_TRANS - 1,
	};
	struct policy_file fp = {
		.data = NULL,
		.len = 0,
	};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;

	KUNIT_EXPECT_EQ(test, 0,
			avtab_filename_trans_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 0, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);
}

static void filename_trans_read__empty(struct kunit *test)
{
	char data[] = {0, 0, 0, 0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_FILENAME_TRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;

	KUNIT_EXPECT_EQ(test, 0,
			avtab_filename_trans_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 0, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);
}

static void filename_trans_read__comp_empty(struct kunit *test)
{
	char data[] = {0, 0, 0, 0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_COMP_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;

	KUNIT_EXPECT_EQ(test, 0,
			avtab_filename_trans_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 0, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);
}

static void filename_trans_read__simple(struct kunit *test)
{
	char data[] = {
		3, 0, 0, 0,	/* count */

		5, 0, 0, 0,			/* entry 1 name len */
		'f', 'i', 'l', 'e', '1',	/* entry 1 name */
		42, 0, 0, 0,			/* entry 1 stype */
		43, 0, 0, 0,			/* entry 1 ttype */
		44, 0, 0, 0,			/* entry 1 tclass */
		45, 0, 0, 0,			/* entry 1 otype */

		5, 0, 0, 0,			/* entry 2 name len */
		'f', 'i', 'l', 'e', '2',	/* entry 2 name */
		46, 0, 0, 0,			/* entry 2 stype */
		47, 0, 0, 0,			/* entry 2 ttype */
		48, 0, 0, 0,			/* entry 2 tclass */
		49, 0, 0, 0,			/* entry 2 otype */

		5, 0, 0, 0,			/* entry 3 name len */
		'f', 'i', 'l', 'e', '3',	/* entry 3 name */
		46, 0, 0, 0,			/* entry 3 stype */
		47, 0, 0, 0,			/* entry 3 ttype */
		48, 0, 0, 0,			/* entry 3 tclass */
		53, 0, 0, 0,			/* entry 3 otype */
	};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_FILENAME_TRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	struct avtab_key key;
	struct avtab_datum *node;
	u32 *otype;

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	KUNIT_ASSERT_EQ(test, 0, avtab_alloc(&p.te_avtab, 3));

	KUNIT_ASSERT_EQ(test, 0,
			avtab_filename_trans_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 2, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);

	key = (struct avtab_key){42, 43, 44, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 0, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 1, node->u.trans->name_trans.table.nel);

	otype = symtab_search(&node->u.trans->name_trans, "file1");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 45, *otype);

	key = (struct avtab_key){46, 47, 48, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 0, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 2, node->u.trans->name_trans.table.nel);

	otype = symtab_search(&node->u.trans->name_trans, "file2");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 49, *otype);

	otype = symtab_search(&node->u.trans->name_trans, "file3");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 53, *otype);

	avtab_destroy(&p.te_avtab);
}

static void filename_trans_read__comp_simple(struct kunit *test)
{
	char data[] = {
		3, 0, 0, 0,	/* count */

		5, 0, 0, 0,			/* entry 1 name len */
		'f', 'i', 'l', 'e', '1',	/* entry 1 name */
		43, 0, 0, 0,			/* entry 1 ttype */
		44, 0, 0, 0,			/* entry 1 tclass */
		1, 0, 0, 0,			/* entry 1 ndatum */
		64, 0, 0, 0,			/* entry 1 datum 1 stypes */
		64, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 2, 0, 0,
		45, 0, 0, 0,			/* entry 1 otype */

		5, 0, 0, 0,			/* entry 2 name len */
		'f', 'i', 'l', 'e', '2',	/* entry 2 name */
		47, 0, 0, 0,			/* entry 2 ttype */
		48, 0, 0, 0,			/* entry 2 tclass */
		1, 0, 0, 0,			/* entry 2 ndatum */
		64, 0, 0, 0,			/* entry 2 datum 1 stypes */
		64, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 32, 0, 0,
		49, 0, 0, 0,			/* entry 2 otype */

		5, 0, 0, 0,			/* entry 3 name len */
		'f', 'i', 'l', 'e', '3',	/* entry 3 name */
		47, 0, 0, 0,			/* entry 3 ttype */
		48, 0, 0, 0,			/* entry 3 tclass */
		1, 0, 0, 0,			/* entry 2 ndatum */
		64, 0, 0, 0,			/* entry 2 datum 1 stypes */
		64, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 32, 0, 0,
		53, 0, 0, 0,			/* entry 3 otype */
	};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_COMP_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	struct avtab_key key;
	struct avtab_datum *node;
	u32 *otype;

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	KUNIT_ASSERT_EQ(test, 0, avtab_alloc(&p.te_avtab, 3));

	KUNIT_ASSERT_EQ(test, 0,
			avtab_filename_trans_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 2, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);

	key = (struct avtab_key){42, 43, 44, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 0, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 1, node->u.trans->name_trans.table.nel);

	otype = symtab_search(&node->u.trans->name_trans, "file1");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 45, *otype);

	key = (struct avtab_key){46, 47, 48, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 0, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 2, node->u.trans->name_trans.table.nel);

	otype = symtab_search(&node->u.trans->name_trans, "file2");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 49, *otype);

	otype = symtab_search(&node->u.trans->name_trans, "file3");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 53, *otype);

	avtab_destroy(&p.te_avtab);
}

static void filename_trans_write__pre_filename_trans(struct kunit *test)
{
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_FILENAME_TRANS - 1,
	};
	struct policy_file fp = {
		.data = NULL,
		.len = 0,
	};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;

	KUNIT_EXPECT_EQ(test, 0,
			avtab_filename_trans_write(&p, &p.te_avtab, &fp));
	KUNIT_EXPECT_EQ(test, 0, fp.len);
}

static void filename_trans_write__empty(struct kunit *test)
{
	char expected_data[] = {0, 0, 0, 0};
	char data[sizeof(expected_data)] = {0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_FILENAME_TRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;

	KUNIT_ASSERT_EQ(test, 0,
			avtab_filename_trans_write(&p, &p.te_avtab, &fp));

	KUNIT_EXPECT_EQ(test, 0, fp.len);
	KUNIT_EXPECT_TRUE(test,
			  !memcmp(expected_data, data, sizeof(expected_data)));
}

static void filename_trans_write__comp_empty(struct kunit *test)
{
	char expected_data[] = {0, 0, 0, 0};
	char data[sizeof(expected_data)] = {0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_COMP_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;

	KUNIT_ASSERT_EQ(test, 0,
			avtab_filename_trans_write(&p, &p.te_avtab, &fp));

	KUNIT_EXPECT_EQ(test, 0, fp.len);
	KUNIT_EXPECT_TRUE(test,
			  !memcmp(expected_data, data, sizeof(expected_data)));
}

static void filename_trans_write__simple(struct kunit *test)
{
	char expected_data[] = {
		3, 0, 0, 0,	/* count */

		5, 0, 0, 0,			/* entry 1 name len */
		'f', 'i', 'l', 'e', '1',	/* entry 1 name */
		42, 0, 0, 0,			/* entry 1 stype */
		43, 0, 0, 0,			/* entry 1 ttype */
		44, 0, 0, 0,			/* entry 1 tclass */
		45, 0, 0, 0,			/* entry 1 otype */

		5, 0, 0, 0,			/* entry 2 name len */
		'f', 'i', 'l', 'e', '2',	/* entry 2 name */
		46, 0, 0, 0,			/* entry 2 stype */
		47, 0, 0, 0,			/* entry 2 ttype */
		48, 0, 0, 0,			/* entry 2 tclass */
		49, 0, 0, 0,			/* entry 2 otype */

		5, 0, 0, 0,			/* entry 3 name len */
		'f', 'i', 'l', 'e', '3',	/* entry 3 name */
		46, 0, 0, 0,			/* entry 3 stype */
		47, 0, 0, 0,			/* entry 3 ttype */
		48, 0, 0, 0,			/* entry 3 tclass */
		53, 0, 0, 0,			/* entry 3 otype */
	};
	char data[sizeof(expected_data)] = {0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_FILENAME_TRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	u32 otypes[] = {45, 49, 53};
	struct hashtab_node nhnodes[] = {
		{"file1", &otypes[0], NULL},
		{"file2", &otypes[1], &nhnodes[2]},
		{"file3", &otypes[2], NULL},
	};
	struct hashtab_node *nhtable[] = {&nhnodes[0], &nhnodes[1]};
	struct avtab_trans transs[] = {
		{0, {{&nhtable[0], 1, 1}, 0}},
		{0, {{&nhtable[1], 1, 2}, 0}},
	};
	struct avtab_node nodes[] = {
		{{42, 43, 44, AVTAB_TRANSITION},
			{.u.trans = &transs[0]}, NULL},
		{{46, 47, 48, AVTAB_TRANSITION},
			{.u.trans = &transs[1]}, NULL},
	};
	struct avtab_node *htable[] = {&nodes[0], &nodes[1]};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	p.te_avtab.htable = htable;
	p.te_avtab.nslot = 2;
	p.te_avtab.nel = 2;

	KUNIT_ASSERT_EQ(test, 0,
			avtab_filename_trans_write(&p, &p.te_avtab, &fp));

	KUNIT_ASSERT_EQ(test, 0, fp.len);
	KUNIT_EXPECT_TRUE(test,
			  !memcmp(expected_data, data, sizeof(expected_data)));
}

static void filename_trans_write__comp_simple(struct kunit *test)
{
	char expected_data[] = {
		3, 0, 0, 0,	/* count */

		5, 0, 0, 0,			/* entry 1 name len */
		'f', 'i', 'l', 'e', '1',	/* entry 1 name */
		43, 0, 0, 0,			/* entry 1 ttype */
		44, 0, 0, 0,			/* entry 1 tclass */
		1, 0, 0, 0,			/* entry 1 ndatum */
		64, 0, 0, 0,			/* entry 1 datum 1 stypes */
		64, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 2, 0, 0,
		45, 0, 0, 0,			/* entry 1 otype */

		5, 0, 0, 0,			/* entry 2 name len */
		'f', 'i', 'l', 'e', '2',	/* entry 2 name */
		47, 0, 0, 0,			/* entry 2 ttype */
		48, 0, 0, 0,			/* entry 2 tclass */
		1, 0, 0, 0,			/* entry 2 ndatum */
		64, 0, 0, 0,			/* entry 2 datum 1 stypes */
		64, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 32, 0, 0,
		49, 0, 0, 0,			/* entry 2 otype */

		5, 0, 0, 0,			/* entry 3 name len */
		'f', 'i', 'l', 'e', '3',	/* entry 3 name */
		47, 0, 0, 0,			/* entry 3 ttype */
		48, 0, 0, 0,			/* entry 3 tclass */
		1, 0, 0, 0,			/* entry 2 ndatum */
		64, 0, 0, 0,			/* entry 2 datum 1 stypes */
		64, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0, 0, 32, 0, 0,
		53, 0, 0, 0,			/* entry 3 otype */
	};
	char data[sizeof(expected_data)] = {0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_COMP_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	u32 otypes[] = {45, 49, 53};
	struct hashtab_node nhnodes[] = {
		{"file1", &otypes[0], NULL},
		{"file2", &otypes[1], &nhnodes[2]},
		{"file3", &otypes[2], NULL},
	};
	struct hashtab_node *nhtable[] = {&nhnodes[0], &nhnodes[1]};
	struct avtab_trans transs[] = {
		{0, {{&nhtable[0], 1, 1}, 0}},
		{0, {{&nhtable[1], 1, 2}, 0}},
	};
	struct avtab_node nodes[] = {
		{{42, 43, 44, AVTAB_TRANSITION},
			{.u.trans = &transs[0]}, NULL},
		{{46, 47, 48, AVTAB_TRANSITION},
			{.u.trans = &transs[1]}, NULL},
	};
	struct avtab_node *htable[] = {&nodes[0], &nodes[1]};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	p.te_avtab.htable = htable;
	p.te_avtab.nslot = 2;
	p.te_avtab.nel = 2;

	KUNIT_ASSERT_EQ(test, 0,
			avtab_filename_trans_write(&p, &p.te_avtab, &fp));

	KUNIT_ASSERT_EQ(test, 0, fp.len);
	KUNIT_EXPECT_TRUE(test,
			  !memcmp(expected_data, data, sizeof(expected_data)));
}

static void read__pre_avtab_ftrans(struct kunit *test)
{
	char data[] = {
		2, 0, 0, 0,	/* nel */

		42, 0,			/* entry 1 source type */
		43, 0,			/* entry 1 target type */
		44, 0,			/* entry 1 target class */
		AVTAB_TRANSITION, 0,	/* entry 1 specified */
		45, 0, 0, 0,		/* entry 1 otype */

		46, 0,			/* entry 2 source type */
		47, 0,			/* entry 2 target type */
		48, 0,			/* entry 2 target class */
		AVTAB_TRANSITION, 0,	/* entry 2 specified */
		49, 0, 0, 0,		/* entry 2 otype */
	};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_COMP_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	struct avtab_key key;
	struct avtab_datum *node;

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	KUNIT_ASSERT_EQ(test, 0,
			avtab_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 2, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);

	key = (struct avtab_key){42, 43, 44, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 45, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 0, node->u.trans->name_trans.table.nel);

	key = (struct avtab_key){46, 47, 48, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 49, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 0, node->u.trans->name_trans.table.nel);

	avtab_destroy(&p.te_avtab);
}

static void read__simple(struct kunit *test)
{
	char data[] = {
		2, 0, 0, 0,	/* nel */

		42, 0,			/* entry 1 source type */
		43, 0,			/* entry 1 target type */
		44, 0,			/* entry 1 target class */
		AVTAB_TRANSITION, 0,	/* entry 1 specified */
		41, 0, 0, 0,		/* entry 1 otype */
		1, 0, 0, 0,		/* entry 1 nfnts */
		45, 0, 0, 0,			/* entry 1 fnt 1 otype */
		5, 0, 0, 0,			/* entry 1 fnt 1 name len */
		'f', 'i', 'l', 'e', '1',	/* entry 1 fnt 1 name */

		46, 0,			/* entry 2 source type */
		47, 0,			/* entry 2 target type */
		48, 0,			/* entry 2 target class */
		AVTAB_TRANSITION, 0,	/* entry 2 specified */
		40, 0, 0, 0,		/* entry 2 otype */
		2, 0, 0, 0,		/* entry 2 nfnts */
		49, 0, 0, 0,			/* entry 2 fnt 1 otype */
		5, 0, 0, 0,			/* entry 2 fnt 1 name len */
		'f', 'i', 'l', 'e', '2',	/* entry 2 fnt 1 name */
		50, 0, 0, 0,			/* entry 2 fnt 2 otype */
		5, 0, 0, 0,			/* entry 2 fnt 2 name len */
		'f', 'i', 'l', 'e', '3',	/* entry 2 fnt 2 name */
	};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_AVTAB_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	struct avtab_key key;
	struct avtab_datum *node;
	u32 *otype;

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	KUNIT_ASSERT_EQ(test, 0,
			avtab_read(&p.te_avtab, &fp, &p));
	KUNIT_EXPECT_EQ(test, 2, p.te_avtab.nel);
	KUNIT_EXPECT_EQ(test, 0, fp.len);

	key = (struct avtab_key){42, 43, 44, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 41, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 1, node->u.trans->name_trans.table.nel);

	otype = symtab_search(&node->u.trans->name_trans, "file1");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 45, *otype);

	key = (struct avtab_key){46, 47, 48, AVTAB_TRANSITION};
	node = avtab_search(&p.te_avtab, &key);
	KUNIT_ASSERT_NOT_NULL(test, node);
	KUNIT_EXPECT_EQ(test, 40, node->u.trans->otype);
	KUNIT_EXPECT_EQ(test, 2, node->u.trans->name_trans.table.nel);

	otype = symtab_search(&node->u.trans->name_trans, "file2");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 49, *otype);

	otype = symtab_search(&node->u.trans->name_trans, "file3");
	KUNIT_ASSERT_NOT_NULL(test, otype);
	KUNIT_EXPECT_EQ(test, 50, *otype);

	avtab_destroy(&p.te_avtab);
}

static void write__pre_avtab_ftrans(struct kunit *test)
{
	char expected_data[] = {
		1, 0, 0, 0,	/* nel */

		46, 0,			/* entry 2 source type */
		47, 0,			/* entry 2 target type */
		48, 0,			/* entry 2 target class */
		AVTAB_TRANSITION, 0,	/* entry 2 specified */
		40, 0, 0, 0,		/* entry 2 otype */
	};
	char data[sizeof(expected_data)] = {0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_COMP_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	u32 otypes[] = {45, 49, 53};
	struct hashtab_node nhnodes[] = {
		{"file1", &otypes[0], NULL},
		{"file2", &otypes[1], &nhnodes[2]},
		{"file3", &otypes[2], NULL},
	};
	struct hashtab_node *nhtable[] = {&nhnodes[0], &nhnodes[1]};
	struct avtab_trans transs[] = {
		{0, {{&nhtable[0], 1, 1}, 0}},
		{40, {{&nhtable[1], 1, 2}, 0}},
	};
	struct avtab_node nodes[] = {
		{{42, 43, 44, AVTAB_TRANSITION},
			{.u.trans = &transs[0]}, NULL},
		{{46, 47, 48, AVTAB_TRANSITION},
			{.u.trans = &transs[1]}, NULL},
	};
	struct avtab_node *htable[] = {&nodes[0], &nodes[1]};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	p.te_avtab.htable = htable;
	p.te_avtab.nslot = 2;
	p.te_avtab.nel = 2;

	KUNIT_ASSERT_EQ(test, 0, avtab_write(&p, &p.te_avtab, &fp));

	KUNIT_ASSERT_EQ(test, 0, fp.len);
	KUNIT_EXPECT_TRUE(test,
			  !memcmp(expected_data, data, sizeof(expected_data)));
}

static void write__simple(struct kunit *test)
{
	char expected_data[] = {
		2, 0, 0, 0,	/* nel */

		42, 0,			/* entry 1 source type */
		43, 0,			/* entry 1 target type */
		44, 0,			/* entry 1 target class */
		AVTAB_TRANSITION, 0,	/* entry 1 specified */
		41, 0, 0, 0,		/* entry 1 otype */
		1, 0, 0, 0,		/* entry 1 nfnts */
		45, 0, 0, 0,			/* entry 1 fnt 1 otype */
		5, 0, 0, 0,			/* entry 1 fnt 1 name len */
		'f', 'i', 'l', 'e', '1',	/* entry 1 fnt 1 name */

		46, 0,			/* entry 2 source type */
		47, 0,			/* entry 2 target type */
		48, 0,			/* entry 2 target class */
		AVTAB_TRANSITION, 0,	/* entry 2 specified */
		40, 0, 0, 0,		/* entry 2 otype */
		2, 0, 0, 0,		/* entry 2 nfnts */
		49, 0, 0, 0,			/* entry 1 fnt 1 otype */
		5, 0, 0, 0,			/* entry 1 fnt 1 name len */
		'f', 'i', 'l', 'e', '2',	/* entry 1 fnt 1 name */
		50, 0, 0, 0,			/* entry 1 fnt 1 otype */
		5, 0, 0, 0,			/* entry 1 fnt 1 name len */
		'f', 'i', 'l', 'e', '3',	/* entry 1 fnt 1 name */
	};
	char data[sizeof(expected_data)] = {0};
	struct policydb p = {
		.te_avtab = {0},
		.policyvers = POLICYDB_VERSION_AVTAB_FTRANS,
	};
	struct policy_file fp = {
		.data = data,
		.len = sizeof(data),
	};
	u32 otypes[] = {45, 49, 50};
	struct hashtab_node nhnodes[] = {
		{"file1", &otypes[0], NULL},
		{"file2", &otypes[1], &nhnodes[2]},
		{"file3", &otypes[2], NULL},
	};
	struct hashtab_node *nhtable[] = {&nhnodes[0], &nhnodes[1]};
	struct avtab_trans transs[] = {
		{41, {{&nhtable[0], 1, 1}, 0}},
		{40, {{&nhtable[1], 1, 2}, 0}},
	};
	struct avtab_node nodes[] = {
		{{42, 43, 44, AVTAB_TRANSITION},
			{.u.trans = &transs[0]}, NULL},
		{{46, 47, 48, AVTAB_TRANSITION},
			{.u.trans = &transs[1]}, NULL},
	};
	struct avtab_node *htable[] = {&nodes[0], &nodes[1]};

	p.p_types.nprim = 54;
	p.p_classes.nprim = 49;
	p.te_avtab.htable = htable;
	p.te_avtab.nslot = 2;
	p.te_avtab.nel = 2;

	KUNIT_ASSERT_EQ(test, 0, avtab_write(&p, &p.te_avtab, &fp));

	KUNIT_ASSERT_EQ(test, 0, fp.len);
	KUNIT_EXPECT_TRUE(test,
			  !memcmp(expected_data, data, sizeof(expected_data)));
}

static struct kunit_case avtab_test_cases[] = {
	KUNIT_CASE(filename_trans_read__pre_filename_trans),
	KUNIT_CASE(filename_trans_read__empty),
	KUNIT_CASE(filename_trans_read__comp_empty),
	KUNIT_CASE(filename_trans_read__simple),
	KUNIT_CASE(filename_trans_read__comp_simple),

	KUNIT_CASE(filename_trans_write__pre_filename_trans),
	KUNIT_CASE(filename_trans_write__empty),
	KUNIT_CASE(filename_trans_write__comp_empty),
	KUNIT_CASE(filename_trans_write__simple),
	KUNIT_CASE(filename_trans_write__comp_simple),

	KUNIT_CASE(read__pre_avtab_ftrans),
	KUNIT_CASE(read__simple),

	KUNIT_CASE(write__pre_avtab_ftrans),
	KUNIT_CASE(write__simple),
	{0},
};

static struct kunit_suite avtab_test_suite = {
	.name = "security-selinux-avtab",
	.test_cases = avtab_test_cases,
};

kunit_test_suite(avtab_test_suite);

MODULE_LICENSE("GPL");
