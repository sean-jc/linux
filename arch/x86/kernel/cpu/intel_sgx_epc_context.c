// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Sean Christopherson <sean.j.christopherson@intel.com>
#include <asm/sgx.h>
#include <uapi/asm/sgx.h>

#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/radix-tree.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>

static struct sgx_epc_page_ops sgx_va_ops;

#define SGX_VA_MAX_TREE_DEPTH	4
#define SGX_VA_SLOTS_PER_PAGE	512

struct sgx_epc_context {
	struct file *swap;
	struct file *pcmd;
	struct list_head va_leafs;
	struct list_head full_va_leafs;
	struct radix_tree_root va_tree;
	struct sgx_va_page *current_va_page[SGX_VA_MAX_TREE_DEPTH];
	pgoff_t swap_base[SGX_VA_MAX_TREE_DEPTH - 1];
	unsigned long max_va_leafs;
	unsigned long nr_va_leafs;
	unsigned long nr_avl_slots;
	int root_level;
};

struct sgx_va_page {
	union {
		struct sgx_epc_page *epc_page;
		struct sgx_va_page *va_page;
	};
	u64 __data;

	struct sgx_epc_page_impl impl;
};

enum sgx_va_page_data {
	SGX_VA_PAGE_PRESENT		= BIT(0),
	SGX_VA_PAGE_INSERTED		= BIT(1),
	SGX_VA_PAGE_ACCESSED		= BIT(2),
	SGX_VA_PAGE_PINNED		= BIT(3),

	SGX_VA_PAGE_LEVEL_SHIFT		= 9,
	SGX_VA_PAGE_LEVEL_MASK		= GENMASK_ULL(11, 9),

	/*
	 * Starting at bit 12 with a 9-bit shift (512 slots per page),
	 * we can go 4 levels deep and pack everything into a single
	 * 64-bit value.  This allows for a ~256TB EPC size.  We need
	 * to track the number of allocated slots since we don't do
	 * per-slot tracking on nodes, and we also want to track the
	 * number of evicted slots/children so that we don't thrash.
	 * The used and eviction counts consume the last two slots.
	 */
	SGX_VA_PAGE_L0_SLOT_SHIFT	= 12,
	SGX_VA_PAGE_L0_SLOT_MASK	= GENMASK_ULL(20, 12),
	SGX_VA_PAGE_L1_SLOT_SHIFT	= 21,
	SGX_VA_PAGE_L1_SLOT_MASK	= GENMASK_ULL(29, 21),
	SGX_VA_PAGE_L2_SLOT_SHIFT	= 30,
	SGX_VA_PAGE_L2_SLOT_MASK	= GENMASK_ULL(38, 30),
	SGX_VA_PAGE_L3_SLOT_SHIFT	= 39,
	SGX_VA_PAGE_L3_SLOT_MASK	= GENMASK_ULL(47, 39),
	SGX_VA_PAGE_ALL_SLOTS_SHIFT	= 12,
	SGX_VA_PAGE_ALL_SLOTS_MASK	= GENMASK_ULL(47, 12),

	SGX_VA_PAGE_RADIX_INDEX_SHIFT	= 9,
	SGX_VA_PAGE_RADIX_INDEX_MASK	= GENMASK_ULL(47, 9),

	SGX_VA_PAGE_NUM_USED_SHIFT	= 48,
	SGX_VA_PAGE_NUM_USED_MASK	= GENMASK_ULL(56, 48),

	SGX_VA_PAGE_NUM_EVICTED_SHIFT	= 57,
	SGX_VA_PAGE_NUM_EVICTED_MASK	= GENMASK_ULL(63, 57),
};

struct sgx_va_leaf {
	struct sgx_va_page page;

	struct list_head list;

	DECLARE_BITMAP(slots, SGX_VA_SLOTS_PER_PAGE);
};

#define BUILD_VA_PAGE_FLAG(...) \
	BUILD_SGX_PAGE_FLAG(sgx_va, SGX_VA, __VA_ARGS__)

#define BUILD_VA_PAGE_VAL(type, ...) \
	BUILD_SGX_PAGE_VAL(type, sgx_va, SGX_VA, __VA_ARGS__)

#define BUILD_VA_PAGE_COUNT_VAL(type, ...) \
	BUILD_SGX_PAGE_COUNT_VAL(type, sgx_va, SGX_VA, __VA_ARGS__)

BUILD_VA_PAGE_FLAG(present, PRESENT, data)
BUILD_VA_PAGE_FLAG(inserted, INSERTED, data)
BUILD_VA_PAGE_FLAG(accessed, ACCESSED, data)
BUILD_VA_PAGE_FLAG(pinned, PINNED, data)

BUILD_VA_PAGE_VAL(int, level, LEVEL, data)
BUILD_VA_PAGE_VAL(u64, radix_index, RADIX_INDEX, data)

BUILD_VA_PAGE_COUNT_VAL(unsigned int, num_used, NUM_USED, data)
BUILD_VA_PAGE_COUNT_VAL(unsigned int, num_evicted, NUM_EVICTED, data)

static __always_inline unsigned int sgx_va_page_slot_shift(int level)
{
	switch (level) {
	case 0: return SGX_VA_PAGE_L0_SLOT_SHIFT;
	case 1: return SGX_VA_PAGE_L1_SLOT_SHIFT;
	case 2: return SGX_VA_PAGE_L2_SLOT_SHIFT;
	case 3: return SGX_VA_PAGE_L3_SLOT_SHIFT;
	}
	BUG();
}

static __always_inline u64 sgx_va_page_slot_mask(int level)
{
	switch (level) {
	case 0: return SGX_VA_PAGE_L0_SLOT_MASK;
	case 1: return SGX_VA_PAGE_L1_SLOT_MASK;
	case 2: return SGX_VA_PAGE_L2_SLOT_MASK;
	case 3: return SGX_VA_PAGE_L3_SLOT_MASK;
	}
	BUG();
}

static __always_inline
unsigned int __sgx_va_page_slot(struct sgx_va_page *page, int level)
{
	return (page->__data & sgx_va_page_slot_mask(level)) >>
		sgx_va_page_slot_shift(level);
}

static __always_inline unsigned int sgx_va_page_slot(struct sgx_va_page *page)
{
	int level = sgx_va_page_level(page);
	return __sgx_va_page_slot(page, level);
}

static pgoff_t sgx_va_page_swap_index(struct sgx_epc_context *epc,
				      struct sgx_va_page *page)
{
	pgoff_t offset, offset_multiplier;
	int level, i;

	level = sgx_va_page_level(page);
	offset = __sgx_va_page_slot(page, level);

	offset_multiplier = PAGE_SIZE;
	for (i = 1; (i + level) < epc->root_level; i++) {
		offset += __sgx_va_page_slot(page, i) * offset_multiplier;
		offset_multiplier *= PAGE_SIZE;
	}

	return epc->swap_base[level] + offset;
}

static struct sgx_epc_page *__sgx_swap_va_page(struct sgx_epc_context *epc,
					       struct sgx_va_page *page)
{
	struct sgx_epc_page *epc_page, *tmp;
	struct sgx_va_page *parent;
	struct sgx_va_leaf *leaf;
	unsigned int slot, evicted;
	u64 parent_index;
	int r, level;

	slot = sgx_va_page_slot(page);
	level = sgx_va_page_level(page);

	parent_index = page->__data & SGX_VA_PAGE_ALL_SLOTS_MASK;
	parent_index &= ~sgx_va_page_slot_mask(level);
	parent_index &= ~SGX_VA_PAGE_LEVEL_MASK;
	parent_index |= (level + 1) << SGX_VA_PAGE_LEVEL_SHIFT;
	parent_index >>= SGX_VA_PAGE_RADIX_INDEX_SHIFT;

	/*
	 * Check current_va_page to see if it's our parent.  This is both
	 * a small optimization and a functional necessity since we allow
	 * lazy insertion into the radix tree, i.e. we keep a page even
	 * if insertion fails by ensuring its pointed at by current_va_page
	 * until said page is successfully inserted into the tree.
	 */
	parent = epc->current_va_page[level + 1];
	if (sgx_va_page_radix_index(parent) != parent_index)
		parent = radix_tree_lookup(&epc->va_tree, parent_index);
	BUG_ON(!parent || !sgx_va_page_present(parent));

	epc_page = page->epc_page;

	r = sgx_ewb(epc_page, parent->epc_page, slot << 3, epc->swap,
		    epc->pcmd, sgx_va_page_swap_index(epc, page), NULL);
	if (WARN_ON(r))
		return ERR_PTR(r);

	sgx_va_page_clear_present(page);
	page->va_page = parent;

	evicted = sgx_va_page_inc_num_evicted(parent) + 1;
	if ((level + 1) < epc->root_level && evicted == SGX_VA_SLOTS_PER_PAGE) {
		tmp = __sgx_swap_va_page(epc, parent);
		if (!IS_ERR(tmp))
			sgx_free_page(tmp);
	}

	if (level == 0) {
		leaf = container_of(page, struct sgx_va_leaf, page);
		list_del_init(&leaf->list);
	}
	return epc_page;
}

static struct sgx_epc_page *sgx_swap_va_page(struct sgx_epc_context *epc)
{
	struct sgx_va_leaf *leaf, *accessed = NULL;

	list_for_each_entry(leaf, &epc->full_va_leafs, list) {
		if (sgx_va_page_pinned(&leaf->page))
			continue;

		if (sgx_va_page_accessed(&leaf->page)) {
			sgx_va_page_clear_accessed(&leaf->page);
			accessed = accessed ? : leaf;
			continue;
		}

		return __sgx_swap_va_page(epc, &leaf->page);
	}
	if (accessed)
		return __sgx_swap_va_page(epc, &accessed->page);

	list_for_each_entry(leaf, &epc->full_va_leafs, list)
		return __sgx_swap_va_page(epc, &leaf->page);

	return ERR_PTR(-ENOMEM);
}

static void sgx_swap_va_pages(struct sgx_epc_context *epc)
{
	struct sgx_va_leaf *leaf, *tmp;
	struct sgx_epc_page *epc_page;

	list_for_each_entry_safe(leaf, tmp, &epc->full_va_leafs, list) {
		if (sgx_va_page_pinned(&leaf->page))
			continue;

		if (sgx_va_page_accessed(&leaf->page)) {
			sgx_va_page_clear_accessed(&leaf->page);
			continue;
		}

		epc_page = __sgx_swap_va_page(epc, &leaf->page);
		if (IS_ERR(epc_page))
			break;
		sgx_free_page(epc_page);
	}
}

static inline u64 sgx_va_page_calc_radix_index(struct sgx_va_page *parent,
					       int level)
{
	unsigned int slot;
	u64 index;

	BUILD_BUG_ON(SGX_VA_PAGE_LEVEL_SHIFT != SGX_VA_PAGE_RADIX_INDEX_SHIFT);

	if (!parent)
		return level;

	slot = sgx_va_page_inc_num_used(parent);
	BUG_ON(slot >= SGX_VA_SLOTS_PER_PAGE);

	BUG_ON((level + 1) != sgx_va_page_level(parent));
	index = parent->__data & SGX_VA_PAGE_ALL_SLOTS_MASK;

	BUG_ON(index & sgx_va_page_slot_mask(level));
	index |= slot << sgx_va_page_slot_shift(level);
	index |= level << SGX_VA_PAGE_LEVEL_SHIFT;
	index >>= SGX_VA_PAGE_RADIX_INDEX_SHIFT;

	return index;
}

static struct sgx_va_page *sgx_alloc_va_node(struct sgx_epc_context *epc,
					     int level, unsigned int flags,
					     bool prefetch);

static int sgx_init_va_page(struct sgx_epc_context *epc,
			    struct sgx_va_page *page, int level,
			    unsigned int flags, bool prefetch)
{
	struct sgx_va_page *parent = NULL;
	struct sgx_epc_page *epc_page;
	u64 index;
	int ret;

	if (level < epc->root_level) {
		parent = sgx_alloc_va_node(epc, level + 1, flags, prefetch);
		if (IS_ERR(parent))
			return PTR_ERR(parent);
	}

	page->impl.ops = &sgx_va_ops;
	epc_page = sgx_alloc_page(&page->impl, flags);
	if (IS_ERR(epc_page)) {
		if (prefetch)
			return PTR_ERR(epc_page);

		epc_page = sgx_swap_va_page(epc);
		if (IS_ERR(epc_page))
			return PTR_ERR(epc_page);
	}

	ret = sgx_epa(epc_page);
	if (WARN_ON(ret)) {
		sgx_free_page(epc_page);
		return ret;
	}

	index = sgx_va_page_calc_radix_index(parent, level);
	sgx_va_page_set_radix_index(page, index);

	/*
	 * Radix Tree insertion failure is only fatal for leafs,
	 * i.e. level 0.  For nodes we can use the cache to keep
	 * tabs on the un-inserted node and delay reporting any
	 * errors.
	 */
	ret = radix_tree_insert(&epc->va_tree, index, page);
	if (!ret) {
		sgx_va_page_set_inserted(page);
	} else if (level == 0) {
		sgx_free_page(epc_page);
		return ret;
	}
	sgx_va_page_set_level(page, level);
	sgx_va_page_set_present(page);
	page->epc_page = epc_page;

	return 0;
}

static struct sgx_va_page *sgx_alloc_va_node(struct sgx_epc_context *epc,
					     int level, unsigned int flags,
					     bool prefetch)
{
	struct sgx_va_page *page;
	unsigned int used;
	u64 index;
	int ret;

	page = epc->current_va_page[level];
	if (likely(page)) {
		used = sgx_va_page_num_used(page);

		/*
		 * Re-attempt insertion if it failed before.  Don't allow a
		 * new node to be allocated until we have inserted into the
		 * tree, we need to keep the page in current_va_page so that
		 * its children can be evicted.
		 */
		if (unlikely(!sgx_va_page_inserted(page))) {
			index = sgx_va_page_radix_index(page);
			ret = radix_tree_insert(&epc->va_tree, index, page);
			if (!ret)
				sgx_va_page_set_inserted(page);
			else if (used >= SGX_VA_SLOTS_PER_PAGE)
				return ERR_PTR(ret);
		}

		if (likely(used < SGX_VA_SLOTS_PER_PAGE))
			return page;
	}

	page = kzalloc(sizeof(struct sgx_va_page), GFP_KERNEL);
	if (!page)
		return ERR_PTR(-ENOMEM);

	ret = sgx_init_va_page(epc, page, level, flags, prefetch);
	if (ret)
		return ERR_PTR(ret);

	epc->current_va_page[level] = page;

	return page;
}

static struct sgx_va_leaf *sgx_alloc_va_leaf(struct sgx_epc_context *epc,
					     unsigned int flags, bool prefetch)
{
	struct sgx_va_leaf *leaf;
	int ret;

	if (WARN_ON(epc->nr_va_leafs == epc->max_va_leafs))
		return ERR_PTR(-ENOMEM);

	leaf = kzalloc(sizeof(struct sgx_va_leaf), GFP_KERNEL);
	if (!leaf)
		return ERR_PTR(-ENOMEM);

	ret = sgx_init_va_page(epc, &leaf->page, 0, flags, prefetch);
	if (ret) {
		kfree(leaf);
		return ERR_PTR(ret);
	}

	epc->nr_va_leafs++;
	epc->nr_avl_slots += SGX_VA_SLOTS_PER_PAGE;
	list_add_tail(&leaf->list, &epc->va_leafs);
	return leaf;
}

static struct sgx_epc_page *__sgx_load_va_page(struct sgx_epc_context *epc,
					       struct sgx_va_page *page)
{
	struct sgx_epc_page *epc_page;
	struct sgx_va_leaf *leaf;
	struct sgx_va_page *parent;
	pgoff_t swap_index;
	unsigned int slot;
	int ret;

	sgx_va_page_set_accessed(page);

	if (sgx_va_page_present(page))
		return page->epc_page;

	epc_page = __sgx_load_va_page(epc, page->va_page);
	if (IS_ERR(epc_page))
		return epc_page;

	epc_page = sgx_alloc_page(&page->impl, SGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page))
		return epc_page;

	slot = sgx_va_page_slot(page);
	swap_index = sgx_va_page_swap_index(epc, page);

	parent = page->va_page;

	ret = sgx_eld(epc_page, parent->epc_page, slot << 3, NULL,
		      epc->swap, epc->pcmd, swap_index, 0, __eldu);
	if (WARN(ret, "sgx: EDLU returned: %d", ret)) {
		sgx_free_page(epc_page);
		return ERR_PTR(ENCLS_TO_ERR(ret));
	}

	sgx_va_page_dec_num_evicted(parent);
	sgx_va_page_set_present(page);
	page->epc_page = epc_page;

	if (sgx_va_page_level(page) == 0) {
		leaf = container_of(page, struct sgx_va_leaf, page);
		list_add_tail(&leaf->list, &epc->full_va_leafs);
	}
	return page->epc_page;
}

struct sgx_epc_page *sgx_load_va_page(struct sgx_epc_context *epc,
				      struct sgx_va_page *page)
{
	struct sgx_epc_page *epc_page;

	epc_page = __sgx_load_va_page(epc, page);
	if (!IS_ERR(epc_page))
		sgx_va_page_set_pinned(page);
	return epc_page;
}
EXPORT_SYMBOL(sgx_load_va_page);

struct sgx_va_page *sgx_alloc_va_entry(struct sgx_epc_context *epc,
				       struct sgx_epc_page **epc_page,
				       unsigned int *offset)
{
	struct sgx_va_leaf *leaf;
	unsigned int slot, nr_used;

	if (unlikely(list_empty(&epc->va_leafs))) {
		leaf = sgx_alloc_va_leaf(epc, SGX_ALLOC_ATOMIC, false);
		if (IS_ERR(leaf))
			return (void *)leaf;
		slot = 0;
	} else {
		leaf = list_first_entry(&epc->va_leafs,
					struct sgx_va_leaf, list);
		slot = find_first_zero_bit(leaf->slots, SGX_VA_SLOTS_PER_PAGE);
		BUG_ON(slot >= SGX_VA_SLOTS_PER_PAGE);
	}

	set_bit(slot, leaf->slots);

	nr_used = sgx_va_page_inc_num_used(&leaf->page) + 1;
	if (nr_used == SGX_VA_SLOTS_PER_PAGE)
		list_move_tail(&leaf->list, &epc->full_va_leafs);

	if (--epc->nr_avl_slots < SGX_VA_SLOTS_PER_PAGE) {
		if (!atomic_read(&sgx_nr_free_pages))
			sgx_swap_va_pages(epc);

		if (epc->nr_va_leafs < epc->max_va_leafs)
			sgx_alloc_va_leaf(epc, SGX_ALLOC_ATOMIC, true);
	}

	*offset = slot << 3;
	*epc_page = leaf->page.epc_page;
	return &leaf->page;
}
EXPORT_SYMBOL(sgx_alloc_va_entry);

void sgx_free_va_entry(struct sgx_epc_context *epc, struct sgx_va_page *page,
		       unsigned int offset)
{
	struct sgx_va_leaf *leaf;

	epc->nr_avl_slots++;

	sgx_va_page_clear_pinned(page);
	sgx_va_page_dec_num_used(page);

	leaf = container_of(page, struct sgx_va_leaf, page);
	clear_bit(offset >> 3, leaf->slots);
	list_move(&leaf->list, &epc->va_leafs);
}
EXPORT_SYMBOL(sgx_free_va_entry);

struct sgx_epc_context *sgx_alloc_epc_context(unsigned long ctxt_size)
{
	unsigned long ctxt_pages, swap_size, nr_pages, nr_slots;
	struct sgx_va_leaf *leaf;
	struct sgx_epc_context *epc;
	struct file *swap, *pcmd;
	int i;

	epc = kzalloc(sizeof(*epc), GFP_KERNEL);
	if (!epc)
		return ERR_PTR(-ENOMEM);

	ctxt_pages = DIV_ROUND_UP(ctxt_size, PAGE_SIZE);
	nr_slots = SGX_VA_SLOTS_PER_PAGE;
	swap_size = 0;

	for (i = 0; i < (SGX_VA_MAX_TREE_DEPTH - 1); i++) {
		nr_pages = DIV_ROUND_UP(ctxt_pages, nr_slots);
		if (i == 0)
			epc->max_va_leafs = nr_pages;
		if (nr_pages == 1)
			break;

		epc->swap_base[i] = swap_size;
		swap_size += DIV_ROUND_UP(ctxt_size, nr_slots);
		nr_slots *= SGX_VA_SLOTS_PER_PAGE;
	}
	epc->root_level = i;

	swap = shmem_file_setup("sgx va swap", swap_size, VM_NORESERVE);
	if (IS_ERR(swap)) {
		kfree(epc);
		return (void *)swap;
	}

	pcmd = shmem_file_setup("sgx va pcmd", swap_size >> 5, VM_NORESERVE);
	if (IS_ERR(pcmd)) {
		kfree(epc);
		fput(swap);
		return (void *)pcmd;
	}

	INIT_LIST_HEAD(&epc->va_leafs);
	INIT_LIST_HEAD(&epc->full_va_leafs);
	INIT_RADIX_TREE(&epc->va_tree, GFP_KERNEL);
	epc->swap = swap;
	epc->pcmd = pcmd;

	leaf = sgx_alloc_va_leaf(epc, 0, false);
	if (IS_ERR(leaf)) {
		sgx_free_epc_context(epc);
		return ERR_PTR(PTR_ERR(leaf));
	}
	return epc;
}
EXPORT_SYMBOL(sgx_alloc_epc_context);

void sgx_free_epc_context(struct sgx_epc_context *epc)
{
	struct radix_tree_iter iter;
	struct sgx_va_page *page;
	struct sgx_va_leaf *leaf;
	void **slot;
	int i;

	for (i = 0; i < ARRAY_SIZE(epc->current_va_page); i++) {
		page = epc->current_va_page[i];
		if (!page || sgx_va_page_inserted(page))
			continue;

		if (sgx_va_page_present(page))
			WARN_ON(sgx_free_page(page->epc_page));
		kfree(page);
	}

	radix_tree_for_each_slot(slot, &epc->va_tree, &iter, 0) {
		page = *slot;
		if (sgx_va_page_present(page))
			WARN_ON(sgx_free_page(page->epc_page));

		if (sgx_va_page_level(page) == 0) {
			leaf = container_of(page, struct sgx_va_leaf, page);
			kfree(leaf);
		} else {
			kfree(page);
		}

		radix_tree_delete(&epc->va_tree, iter.index);
	}

	fput(epc->swap);
	fput(epc->pcmd);
	kfree(epc);
}
EXPORT_SYMBOL(sgx_free_epc_context);
