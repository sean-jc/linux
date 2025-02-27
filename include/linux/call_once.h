#ifndef _LINUX_CALL_ONCE_H
#define _LINUX_CALL_ONCE_H

#include <linux/types.h>
#include <linux/mutex.h>

#define ONCE_NOT_STARTED 0
#define ONCE_RUNNING     1
#define ONCE_COMPLETED   2

struct once {
	atomic_t state;
	struct mutex lock;
};

static inline void __once_init(struct once *once, const char *name,
			       struct lock_class_key *key)
{
	atomic_set(&once->state, ONCE_NOT_STARTED);
	__mutex_init(&once->lock, name, key);
}

#define once_init(once)							\
do {									\
	static struct lock_class_key __key;				\
	__once_init((once), #once, &__key);				\
} while (0)

static inline int call_once(struct once *once, int (*cb)(struct once *))
{
	int r, state;

	/* Pairs with atomic_set_release() below.  */
	if (atomic_read_acquire(&once->state) == ONCE_COMPLETED)
		return 0;

	guard(mutex)(&once->lock);
	state = atomic_read(&once->state);
	if (unlikely(state != ONCE_NOT_STARTED))
		return WARN_ON_ONCE(state != ONCE_COMPLETED) ? -EINVAL : 0;

	atomic_set(&once->state, ONCE_RUNNING);
	r = cb(once);
	if (r)
		atomic_set(&once->state, ONCE_NOT_STARTED);
	else
		atomic_set_release(&once->state, ONCE_COMPLETED);
	return r;
}

#endif /* _LINUX_CALL_ONCE_H */
