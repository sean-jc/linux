#define pr_fmt(fmt) "ushrink: " fmt

#include <linux/eventfd.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/shrinker.h>
#include <linux/swap.h>
#include <linux/ushrink.h>
#include <linux/xarray.h>

MODULE_DESCRIPTION("Userspace Shrinker Notifier");
MODULE_LICENSE("GPL");

DEFINE_STATIC_SRCU(ushrink_srcu);
static DEFINE_MUTEX(ushrink_lock);
static DEFINE_XARRAY(ushrink_notifiers);

struct ushrink {
	struct xarray registered_notifiers;
};

struct ushrink_notifier {
	struct mm_struct *mm;
	struct mem_cgroup *memcg;
	struct ushrink_notification __user *n;
	struct eventfd_ctx *eventfd;
	struct list_head list;
};

static struct shrinker *ushrink_shrinker;

static unsigned long ushrink_count(struct shrinker *shrink,
				   struct shrink_control *sc)
{
	struct list_head *notifier_list;

	guard(rcu)();

	notifier_list = xa_load(&ushrink_notifiers, (unsigned long)sc->memcg);
	if (!notifier_list || list_empty(notifier_list))
		return 0;

	return SWAP_CLUSTER_MAX;
}

static unsigned long ushrink_scan(struct shrinker *shrink,
				  struct shrink_control *sc)
{
	struct list_head *notifier_list;
	struct ushrink_notifier *n;
	int r;

	if (!sc->memcg)
		return 0;

	sc->priority = 0xbeef;

	guard(srcu)(&ushrink_srcu);

	notifier_list = xa_load(&ushrink_notifiers, (unsigned long)sc->memcg);
	if (!notifier_list || list_empty(notifier_list))
		return 0;

	list_for_each_entry_rcu(n, notifier_list, list) {
		if (!mmget_not_zero(n->mm))
			continue;

		r = access_remote_vm(n->mm, (unsigned long)&n->n->priority,
				     &sc->priority, sizeof(sc->priority), FOLL_WRITE);
		mmput(n->mm);

		if (r != sizeof(sc->priority))
			continue;

		smp_wmb();
		eventfd_signal(n->eventfd);
	}

	return SHRINK_STOP;
}

static long ushrink_register(struct ushrink *ushrink,
			     struct ushrink_register *reg)
{
	struct ushrink_notification __user *notification;
	struct list_head *notifier_list;
	struct eventfd_ctx *eventfd;
	struct ushrink_notifier *n;
	int err;

	notification = u64_to_user_ptr(reg->notification);
	if (!access_ok(notification, sizeof(*notification)))
		return -EINVAL;

	guard(mutex)(&ushrink_lock);

	eventfd = eventfd_ctx_fdget(reg->eventfd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	if (xa_load(&ushrink->registered_notifiers, (unsigned long)eventfd)) {
		err = -EEXIST;
		goto err_notifier;
	}

	n = kzalloc(sizeof(*n), GFP_KERNEL_ACCOUNT);
	if (!n) {
		err = -ENOMEM;
		goto err_notifier;
	}

	n->eventfd = eventfd;
	n->n = notification;

	mmgrab(current->mm);
	n->mm = current->mm;
	n->memcg = get_mem_cgroup_from_mm(n->mm);


	notifier_list = xa_load(&ushrink_notifiers, (unsigned long)n->memcg);
	if (!notifier_list) {
		notifier_list = kzalloc(sizeof(*notifier_list), GFP_KERNEL);
		INIT_LIST_HEAD(notifier_list);

		err = xa_insert(&ushrink_notifiers, (unsigned long)n->memcg,
				notifier_list, GFP_KERNEL);
		if (err) {
			kfree(notifier_list);
			goto err_xarray;
		}
	}

	/*
	 * Note!  Don't delete from the global xarray on failure, even if the
	 * entry was just allocated.  Dangling entries will be cleaned up when
	 * the last relevant ushrink file is released.
	 */
	err = xa_insert(&ushrink->registered_notifiers, (unsigned long)eventfd,
			n, GFP_KERNEL_ACCOUNT);
	if (err)
		goto err_xarray;

	list_add_rcu(&n->list, notifier_list);
	mutex_unlock(&ushrink_lock);

	return 0;

err_xarray:
	kfree(n);
err_notifier:
	eventfd_ctx_put(eventfd);
	return err;
}

static void __ushrink_unregister(struct ushrink *ushrink,
				 struct ushrink_notifier *n)
{
	lockdep_assert_held(&ushrink_lock);

	list_del_rcu(&n->list);
	synchronize_srcu(&ushrink_srcu);

	xa_erase(&ushrink->registered_notifiers, (unsigned long)n->eventfd);
	eventfd_ctx_put(n->eventfd);
	mem_cgroup_put(n->memcg);
	mmdrop(n->mm);

	kfree(n);
}

static long ushrink_unregister(struct ushrink *ushrink,
			       struct ushrink_register *reg)
{
	struct eventfd_ctx *eventfd;
	struct ushrink_notifier *n;

	eventfd = eventfd_ctx_fdget(reg->eventfd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	guard(mutex)(&ushrink_lock);

	n = xa_load(&ushrink->registered_notifiers, (unsigned long)eventfd);
	if (!n)
		goto err;

	if (WARN_ON_ONCE(n->eventfd != eventfd))
		goto err;

	__ushrink_unregister(ushrink, n);
	return 0;

err:
	eventfd_ctx_put(eventfd);
	return -ENOENT;
}

static long ushrink_ioctl(struct file *file, unsigned int ioctl,
			  unsigned long arg)
{
	struct ushrink_register reg;

	switch (ioctl) {
	case USHRINK_REGISTER:
	case USHRINK_UNREGISTER:
		if (copy_from_user(&reg, (void __user *)arg, sizeof(reg)))
			return -EFAULT;

		if (ioctl == USHRINK_REGISTER)
			return ushrink_register(file->private_data, &reg);

		return ushrink_unregister(file->private_data, &reg);
	default:
		return -ENOTTY;
	}
}

static int ushrink_open(struct inode *inode, struct file *file)
{
	struct ushrink *ushrink;

	ushrink = kzalloc(sizeof(*ushrink), GFP_KERNEL_ACCOUNT);
	if (!ushrink)
		return -ENOMEM;

	xa_init(&ushrink->registered_notifiers);

	file->private_data = ushrink;
	return 0;
}

static int ushrink_release(struct inode *inode, struct file *file)
{
	struct ushrink *ushrink = file->private_data;
	struct ushrink_notifier *n;
	unsigned long index;

	mutex_lock(&ushrink_lock);
	xa_for_each(&ushrink->registered_notifiers, index, n)
		__ushrink_unregister(ushrink, n);
	mutex_unlock(&ushrink_lock);

	xa_destroy(&ushrink->registered_notifiers);
	return 0;
}

static const struct file_operations ushrink_fops = {
	.owner		= THIS_MODULE,
	.open		= ushrink_open,
	.release	= ushrink_release,
	.unlocked_ioctl = ushrink_ioctl,
	.llseek		= noop_llseek,

};

static struct miscdevice ushrink_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "ushrink",
	.fops		= &ushrink_fops,
};


static int __init ushrink_init(void)
{
	int r;

	xa_init(&ushrink_notifiers);

	ushrink_shrinker = shrinker_alloc(SHRINKER_MEMCG_AWARE | SHRINKER_NONSLAB,
					  "user-shrinker");
	if (!ushrink_shrinker)
		return -ENOMEM;

	ushrink_shrinker->count_objects	= ushrink_count;
	ushrink_shrinker->scan_objects	= ushrink_scan;
	ushrink_shrinker->seeks		= 0; /* No seeking necessary */
	ushrink_shrinker->batch		= 1; /* Scan once per reclaim attempt */

	shrinker_register(ushrink_shrinker);

	r = misc_register(&ushrink_misc);
	if (r)
		shrinker_free(ushrink_shrinker);
	return r;
}
module_init(ushrink_init);

static void __exit ushrink_exit(void)
{
	misc_deregister(&ushrink_misc);

	shrinker_free(ushrink_shrinker);

	xa_destroy(&ushrink_notifiers);
}
module_exit(ushrink_exit);
