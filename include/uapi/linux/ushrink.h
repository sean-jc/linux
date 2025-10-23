/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_USHRINK_H
#define __LINUX_USHRINK_H

#include <linux/const.h>
#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/ioctl.h>

struct ushrink_notification {
	__u32 priority;
	__u32 pad[1];
	__u64 reserved[7];
};

struct ushrink_register {
	__u32 eventfd;
	__u32 pad[1];
	__u64 notification;
	__u64 reserved[6];
};

#define USHRINK_MAGIC 'u'

#define USHRINK_REGISTER	_IOW(USHRINK_MAGIC, 0, struct ushrink_register)
#define USHRINK_UNREGISTER	_IOW(USHRINK_MAGIC, 1, struct ushrink_register)

#endif /* __LINUX_USHRINK_H */
