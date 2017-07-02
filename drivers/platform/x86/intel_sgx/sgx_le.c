// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
// Copyright(c) 2016-17 Intel Corporation.
//
// Authors:
//
// Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>

#include <asm/sgx_le.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kmod.h>
#include <linux/mutex.h>
#include <linux/sched/signal.h>
#include <linux/shmem_fs.h>
#include <linux/wait.h>
#include "sgx.h"

struct sgx_le_ctx {
	struct pid *tgid;
	char *argv[2];
	struct crypto_shash *tfm;
	struct mutex hash_lock;
	struct mutex launch_lock;
	struct rw_semaphore users;
	wait_queue_head_t wq;
	bool kernel_read;
	bool user_read;
	struct file *pipe;
	struct sgx_launch_request req;
	struct sgx_einittoken token;
};

struct sgx_le_ctx sgx_le_ctx;

static int __sgx_get_key_hash(struct crypto_shash *tfm, const void *modulus,
			      void *hash)
{
	SHASH_DESC_ON_STACK(shash, tfm);

	shash->tfm = tfm;
	shash->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	return crypto_shash_digest(shash, modulus, SGX_MODULUS_SIZE, hash);
}

/**
 * sgx_get_key_hash - calculate SHA256 for a given RSA key
 * @modulus:	modulus of the key
 * @hash:	the resulting hash
 */
int sgx_get_key_hash(const void *modulus, void *hash)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = __sgx_get_key_hash(tfm, modulus, hash);

	crypto_free_shash(tfm);
	return ret;
}

static ssize_t sgx_le_ctx_fops_read(struct file *filp, char __user *buf,
				    size_t count, loff_t *off)
{
	struct sgx_le_ctx *ctx = filp->private_data;
	int ret;

	if (count != sizeof(ctx->req)) {
		pr_crit("%s: invalid count %lu\n", __func__, count);
		return -EIO;
	}

	ret = wait_event_interruptible(ctx->wq, ctx->user_read);
	if (ret)
		return -EINTR;

	ret = copy_to_user(buf, &ctx->req, count);
	ctx->user_read = false;

	return ret ? ret : count;
}

static ssize_t sgx_le_ctx_fops_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t *off)
{
	struct sgx_le_ctx *ctx = filp->private_data;
	int ret;

	if (count != sizeof(ctx->token)) {
		pr_crit("%s: invalid count %lu\n", __func__, count);
		return -EIO;
	}

	ret = copy_from_user(&ctx->token, buf, count);
	if (!ret)
		ctx->kernel_read = true;
	wake_up_interruptible(&ctx->wq);

	return ret ? ret : count;
}

static const struct file_operations sgx_le_ctx_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.read = sgx_le_ctx_fops_read,
	.write = sgx_le_ctx_fops_write,
};

static int sgx_le_task_init(struct subprocess_info *subinfo, struct cred *new)
{
	struct sgx_le_ctx *ctx = (struct sgx_le_ctx *)subinfo->data;
	struct file *tmp_filp;
	unsigned long len;
	loff_t pos = 0;
	int ret;

	len = (unsigned long)&sgx_le_proxy_end - (unsigned long)&sgx_le_proxy;

	tmp_filp = shmem_file_setup("[sgx_le_proxy]", len, 0);
	if (IS_ERR(tmp_filp)) {
		ret = PTR_ERR(tmp_filp);
		return ret;
	}
	fd_install(SGX_LE_EXE_FD, tmp_filp);

	ret = kernel_write(tmp_filp, &sgx_le_proxy, len, &pos);
	if (ret != len && ret >= 0)
		return -ENOMEM;
	if (ret < 0)
		return ret;

	tmp_filp = anon_inode_getfile("[/dev/sgx]", &sgx_fops, NULL, O_RDWR);
	if (IS_ERR(tmp_filp))
		return PTR_ERR(tmp_filp);
	fd_install(SGX_LE_DEV_FD, tmp_filp);

	tmp_filp = anon_inode_getfile("[sgx_le]", &sgx_le_ctx_fops, ctx,
				      O_RDWR);
	if (IS_ERR(tmp_filp))
		return PTR_ERR(tmp_filp);
	fd_install(SGX_LE_PIPE_FD, tmp_filp);

	ctx->tgid = get_pid(task_tgid(current));
	ctx->pipe = tmp_filp;

	return 0;
}

static void __sgx_le_stop(struct sgx_le_ctx *ctx)
{
	if (ctx->tgid) {
		fput(ctx->pipe);
		kill_pid(ctx->tgid, SIGKILL, 1);
		put_pid(ctx->tgid);
		ctx->tgid = NULL;
	}
}

void sgx_le_stop(struct sgx_le_ctx *ctx, bool update_users)
{
	if (update_users) {
		up_read(&ctx->users);
		if (!down_write_trylock(&ctx->users))
			return;
	}

	mutex_lock(&ctx->launch_lock);
	__sgx_le_stop(ctx);
	mutex_unlock(&ctx->launch_lock);

	if (update_users)
		up_write(&ctx->users);
}

static int __sgx_le_start(struct sgx_le_ctx *ctx)
{
	struct subprocess_info *subinfo;
	int ret;

	if (ctx->tgid)
		return 0;

	ctx->argv[0] = SGX_LE_EXE_PATH;
	ctx->argv[1] = NULL;

	subinfo = call_usermodehelper_setup(ctx->argv[0], ctx->argv,
					    NULL, GFP_KERNEL, sgx_le_task_init,
					    NULL, &sgx_le_ctx);
	if (!subinfo)
		return -ENOMEM;

	ret = call_usermodehelper_exec(subinfo, UMH_WAIT_EXEC);
	if (ret) {
		__sgx_le_stop(ctx);
		return ret;
	}

	return 0;
}

int sgx_le_start(struct sgx_le_ctx *ctx)
{
	int ret;

	down_read(&ctx->users);

	mutex_lock(&ctx->launch_lock);
	ret = __sgx_le_start(ctx);
	mutex_unlock(&ctx->launch_lock);

	if (ret)
		up_read(&ctx->users);

	return ret;
}

int sgx_le_init(struct sgx_le_ctx *ctx)
{
	struct crypto_shash *tfm;

	tfm = crypto_alloc_shash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ctx->tfm = tfm;
	mutex_init(&ctx->hash_lock);
	mutex_init(&ctx->launch_lock);
	init_rwsem(&ctx->users);
	init_waitqueue_head(&ctx->wq);

	return 0;
}

void sgx_le_exit(struct sgx_le_ctx *ctx)
{
	mutex_lock(&ctx->launch_lock);
	crypto_free_shash(ctx->tfm);
	mutex_unlock(&ctx->launch_lock);
}

static int __sgx_le_get_token(struct sgx_le_ctx *ctx,
			      const struct sgx_encl *encl,
			      struct sgx_einittoken *token)
{
	ssize_t ret;

	if (!ctx->tgid)
		return -EIO;

	ctx->user_read = true;
	wake_up_interruptible(&ctx->wq);

	ret = wait_event_interruptible(ctx->wq, ctx->kernel_read);
	if (ret)
		return -EINTR;

	memcpy(token, &ctx->token, sizeof(*token));
	ctx->kernel_read = false;

	return 0;
}

int sgx_le_get_token(struct sgx_le_ctx *ctx,
		     const struct sgx_encl *encl,
		     const struct sgx_sigstruct *sigstruct,
		     struct sgx_einittoken *token)
{
	u8 mrsigner[32];
	int ret;

	mutex_lock(&ctx->hash_lock);
	ret = __sgx_get_key_hash(ctx->tfm, sigstruct->modulus, mrsigner);
	if (ret) {
		mutex_unlock(&ctx->hash_lock);
		return ret;
	}
	if (!memcmp(mrsigner, sgx_le_pubkeyhash, 32)) {
		token->payload.valid = false;
		mutex_unlock(&ctx->hash_lock);
		return 0;
	}
	mutex_unlock(&ctx->hash_lock);

	mutex_lock(&ctx->launch_lock);
	ret = __sgx_le_start(ctx);
	if (ret) {
		mutex_unlock(&ctx->launch_lock);
		return ret;
	}
	memcpy(&ctx->req.mrenclave, sigstruct->body.mrenclave, 32);
	memcpy(&ctx->req.mrsigner, mrsigner, 32);
	ctx->req.attributes = encl->attributes;
	ctx->req.xfrm = encl->xfrm;
	memset(&ctx->token, 0, sizeof(ctx->token));
	ret = __sgx_le_get_token(ctx, encl, token);
	mutex_unlock(&ctx->launch_lock);
	return ret;
}
