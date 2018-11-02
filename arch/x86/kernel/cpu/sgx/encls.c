#include <asm/cpufeature.h>
#include <asm/traps.h>
#include "encls.h"
#include "sgx.h"

/**
 * encls_failed() - Check if an ENCLS leaf function failed
 * @ret:	the return value of an ENCLS leaf function call
 *
 * Check if an ENCLS leaf function failed. This is a condition where the leaf
 * function causes a fault that is not caused by an EPCM conflict.
 *
 * Return: true if there was a fault other than an EPCM conflict
 */
bool encls_failed(int ret)
{
	int epcm_trapnr = boot_cpu_has(X86_FEATURE_SGX2) ?
			  X86_TRAP_PF : X86_TRAP_GP;

	return encls_faulted(ret) && ENCLS_TRAPNR(ret) != epcm_trapnr;
}
EXPORT_SYMBOL_GPL(encls_failed);
