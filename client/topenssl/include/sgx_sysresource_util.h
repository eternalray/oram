#ifndef SGX_SYSRESOURCE_UTIL_H
#define SGX_SYSRESOURCE_UTIL_H

#include <proxy/sgx_sysresource_t.h>

static inline int sgx_wrapper_prlimit (__pid_t pid, enum __rlimit_resource resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
	int retval;
	ocall_prlimit(&retval, pid, resource, new_limit, old_limit);
	return retval;
}

#define prlimit(A, B, C, D) sgx_wrapper_prlimit(A, B, C, D)

#endif