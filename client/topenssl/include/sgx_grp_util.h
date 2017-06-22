#ifndef SGX_GRP_UTIL_H
#define SGX_GRP_UTIL_H

#include <struct/sgx_grp_struct.h>
#include <proxy/sgx_grp_t.h>

static inline struct group *sgx_wrapper_getgrgid(gid_t gid)
{
	struct group *retval;
	ocall_getgrgid(&retval, gid);
	return retval;
}

static inline struct group *sgx_wrapper_getgrnam(const char *name)
{
	struct group *retval;
	ocall_getgrnam(&retval, name);
	return retval;
}

#define getgrgid(A) sgx_wrapper_getgrgid(A)
#define getgrnam(A) sgx_wrapper_getgrnam(A)

#endif