#ifndef SGX_PWD_UTIL_H
#define SGX_PWD_UTIL_H

#include <struct/sgx_pwd_struct.h>
#include <proxy/sgx_pwd_t.h>

static inline struct passwd *sgx_wrapper_getpwuid(uid_t uid)
{
	struct passwd *retval;
	ocall_getpwuid(&retval, uid);
	return retval;
}

static inline struct passwd *sgx_wrapper_getpwnam(const char *name)
{
	struct passwd *retval;
	ocall_getpwnam(&retval, name);
	return retval;
}

#define getpwuid(A) sgx_wrapper_getpwuid(A)
#define getpwnam(A) sgx_wrapper_getpwnam(A)

#endif 