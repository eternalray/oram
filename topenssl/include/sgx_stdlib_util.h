#ifndef SGX_STDLIB_UTIL_H
#define SGX_STDLIB_UTIL_H

#include <proxy/sgx_stdlib_t.h>
#include <sgx_trts.h>
#include <stdlib.h>
#include <sgx_stdio_util.h>

static inline char *sgx_wrapper_getenv(const char *name)
{
	char* retval;
	ocall_getenv(&retval, name);
	return retval;
}

static inline int sgx_wrapper_putenv(char *string)
{
	int retval;
	ocall_putenv(&retval, string);
	return retval;
}

static inline int sgx_wrapper_clearenv(void)
{
	int retval;
	ocall_clearenv(&retval);
	return retval;
}

static inline void sgx_wrapper_exit(int status)
{
	fprintf(stderr, "Dummy exit call with status : %d\n", status);
} 


static inline int sgx_wrapper_setenv(const char *name, const char *value, int replace)
{
	int retval;
	ocall_setenv(&retval, name, value, replace);
	return retval;
}

static inline int sgx_wrapper_unsetenv (const char *name)
{
	int retval;
	ocall_unsetenv(&retval, name);
	return retval;
}

static inline int sgx_wrapper_random()
{
	int ran;
	sgx_read_rand((unsigned char*)&ran, sizeof(int));
	return ran;
} 

static inline void sgx_wrapper_srandom (unsigned int seed)
{
	fprintf(stdout, "Dummy srandom call \n");
}

#define getenv(A) sgx_wrapper_getenv(A)
#define putenv(A) sgx_wrapper_putenv(A)
#define clearenv() sgx_wrapper_clearenv()
#define exit(A) sgx_wrapper_exit(A)
#define random() sgx_wrapper_random()
#define rand() sgx_wrapper_random()
#define srandom(A) sgx_wrapper_srandom(A)
#define setenv(A, B, C) sgx_wrapper_setenv(A, B, C)
#define unsetenv(A) sgx_wrapper_unsetenv(A)

#endif 