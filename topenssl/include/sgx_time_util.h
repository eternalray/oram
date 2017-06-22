#ifndef SGX_TIME_UTIL_H
#define SGX_TIME_UTIL_H

#include "struct/sgx_time_struct.h"
#include "proxy/sgx_time_t.h"

static inline time_t sgx_wrapper_time(time_t * tim)
{
	time_t retval;
	ocall_time(&retval, tim);
	return retval;
}

static inline int sgx_wrapper_gettimeofday(void * tv, void * tz)
{
	int retval;
	ocall_gettimeofday(&retval, tv, tz);
	return retval;
}

static inline struct tm *sgx_wrapper_gmtime_r(const time_t *timer, struct tm *tp)
{
	struct tm * retval;
	ocall_gmtime_r(&retval, timer, tp);
	return retval;
}

static inline struct tm *sgx_wrapper_localtime_r(const time_t *timer, struct tm *tp)
{
	struct tm * retval;
	ocall_localtime_r(&retval, timer, tp);
	return retval;
}

static inline time_t sgx_wrapper_mktime(struct tm *tp)	
{
	time_t retval;
	ocall_mktime(&retval, tp);
	return retval;
}


#define time(A) sgx_wrapper_time(A)
#define gettimeofday(A, B) sgx_wrapper_gettimeofday(A, B)
#define gmtime_r(A, B) sgx_wrapper_gmtime_r(A, B)
#define localtime_r(A, B) sgx_wrapper_localtime_r(A, B)
#define mktime(A) sgx_wrapper_mktime(A)

#endif
