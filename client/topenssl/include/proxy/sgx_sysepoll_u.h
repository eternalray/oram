#ifndef SGX_SYSEPOLL_U_H__
#define SGX_SYSEPOLL_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "struct/sgx_sysepoll_struct.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_create, (int __size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_create1, (int __flags));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_ctl, (int __epfd, int __op, int __fd, struct epoll_event* __event));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_wait, (int __epfd, struct epoll_event* __events, int __maxevents, int __timeout));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_epoll_pwait, (int __epfd, struct epoll_event* __events, int __maxevents, int __timeout, const __sigset_t* __ss));


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
