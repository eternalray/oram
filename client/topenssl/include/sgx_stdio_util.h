#ifndef SGX_STDIO_UTIL_H
#define SGX_STDIO_UTIL_H

#include "struct/sgx_stdio_struct.h"
#include "proxy/sgx_stdio_t.h"

static inline SGX_WRAPPER_FILE sgx_wrapper_fopen(const char* filename, const char* mode)	
{
	SGX_WRAPPER_FILE f = 0;
	ocall_fopen(&f, filename, mode);
	return f;
}

static inline SGX_WRAPPER_FILE sgx_wrapper_fdopen(int fd, const char* mode)	
{
	SGX_WRAPPER_FILE f = 0;
	ocall_fdopen(&f, fd, mode);
	return f;
}

static inline int sgx_wrapper_fileno(SGX_WRAPPER_FILE stream)
{
    int retval;
    ocall_fileno(&retval, stream);    
    return retval;
}

static inline int sgx_wrapper_fclose(SGX_WRAPPER_FILE file)	
{
	int ret = 0;
	ocall_fclose(&ret, file);
	return ret;
}
static inline int sgx_wrapper_fputs(const char* str, SGX_WRAPPER_FILE file)	
{
	int ret = 0;
	ocall_fputs(&ret, str, file);
	return ret;
}
static inline char* sgx_wrapper_fgets(char* str, int num, SGX_WRAPPER_FILE FILESTREAM)
{
	char* ret;
	ocall_fgets(&ret, str, num, FILESTREAM);
	return ret;
}
static inline int sgx_wrapper_feof(SGX_WRAPPER_FILE file)	
{
	int ret = 0;
	ocall_feof(&ret, file);
	return ret;
}
static inline size_t sgx_wrapper_fread(void* ptr, size_t size, size_t nmemb, SGX_WRAPPER_FILE FILESTREAM)
{
	size_t ret; 
	ocall_fread(&ret, ptr, size, nmemb, FILESTREAM);
	return ret;
}
static inline size_t sgx_wrapper_fwrite(const void* ptr, size_t size, size_t count, SGX_WRAPPER_FILE FILESTREAM)
{
	size_t ret;
	ocall_fwrite(&ret, ptr, size, count, FILESTREAM);
	return ret;
}
static inline int sgx_wrapper_fseeko(SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence)
{
	int ret;
	ocall_fseeko(&ret, FILESTREAM, offset, whence);
	return ret;
}
static inline off_t sgx_wrapper_ftello(SGX_WRAPPER_FILE FILESTREAM)
{
	off_t ret;
	ocall_ftello(&ret, FILESTREAM);
	return ret;
}
static inline int sgx_wrapper_fseek(SGX_WRAPPER_FILE FILESTREAM, off_t offset, int whence)
{
	int ret;
	ocall_fseek(&ret, FILESTREAM, offset, whence);
	return ret;
}
static inline off_t sgx_wrapper_ftell(SGX_WRAPPER_FILE FILESTREAM)
{
	off_t ret;
	ocall_ftell(&ret, FILESTREAM);
	return ret;
}
static inline int sgx_wrapper_ferror(SGX_WRAPPER_FILE FILESTREAM)
{
	int ret;
	ocall_ferror(&ret, FILESTREAM);
	return ret;
}
static inline int sgx_wrapper_fflush(SGX_WRAPPER_FILE FILESTREAM)
{
	int ret;
	ocall_fflush(&ret, FILESTREAM);
	return ret;
}
static inline int sgx_wrapper_vfprintf(SGX_WRAPPER_FILE FILESTREAM, const char* format, void* val)
{
	int ret;
	ocall_vfprintf(&ret, FILESTREAM, format, val);
	return ret;
}
static inline int sgx_wrapper_vprintf(const char* format, void* val)
{
	int ret;
	ocall_vprintf(&ret, format, val);
	return ret;
}
static inline int sgx_wrapper_vsprintf(char* string, const char* format, void* val)
{
	int ret;
	ocall_vsprintf(&ret, string, format, val);
	return ret;
}
static inline int sgx_wrapper_vasprintf(char** string, const char* format, void* val)
{
	int ret;
	ocall_vasprintf(&ret, string, format, val);
	return ret;
}
static inline int sgx_wrapper_getc(SGX_WRAPPER_FILE FILESTREAM)
{
	int ret;
	ocall_getc(&ret, FILESTREAM);
	return ret;
}

static inline int sgx_wrapper_getchar()
{
	return sgx_wrapper_getc(SGX_STDIN);
}


static inline int sgx_wrapper_vfscanf(SGX_WRAPPER_FILE FILESTREAM, const char *format, void* ap)
{
	int retval;
    ocall_vfscanf(&retval, FILESTREAM, format, ap);
	return retval;
}

static inline int sgx_wrapper_vscanf(const char *format, void* ap)
{
	int retval;
    ocall_vscanf(&retval, format, ap);
	return retval;
}

static inline int sgx_wrapper_vsscanf(const char* s, const char *format, void* ap)
{
	int retval;
    ocall_vsscanf(&retval, s, format, ap);
	return retval;
}

static inline int sgx_wrapper_putchar(int c)
{
	int retval;
    ocall_putchar(&retval, c);
	return retval;
}

static inline int sgx_wrapper_putc(int c, SGX_WRAPPER_FILE FILESTREAM)
{
	int retval; 
    ocall_putc(&retval, c, FILESTREAM);
	return retval;
}

// #define fprintf(A, B, ...) ocall_fprintf(A, B, ##__VA_ARGS__)
static inline int sgx_wrapper_scanf(const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vscanf(&ret, format, &ap);
    va_end(ap);
    return result;
}

static inline int sgx_wrapper_fscanf(SGX_WRAPPER_FILE FILESTREAM, const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vfscanf(&ret, FILESTREAM, format, &ap);
    va_end(ap);
    return result;
}

static inline int sgx_wrapper_sscanf(const char* s, const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vsscanf(&ret, s, format, &ap);
    va_end(ap);
    return result;
}

static inline int sgx_wrapper_fprintf(int FILESTREAM, const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vfprintf(&ret, FILESTREAM, format, &ap);
    va_end(ap);
    return result;
}

static inline int sgx_wrapper_printf(const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vprintf(&ret, format, &ap);
    va_end(ap);
    return result;
}

static inline int sgx_wrapper_sprintf(char* string, const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vsprintf(&ret, string, format, &ap);
    va_end(ap);
    return result;
}

static inline int sgx_wrapper_asprintf(char** string, const char* format, ...)	
{
	int result = 0;
	va_list ap;
	va_start(ap, format);
	int ret;
	result += ret;
    ocall_vasprintf(&ret, string, format, &ap);
    va_end(ap);
    return result;
}

#define stdin SGX_STDIN
#define stdout SGX_STDOUT 
#define stderr SGX_STDERR

#define printf(A, ...) sgx_wrapper_printf(A, ##__VA_ARGS__)
#define fprintf(A, B, ...) sgx_wrapper_fprintf(A, B, ##__VA_ARGS__)
#define sprintf(A, B, ...) sgx_wrapper_sprintf(A, B, ##__VA_ARGS__)
#define asprintf(A, B, ...) sgx_wrapper_asprintf(A, B, ##__VA_ARGS__)
#define funlockfile(A) sgx_wrapper_funlockfile(A)
#define flockfile(A) sgx_wrapper_flockfile(A)
#define rewind(A) sgx_wrapper_rewind(A)
#define sgx_wrapper_rewind(A) ocall_rewind(A)
#define fopen(A, B) sgx_wrapper_fopen(A, B)
#define fdopen(A, B) sgx_wrapper_fdopen(A, B)
#define fileno(A) sgx_wrapper_fileno(A)
#define fclose(A) sgx_wrapper_fclose(A)
#define fputs(A, B) sgx_wrapper_fputs(A, B)
#define fgets(A, B, C) sgx_wrapper_fgets(A, B, C)	
#define feof(A) sgx_wrapper_feof(A)
#define fread(A, B, C, D) sgx_wrapper_fread(A, B, C, D)
#define fwrite(A, B, C, D) sgx_wrapper_fwrite(A, B, C, D)
#define fseeko(A, B, C) sgx_wrapper_fseeko(A, B, C)
#define ftello(A) sgx_wrapper_ftello(A)
#define fseek(A, B, C) sgx_wrapper_fseek(A, B, C)
#define ftell(A) sgx_wrapper_ftell(A)
#define ferror(A) sgx_wrapper_ferror(A)
#define fflush(A) sgx_wrapper_fflush(A)
#define vfprinff(A, B, C) sgx_wrapper_vfprintf(A, B, C)
#define vprintf(A, B) sgx_wrapper_vprintf(A, B)
#define vsprintf(A, B, C) sgx_wrapper_vsprintf(A, B, C)
#define vasprintf(A, B, C) sgx_wrapper_vasprintf(A, B, C)
#define getc(A) sgx_wrapper_getc(A)
#define getchar() sgx_wrapper_getchar()
#define vscanf(A, B) sgx_wrapper_vscanf(A, B)
#define vfscanf(A, B, C) sgx_wrapper_vscanf(A, B, C)
#define vsscanf(A, B, C) sgx_wrapper_vscanf(A, B, C)
#define putchar(A) sgx_wrapper_putchar(A)
#define putc(A, B) sgx_wrapper_putc(A, B)
#define scanf(A, ...) sgx_wrapper_scanf(A, ##__VA_ARGS__)
#define fscanf(A, B, ...) sgx_wrapper_fscanf(A, B, ##__VA_ARGS__)
#define sscanf(A, B, ...) sgx_wrapper_sscanf(A, B, ##__VA_ARGS__)

#endif

