#include "client_enclave_t.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/aes.h"
// #include "openssl/sha.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/sha.h>

void sample(){
  unsigned char asdf[] = "asdf";
  unsigned char key;
  RAND_bytes(&key, 32);
  ocall_print_string(asdf,4);

  ocall_print_string(&key, 32);
}
