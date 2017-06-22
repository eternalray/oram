#include <iostream>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"
#include "client_enclave_u.h"
#include "message.h"
#include "service_provider.h"

#define PORT 8080

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

using namespace std;

const string ENCLAVE_NAME = "enclave.signed.so";
const string ENCLAVE_TOKEN = "enclave.token";

sgx_enclave_id_t global_eid = 0;

void PRINT_BYTE_ARRAY(
    FILE *file, void *mem, uint32_t len)
{
    if(!mem || !len)
    {
        fprintf(file, "\n( null )\n");
        return;
    }
    uint8_t *array = (uint8_t *)mem;
    fprintf(file, "%u bytes:\n{\n", len);
    uint32_t i = 0;
    for(i = 0; i < len - 1; i++)
    {
        fprintf(file, "0x%x, ", array[i]);
        if(i % 8 == 7) fprintf(file, "\n");
    }
    fprintf(file, "0x%x ", array[i]);
    fprintf(file, "\n}\n");
}

void print_error_message(sgx_status_t ret){
  cout << "SGX error code : " << ret << endl;
}

int initializeEnclave(){
  cout << "initializing enclave..." << endl;

  const char* token_path = ENCLAVE_TOKEN.c_str();
  sgx_launch_token_t token = {0};
  size_t token_size = sizeof(sgx_launch_token_t);
  int updated = 0;
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  FILE* fp = fopen(token_path, "rb");
  if(fp == NULL && (fp = fopen(token_path, "wb")) == NULL)
    cout << "WARNING : Failed to load token " << token_path << endl;

  if(fp != NULL){
    size_t read_num = fread(token, 1, token_size, fp);
    if(read_num != 0 && read_num != token_size){
      memset(&token, 0x0, token_size);
      cout << "WARNING : Invalid launch token read " << token_path << endl;
    }
  }

  ret = sgx_create_enclave(ENCLAVE_NAME.c_str(), 1, &token, &updated, &global_eid, NULL);
  if(ret != SGX_SUCCESS){
    cout << "Creating enclave failed. Aborting..." << endl;
    print_error_message(ret);
    if(fp != NULL) fclose(fp);
    return -1;
  }

  if(updated == 0 || fp == NULL){
    if(fp != NULL) fclose(fp);
    return 0;
  }

  fp = freopen(token_path, "wb", fp);
  if(fp == NULL) return 0;
  size_t write_num = fwrite(token, 1, token_size, fp);
  if(write_num != token_size)
    cout << "WARNING : Failed to save launch token." << endl;
  fclose(fp);
  return 0;
}

int initSocket(int* sockfd, struct sockaddr_in* address,
               struct sockaddr_in* serv_addr){

  if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return -1;
  }

  memset(serv_addr, '0', sizeof(*serv_addr));

  serv_addr->sin_family = AF_INET;
  serv_addr->sin_port = htons(PORT);

  if(inet_pton(AF_INET, "127.0.0.1", &(serv_addr->sin_addr))<=0){
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  if(connect(*sockfd, (struct sockaddr *)serv_addr, sizeof(*serv_addr)) < 0){
    printf("\nConnection Failed \n");
    return -1;
  }

  cout << "socket connected" << endl;

  return 0;
}

int main(){

  int valread;
  int ret;
  ra_request_header_t* p_msg0_full = NULL;
  ra_response_header_t* p_msg0_resp_full = NULL;
  ra_request_header_t* p_msg1_full = NULL;
  ra_response_header_t *p_msg2_full = NULL;
  ra_request_header_t* p_msg3_full = NULL;
  ra_response_header_t* p_att_result_msg_full = NULL;

  if(initializeEnclave()){
    cout << "Failed to initialize enclave" << endl;
    return -1;
  }



  struct sockaddr_in address;
  int sockfd;
  struct sockaddr_in serv_addr;

  ret = initSocket(&sockfd, &address, &serv_addr);

  if(ret != 0){
    cerr << "initSocket failed" << endl;
    return -1;
  }

  const char* attestation_msg = "attestation";
  send(sockfd, attestation_msg, strlen(attestation_msg), 0);
  cout << "attestation message sent" << endl;

  p_msg0_full = (ra_request_header_t*)malloc(sizeof(ra_request_header_t)
               + sizeof(uint32_t));

  valread = read(sockfd, p_msg0_full, sizeof(ra_request_header_t) + sizeof(uint32_t));
  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  cout << "got msg0" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg0_full->body, p_msg0_full->size);

  ret = sp_ra_proc_msg0_req((const sample_ra_msg0_t*)((uint8_t*)p_msg0_full + sizeof(ra_request_header_t))
                            ,p_msg0_full->size);

  p_msg0_resp_full = (ra_response_header_t*)malloc(sizeof(ra_response_header_t)
  + sizeof(uint32_t));

  p_msg0_full->type = TYPE_RA_MSG0;
  p_msg0_full->size = sizeof(uint32_t);

  if(ret != 0){
    cout << "sp_ra_proc_msg0_req failed";
    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_request_header_t)) = 1;
  }
  else
    *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_request_header_t)) = 0;

  send(sockfd, p_msg0_full, sizeof(ra_request_header_t) + p_msg0_full->size, 0);

  p_msg1_full = (ra_request_header_t*)
                malloc(sizeof(ra_request_header_t) + sizeof(sgx_ra_msg1_t));

  valread = read(sockfd, p_msg1_full, sizeof(ra_request_header_t) + sizeof(sgx_ra_msg1_t));

  if(valread < 0){
    cout << "read failed" << endl;
    return -1;
  }

  cout << "got msg1" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg1_full->body, p_msg1_full->size);

  ret = sp_ra_proc_msg1_req((const sample_ra_msg1_t*)((uint8_t*)p_msg1_full + sizeof(ra_request_header_t)),
  						              p_msg1_full->size,
  						              &p_msg2_full);

  if(ret != 0){
    cerr << "sp_ra_proc_msg1_req failed" << endl;
    return -1;
  }

  cout << "msg2 generated" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg2_full->body, p_msg2_full->size);

  cout << "send msg2" << endl;

  send(sockfd, p_msg2_full, sizeof(ra_response_header_t) + p_msg2_full->size, 0);

  p_msg3_full = (ra_request_header_t*)malloc(sizeof(ra_request_header_t));

  valread = read(sockfd, p_msg3_full, sizeof(ra_request_header_t));
  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  p_msg3_full = (ra_request_header_t*)realloc(p_msg3_full,
                                              sizeof(ra_request_header_t)
                                              + p_msg3_full->size);
  valread = read(sockfd,
                 (uint8_t*)p_msg3_full + sizeof(ra_request_header_t),
                 p_msg3_full->size);

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  cout << "got msg3" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg3_full->body, p_msg3_full->size);

  ret = sp_ra_proc_msg3_req((const sample_ra_msg3_t*)((uint8_t*)p_msg3_full
                            + sizeof(ra_request_header_t)),
                            p_msg3_full->size,
                            &p_att_result_msg_full);

  if(ret != 0){
    cerr << "sp_ra_proc_msg3_req failed" << endl;
    return -1;
  }

  sample_ra_att_result_msg_t* p_att_result_msg_body =
             (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
              + sizeof(ra_response_header_t));

  cout << "ATTESTATION RESULT RECEIVED" << endl;

  PRINT_BYTE_ARRAY(stdout, p_att_result_msg_full->body, p_att_result_msg_full->size);

  cout << "send attestation result" << endl;

  send(sockfd, p_att_result_msg_full, sizeof(ra_response_header_t)
                                    + p_att_result_msg_full->size, 0);
  close(sockfd);
  SAFE_FREE(p_msg0_full);
  SAFE_FREE(p_msg0_resp_full);
  SAFE_FREE(p_msg1_full);
  SAFE_FREE(p_msg2_full);
  SAFE_FREE(p_msg3_full);
  SAFE_FREE(p_att_result_msg_full);  


}
