#include <iostream>
#include <stdio.h>
#include <limits.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "server_enclave_u.h"
#include "sgx_urts.h"
#include "sgx_ukey_exchange.h"
#include "sgx_uae_service.h"
#include "message.h"
#define PORT 8080

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

int main(){

  sgx_ra_context_t context = INT_MAX;
  int ret;
  int enclave_lost_retry_time = 1;
  int busy_retry_time = 4;
  sgx_status_t status;
  ra_request_header_t* p_msg0_full;
  ra_response_header_t* p_msg0_resp_full;
  ra_request_header_t* p_msg1_full;
  ra_response_header_t* p_msg2_full;

  if(initializeEnclave()){
    cout << "Failed to initialize enclave" << endl;
    return -1;
  }

  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  char buffer[1024] = {0};

  cout << "initializing connection..." << endl;
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
      perror("socket failed");
      exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt))){
      perror("setsockopt");
      exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons( PORT );

  if (bind(server_fd, (struct sockaddr *)&address,
                                 sizeof(address))<0){
      perror("bind failed");
      exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 3) < 0){
      perror("listen");
      exit(EXIT_FAILURE);
  }
  if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                       (socklen_t*)&addrlen))<0){
      perror("accept");
      exit(EXIT_FAILURE);
  }

  cout << "wating for attestation request" << endl;
  valread = read(new_socket, buffer, 1024);

  if(valread > 0 && !strcmp(buffer,"attestation"))
    cout << "got attestation request from client" << endl;
  else{
    cerr << "read failed" << endl;
    return -1;
  }


  uint32_t extended_epid_group_id = 0;
  ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);
  if(ret != SGX_SUCCESS){
    cerr << "sgx_get_extended_epid_group_id failed" << endl;
    return -1;
  }

  cout << "sgx_get_extended_epid_group_id success" << endl;

  p_msg0_full = (ra_request_header_t*)malloc(sizeof(ra_request_header_t)
                + sizeof(uint32_t));

  if(p_msg0_full == NULL){
    ret = -1;
    //goto CLEANUP;
  }

  p_msg0_full->type = TYPE_RA_MSG0;
  p_msg0_full->size = sizeof(uint32_t);

  *(uint32_t*)((uint8_t*)p_msg0_full + sizeof(ra_request_header_t)) = extended_epid_group_id;

  cout << "msg0 body" << endl;
  PRINT_BYTE_ARRAY(stdout, p_msg0_full->body, p_msg0_full->size);

  cout << "send msg0 to SP" << endl;
  send(new_socket, p_msg0_full, sizeof(ra_request_header_t) + p_msg0_full->size, 0);

  p_msg0_resp_full = (ra_response_header_t*)malloc(sizeof(ra_response_header_t)
  + sizeof(uint32_t));

  read(new_socket, p_msg0_resp_full, sizeof(ra_response_header_t) + sizeof(uint32_t));
  if(*(uint32_t*)((uint8_t*)p_msg0_resp_full + sizeof(ra_response_header_t)) == 1){
    cout << "invaild epid" << endl;
    return -1;
  }
  else
    cout << "got msg0 response" <<endl;

  do{
    ret = enclave_init_ra(global_eid, &status, false, &context);
  }while(ret == SGX_ERROR_ENCLAVE_LOST && enclave_lost_retry_time--);

  if(SGX_SUCCESS != ret || status){
    ret = -1;
    goto CLEANUP;
  }

  cout << "enclave_init_ra success." << endl;

  p_msg1_full = (ra_request_header_t*)
                malloc(sizeof(ra_request_header_t) + sizeof(sgx_ra_msg1_t));

  if(p_msg1_full == NULL){
    ret = -1;
    goto CLEANUP;
  }

  p_msg1_full->type = TYPE_RA_MSG1;
  p_msg1_full->size = sizeof(sgx_ra_msg1_t);

  do{
    ret = sgx_ra_get_msg1(context, global_eid, sgx_ra_get_ga,
                          (sgx_ra_msg1_t*)((uint8_t*)p_msg1_full
                          + sizeof(ra_request_header_t)));
    sleep(3);
  }while(ret == SGX_ERROR_BUSY && busy_retry_time--);

  if(ret != SGX_SUCCESS){
    ret = -1;
    goto CLEANUP;
  }

  cout << "sgx_ra_get_msg1 success" << endl;
  cout << "msg1 body generated" << endl;
  PRINT_BYTE_ARRAY(stdout, p_msg1_full->body, p_msg1_full->size);

  cout << "send msg1 to SP, expect msg2" << endl;
  send(new_socket, p_msg1_full, sizeof(ra_request_header_t) + p_msg1_full->size, 0);

  p_msg2_full = (ra_response_header_t*)malloc(sizeof(ra_response_header_t));

  valread = read(new_socket, p_msg2_full, sizeof(ra_response_header_t));

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }


  p_msg2_full = (ra_response_header_t*)
                 realloc(p_msg2_full,
                         sizeof(ra_response_header_t) + p_msg2_full->size);

  valread = read(new_socket,
                 (uint8_t*)p_msg2_full + sizeof(ra_response_header_t),
                  p_msg2_full->size);

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  cout << "got msg2" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg2_full->body, p_msg2_full->size);


  CLEANUP:
      // Clean-up
      // Need to close the RA key state.
      if(INT_MAX != context)
      {
          int ret_save = ret;
          ret = enclave_ra_close(global_eid, &status, context);
          if(SGX_SUCCESS != ret || status)
          {
              ret = -1;
              cerr << "\nError, call enclave_ra_close fail" << endl;
          }
          else
          {
              // enclave_ra_close was successful, let's restore the value that
              // led us to this point in the code.
              ret = ret_save;
          }
          cout << "\nCall enclave_ra_close success." << endl;
      }


  return 0;
}
