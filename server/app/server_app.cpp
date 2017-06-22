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
#include "remote_attestation_result.h"
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

void PRINT_ATTESTATION_SERVICE_RESPONSE(
    FILE *file,
    ra_response_header_t *response)
{
    if(!response)
    {
        fprintf(file, "\t\n( null )\n");
        return;
    }

    fprintf(file, "RESPONSE TYPE:   0x%x\n", response->type);
    fprintf(file, "RESPONSE STATUS: 0x%x 0x%x\n", response->status[0],
            response->status[1]);
    fprintf(file, "RESPONSE BODY SIZE: %u\n", response->size);

    if(response->type == TYPE_RA_MSG2)
    {
        sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)(response->body);

        fprintf(file, "MSG2 gb - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->g_b), sizeof(p_msg2_body->g_b));

        fprintf(file, "MSG2 spid - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->spid), sizeof(p_msg2_body->spid));

        fprintf(file, "MSG2 quote_type : %hx\n", p_msg2_body->quote_type);

        fprintf(file, "MSG2 kdf_id : %hx\n", p_msg2_body->kdf_id);

        fprintf(file, "MSG2 sign_gb_ga - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sign_gb_ga),
                         sizeof(p_msg2_body->sign_gb_ga));

        fprintf(file, "MSG2 mac - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->mac), sizeof(p_msg2_body->mac));

        fprintf(file, "MSG2 sig_rl - ");
        PRINT_BYTE_ARRAY(file, &(p_msg2_body->sig_rl),
                         p_msg2_body->sig_rl_size);
    }
    else if(response->type == TYPE_RA_ATT_RESULT)
    {
        sample_ra_att_result_msg_t *p_att_result =
            (sample_ra_att_result_msg_t *)(response->body);
        fprintf(file, "ATTESTATION RESULT MSG platform_info_blob - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->platform_info_blob),
                         sizeof(p_att_result->platform_info_blob));

        fprintf(file, "ATTESTATION RESULT MSG mac - ");
        PRINT_BYTE_ARRAY(file, &(p_att_result->mac), sizeof(p_att_result->mac));

        fprintf(file, "ATTESTATION RESULT MSG secret.payload_tag - %u bytes\n",
                p_att_result->secret.payload_size);

        fprintf(file, "ATTESTATION RESULT MSG secret.payload - ");
        PRINT_BYTE_ARRAY(file, p_att_result->secret.payload,
                p_att_result->secret.payload_size);
    }
    else
    {
        fprintf(file, "\nERROR in printing out the response. "
                       "Response of type not supported %d\n", response->type);
    }
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

int initSocket(int* sockfd, struct sockaddr_in* address, int* opt){

  int addrlen = sizeof(address);

  cout << "initializing connection..." << endl;
  if ((*sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
      perror("socket failed");
      return -1;
  }

  if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  opt, sizeof(*opt))){
      perror("setsockopt");
      return -1;
  }
  address->sin_family = AF_INET;
  address->sin_addr.s_addr = INADDR_ANY;
  address->sin_port = htons( PORT );

  if (bind(*sockfd, (struct sockaddr *)address,
                                 sizeof(*address))<0){
      perror("bind failed");
      return -1;
  }
  if (listen(*sockfd, 3) < 0){
      perror("listen");
      return -1;
  }
  if ((*sockfd = accept(*sockfd, (struct sockaddr *)address,
                       (socklen_t*)&addrlen))<0){
      perror("accept");
      return -1;
  }

  return 0;
}

int genMsg0(ra_request_header_t** p_msg0_full){
  uint32_t extended_epid_group_id = 0;
  int ret;
  ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);

  if(ret != SGX_SUCCESS){
    cerr << "sgx_get_extended_epid_group_id failed inside genMsg0" << endl;
    return -1;
  }

  cout << "sgx_get_extended_epid_group_id success" << endl;

  *p_msg0_full = (ra_request_header_t*)malloc(sizeof(ra_request_header_t)
                + sizeof(uint32_t));

  if(*p_msg0_full == NULL){
    cerr << "memory problem with msg0" << endl;
    return -1;
  }

  (*p_msg0_full)->type = TYPE_RA_MSG0;
  (*p_msg0_full)->size = sizeof(uint32_t);

  *(uint32_t*)((uint8_t*)*p_msg0_full + sizeof(ra_request_header_t)) = extended_epid_group_id;

  cout << "msg0 body" << endl;
  PRINT_BYTE_ARRAY(stdout, (*p_msg0_full)->body, (*p_msg0_full)->size);

  return 0;
}

int genMsg1(sgx_status_t* status, sgx_ra_context_t* context,
             ra_request_header_t** p_msg1_full, int busy_retry_time,
              int enclave_lost_retry_time){
  int ret;

  do{
    ret = enclave_init_ra(global_eid, status, false, context);
  }while(ret == SGX_ERROR_ENCLAVE_LOST && enclave_lost_retry_time--);

  if(SGX_SUCCESS != ret || *status){
    cerr << "enclave_init_ra failed" << endl;
    return -1;
  }

  cout << "enclave_init_ra success." << endl;

  *p_msg1_full = (ra_request_header_t*)
                malloc(sizeof(ra_request_header_t) + sizeof(sgx_ra_msg1_t));

  if(*p_msg1_full == NULL){
    cerr << "memory problem with msg1" << endl;
    return -1;
  }

  (*p_msg1_full)->type = TYPE_RA_MSG1;
  (*p_msg1_full)->size = sizeof(sgx_ra_msg1_t);

  do{
    ret = sgx_ra_get_msg1(*context, global_eid, sgx_ra_get_ga,
                          (sgx_ra_msg1_t*)((uint8_t*)*p_msg1_full
                          + sizeof(ra_request_header_t)));
    sleep(3);
  }while(ret == SGX_ERROR_BUSY && busy_retry_time--);

  if(ret != SGX_SUCCESS){
    cerr << "sgx_ra_get_msg1 failed" << endl;
    return -1;
  }

  cout << "sgx_ra_get_msg1 success" << endl;
  cout << "msg1 body generated" << endl;
  PRINT_BYTE_ARRAY(stdout, (*p_msg1_full)->body, (*p_msg1_full)->size);

  return 0;
}

int genMsg3(ra_response_header_t* p_msg2_full,
            ra_request_header_t** p_msg3_full,
            sgx_ra_context_t context,
            uint32_t* msg3_size
            ){
  sgx_ra_msg2_t* p_msg2_body = (sgx_ra_msg2_t*)((uint8_t*)p_msg2_full
                               + sizeof(ra_response_header_t));
  sgx_ra_msg3_t* p_msg3 = NULL;
  int busy_retry_time = 2;
  int ret;

  do{
    ret = sgx_ra_proc_msg2(context,
                        global_eid,
                        sgx_ra_proc_msg2_trusted,
                        sgx_ra_get_msg3_trusted,
                        p_msg2_body,
                        p_msg2_full->size,
                        &p_msg3,
                        msg3_size);
  }while(ret == SGX_ERROR_BUSY && busy_retry_time--);

  if(!p_msg3){
    cerr << "sgx_ra_proc_msg2 failed" << endl;
    return -1;
  }

  if((sgx_status_t)ret != SGX_SUCCESS){
    cerr << "sgx_ra_proc_msg2 failed" << endl;
    return -1;
  }

  cout << "msg3 generated" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg3, *msg3_size);

  *p_msg3_full = (ra_request_header_t*)malloc(sizeof(ra_request_header_t) + *msg3_size);

  if(*p_msg3_full == NULL){
    cerr << "memory problem with msg3" << endl;
    return -1;
  }

  (*p_msg3_full)->type = TYPE_RA_MSG3;
  (*p_msg3_full)->size = *msg3_size;
  memcpy((*p_msg3_full)->body, p_msg3, *msg3_size);
  if((*p_msg3_full)->body == NULL){
    cerr << "assembling msg3 failed" << endl;
    return -1;
  }

  return 0;
}

int main(){

  int sockfd, valread;
  struct sockaddr_in address;
  int opt = 1;
  char buffer[1024] = {0};

  sgx_ra_context_t context = INT_MAX;
  int ret;
  int enclave_lost_retry_time = 1;
  int busy_retry_time = 4;
  sgx_status_t status;
  ra_request_header_t* p_msg0_full = NULL;
  ra_response_header_t* p_msg0_resp_full = NULL;
  ra_request_header_t* p_msg1_full = NULL;
  ra_response_header_t* p_msg2_full = NULL;
  ra_request_header_t* p_msg3_full = NULL;
  ra_response_header_t* p_att_result_msg_full = NULL;


  if(initializeEnclave()){
    cerr << "Failed to initialize enclave" << endl;
    return -1;
  }

  ret = initSocket(&sockfd, &address, &opt);

  if(ret != 0){
    cerr << "initSocket failed" << endl;
    return -1;
  }

  cout << "wating for attestation request" << endl;
  valread = read(sockfd, buffer, 1024);

  if(valread > 0 && !strcmp(buffer,"attestation"))
    cout << "got attestation request from client" << endl;
  else{
    cerr << "read failed" << endl;
    return -1;
  }

  ret = genMsg0(&p_msg0_full);

  if(ret != 0){
    cerr << "generating msg0 failed" << endl;
    return -1;
  }

  cout << "send msg0 to SP" << endl;
  send(sockfd, p_msg0_full, sizeof(ra_request_header_t) + p_msg0_full->size, 0);

  p_msg0_resp_full = (ra_response_header_t*)malloc(sizeof(ra_response_header_t)
  + sizeof(uint32_t));

  read(sockfd, p_msg0_resp_full, sizeof(ra_response_header_t) + sizeof(uint32_t));
  if(*(uint32_t*)((uint8_t*)p_msg0_resp_full + sizeof(ra_response_header_t)) == 1){
    cout << "invaild epid" << endl;
    return -1;
  }
  else
    cout << "got msg0 response" <<endl;

  ret = genMsg1(&status, &context, &p_msg1_full,
                 busy_retry_time, enclave_lost_retry_time);

  if(ret != 0){
    cerr << "generating msg1 failed" << endl;
    return -1;
  }

  cout << "send msg1 to SP, expect msg2" << endl;
  send(sockfd, p_msg1_full, sizeof(ra_request_header_t) + p_msg1_full->size, 0);

  p_msg2_full = (ra_response_header_t*)malloc(sizeof(ra_response_header_t));

  valread = read(sockfd, p_msg2_full, sizeof(ra_response_header_t));

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  p_msg2_full = (ra_response_header_t*)
                  realloc(p_msg2_full,
                          sizeof(ra_response_header_t) + p_msg2_full->size);

  valread = read(sockfd,
                  (uint8_t*)p_msg2_full + sizeof(ra_response_header_t),
                   p_msg2_full->size);

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  cout << "got msg2" << endl;

  PRINT_BYTE_ARRAY(stdout, p_msg2_full->body, p_msg2_full->size);

  cout << "description about msg2" << endl;

  PRINT_ATTESTATION_SERVICE_RESPONSE(stdout, p_msg2_full);

  uint32_t msg3_size;

  ret = genMsg3(p_msg2_full, &p_msg3_full, context, &msg3_size);

  if(ret != 0){
    cerr << "generating msg3 failed" << endl;
    return -1;
  }

  cout << "send msg3" << endl;

  send(sockfd, p_msg3_full, sizeof(ra_request_header_t) + msg3_size, 0);

  p_att_result_msg_full = (ra_response_header_t*)malloc(sizeof(ra_response_header_t));

  valread = read(sockfd, p_att_result_msg_full, sizeof(ra_response_header_t));

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  p_att_result_msg_full = (ra_response_header_t*)realloc(p_att_result_msg_full,
                                                 sizeof(ra_response_header_t)
                                                 + p_att_result_msg_full->size);
  valread = read(sockfd, (uint8_t*)p_att_result_msg_full
                             + sizeof(ra_response_header_t),
                              p_att_result_msg_full->size);

  if(valread < 0){
    cerr << "read failed" << endl;
    return -1;
  }

  cout << "got attestation result" << endl;

  PRINT_BYTE_ARRAY(stdout, p_att_result_msg_full->body, p_att_result_msg_full->size);

  sample_ra_att_result_msg_t* p_att_result_msg_body =
             (sample_ra_att_result_msg_t *)((uint8_t*)p_att_result_msg_full
              + sizeof(ra_response_header_t));

  ret = verify_att_result_mac(global_eid,
                &status,
                context,
                (uint8_t*)&p_att_result_msg_body->platform_info_blob,
                sizeof(ias_platform_info_blob_t),
                (uint8_t*)&p_att_result_msg_body->mac,
                sizeof(sgx_mac_t));
        if((SGX_SUCCESS != ret) ||
           (SGX_SUCCESS != status))
        {
            ret = -1;
            return -1;
        }

        cout << "verification done" << endl;
        bool attestation_passed = true;

        close(sockfd);
        SAFE_FREE(p_msg0_full);
        SAFE_FREE(p_msg0_resp_full);
        SAFE_FREE(p_msg1_full);
        SAFE_FREE(p_msg2_full);
        SAFE_FREE(p_msg3_full);
        SAFE_FREE(p_att_result_msg_full);



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
