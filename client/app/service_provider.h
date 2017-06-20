#ifndef _SERVICE_PROVIDER_H
#define _SERVICE_PROVIDER_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include "remote_attestation_result.h"
#include "message.h"
#include "ecp.h"

typedef enum {
    SP_OK,
    SP_UNSUPPORTED_EXTENDED_EPID_GROUP,
    SP_INTEGRITY_FAILED,
    SP_QUOTE_VERIFICATION_FAILED,
    SP_IAS_FAILED,
    SP_INTERNAL_ERROR,
    SP_PROTOCOL_ERROR,
    SP_QUOTE_VERSION_ERROR,
} sp_ra_msg_status_t;

#pragma pack(push,1)

#define SAMPLE_SP_TAG_SIZE       16
#define SAMPLE_SP_IV_SIZE        12

#define SAMPLE_QUOTE_UNLINKABLE_SIGNATURE 0
#define SAMPLE_QUOTE_LINKABLE_SIGNATURE   1

typedef uint8_t sample_epid_group_id_t[4];

typedef struct sample_spid_t
{
    uint8_t                 id[16];
} sample_spid_t;

typedef struct sample_ec_pub_t
{
    uint8_t gx[SAMPLE_ECP_KEY_SIZE];
    uint8_t gy[SAMPLE_ECP_KEY_SIZE];
} sample_ec_pub_t;

/*fixed length to align with internal structure*/
typedef struct sample_ps_sec_prop_desc_t
{
    uint8_t  sample_ps_sec_prop_desc[256];
} sample_ps_sec_prop_desc_t;

#pragma pack(pop)

typedef uint32_t                sample_ra_context_t;

typedef uint8_t                 sample_key_128bit_t[16];

typedef sample_key_128bit_t     sample_ra_key_128_t;

typedef struct sample_ra_msg0_t
{
    uint32_t                    extended_epid_group_id;
} sample_ra_msg0_t;


typedef struct sample_ra_msg1_t
{
    sample_ec_pub_t             g_a;        /* the Endian-ness of Ga is
                                                 Little-Endian*/
    sample_epid_group_id_t      gid;        /* the Endian-ness of GID is
                                                 Little-Endian*/
} sample_ra_msg1_t;

/*Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion*/
const uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;

typedef struct sample_ra_msg2_t
{
    sample_ec_pub_t             g_b;        /* the Endian-ness of Gb is
                                                  Little-Endian*/
    sample_spid_t               spid;       /* In little endian*/
    uint16_t                    quote_type; /* unlinkable Quote(0) or linkable Quote(0) in little endian*/
    uint16_t                    kdf_id;     /* key derivation function id in little endian.
                                             0x0001 for AES-CMAC Entropy Extraction and Key Derivation */
    sample_ec_sign256_t         sign_gb_ga; /* In little endian*/
    sample_mac_t                mac;        /* mac_smk(g_b||spid||quote_type||
                                                       sign_gb_ga)*/
    uint32_t                    sig_rl_size;
    uint8_t                     sig_rl[];
} sample_ra_msg2_t;

typedef struct sample_ra_msg3_t
{
    sample_mac_t                mac;           /* mac_smk(g_a||ps_sec_prop||quote)*/
    sample_ec_pub_t             g_a;           /* the Endian-ness of Ga is*/
                                               /*  Little-Endian*/
    sample_ps_sec_prop_desc_t   ps_sec_prop;
    uint8_t                     quote[];
} sample_ra_msg3_t;

int sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
    uint32_t msg0_size);

int sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
						uint32_t msg1_size,
						ra_response_header_t **pp_msg2);

#endif
