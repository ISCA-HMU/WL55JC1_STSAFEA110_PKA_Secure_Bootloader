/**
  ******************************************************************************
  * @file    secret_establishment.c
  * @author  SMD application team
  * @version V3.1.1
  * @brief   Key establishment use case using STSAFE-A and MbedTLS cryptographic library.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2015 STMicroelectronics</center></h2>
  *
  * Licensed under ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */


/* Includes ------------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>

#include "stm32wlxx_nucleo.h"
#ifdef HAL_UART_MODULE_ENABLED
#include <stdio.h>
#endif /* HAL_UART_MODULE_ENABLED */

#include "stsafea_interface_conf.h"
#ifdef MCU_PLATFORM_INCLUDE
#include MCU_PLATFORM_INCLUDE
#endif /* MCU_PLATFORM_INCLUDE */

#include "stsafea_core.h"

#include "mbedtls/x509_crt.h"


#define NIST_P_256
//#define NIST_P_384
//#define BRAINPOOL_P_256
//#define BRAINPOOL_P_384


#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }

#if defined(STSAFE_A100)
#define STSAFEA_KEY_SLOT_EPHEMERAL          STSAFEA_KEY_SLOT_1
#endif

#ifdef HAL_UART_MODULE_ENABLED
static uint8_t idx = 0;
#endif /* HAL_UART_MODULE_ENABLED */

/* NIST_P_256 */
#if defined (NIST_P_256)
#define STSAFE_INPUT_BUFFER_MAX_LEN         2 * STSAFEA_XYRS_ECDSA_SHA256_LENGTH + 1U /* + POINT REPRESENTATION ID */   
#define HOST_PRIVATE_KEY \
  0xED,0x2C,0xA6,0xE4,0x06,0xEA,0xE1,0xD7,0x3E,0x4A,0x1B,0x24,0x5D,0xF0,0xF0,0x60,\
  0xEC,0xC3,0xE5,0x3F,0x13,0xE8,0x09,0xC5,0x53,0x51,0x23,0xE3,0xB5,0x71,0x2F,0xD4
#define HOST_PUBLIC_X_KEY \
  0xAB,0x06,0x01,0x5B,0x1B,0xEC,0x73,0xA1,0x25,0x4A,0xA1,0x84,0x66,0x0D,0xB9,0x9F,\
  0xAE,0xC9,0x60,0x3F,0xE8,0x9D,0xD0,0x74,0x54,0xE7,0xD1,0x3D,0x30,0x1D,0xCF,0x25
#define HOST_PUBLIC_Y_KEY \
  0xA6,0xF7,0x32,0x40,0xF7,0x9D,0x81,0x8A,0xB0,0x72,0x3C,0x8E,0x1C,0xE5,0xDC,0xCB,\
  0x07,0x72,0x0A,0x2A,0x7A,0x71,0xC5,0x26,0x3B,0xC9,0x89,0xD9,0x1E,0xCD,0x98,0x23
/* NIST_P_384 */
#elif defined (NIST_P_384)
#define STSAFE_INPUT_BUFFER_MAX_LEN         2 * STSAFEA_XYRS_ECDSA_SHA384_LENGTH + 1U /* + POINT REPRESENTATION ID */   
#define HOST_PRIVATE_KEY \
  0x6F,0x3E,0x90,0x2F,0xB4,0x2D,0x3F,0x0C,0x97,0x4B,0xB8,0x51,0x93,0x7A,0xEB,0xD3,0xE8,0xF0,0x99,0xBB,0xA0,0xE7,0xEF,0x6E,\
  0x75,0xA7,0xE4,0x04,0x7A,0xCC,0x8F,0xCA,0x23,0x81,0xAF,0x8E,0x4F,0xE6,0x79,0xA7,0xA2,0x67,0x7A,0x06,0x60,0x54,0x51,0xBF
#define HOST_PUBLIC_X_KEY \
  0x43,0xC7,0x9F,0x77,0x63,0x0E,0xE2,0xBF,0xF7,0x6E,0x8B,0xC3,0x11,0x64,0xC5,0xA4,0xE5,0xE6,0x9F,0xA8,0x67,0xDC,0x83,0xB2,\
  0x97,0xEA,0xA6,0x03,0x25,0x2B,0xEA,0x84,0x5B,0xC4,0x5D,0x6D,0xC2,0xCA,0x11,0x53,0xFA,0x42,0x79,0x96,0xC3,0xF6,0x8B,0x6B
#define HOST_PUBLIC_Y_KEY \
  0x03,0x6D,0x24,0x9D,0x61,0x9B,0xAA,0xCD,0x35,0x7D,0xA4,0xDC,0xD7,0xC0,0x75,0x69,0xC2,0x11,0x47,0x8B,0xDA,0x13,0xE8,0xFE,\
  0x6A,0x7B,0xFF,0x95,0x19,0xB1,0xB9,0x3B,0xCF,0x86,0xC3,0xF0,0x2E,0x49,0xC1,0xB8,0x54,0x5E,0xC8,0xAF,0x74,0xCF,0x40,0xB6
/* BRAINPOOL_P_256 */
#elif defined (BRAINPOOL_P_256)
#define STSAFE_INPUT_BUFFER_MAX_LEN         2 * STSAFEA_XYRS_ECDSA_SHA256_LENGTH + 1U /* + POINT REPRESENTATION ID */   
#define HOST_PRIVATE_KEY \
  0x62,0x2B,0x7C,0x81,0x9B,0x72,0x84,0xC5,0xFB,0x23,0xC2,0x1C,0x75,0x1E,0x84,0x1A,\
  0x24,0x07,0xDF,0x1F,0x3E,0xAD,0x26,0x40,0x86,0x88,0xBE,0x7B,0x8D,0xBD,0xB8,0xA8
#define HOST_PUBLIC_X_KEY \
  0x6E,0x46,0xB4,0xF8,0x6A,0xF2,0xAB,0x1C,0x84,0x46,0xCE,0x0D,0x58,0x37,0x43,0xD4,\
  0x97,0xCB,0x27,0xF6,0x43,0xCD,0x6F,0x0E,0x4C,0xF6,0x6E,0x6B,0x65,0x31,0x98,0x86
#define HOST_PUBLIC_Y_KEY \
  0x0E,0x2B,0x40,0xE2,0x75,0xF0,0x81,0x82,0x53,0xEF,0x6B,0x4C,0xF0,0x43,0x30,0x17,\
  0xAD,0x04,0xA8,0xCC,0xF9,0xB7,0x23,0xAE,0x98,0x83,0xDB,0xAD,0x54,0x36,0x18,0x45
/* BRAINPOOL_P_384 */
#elif defined (BRAINPOOL_P_384)
#define STSAFE_INPUT_BUFFER_MAX_LEN         2 * STSAFEA_XYRS_ECDSA_SHA384_LENGTH + 1U /* + POINT REPRESENTATION ID */   
#define HOST_PRIVATE_KEY \
  0x7C,0x04,0x8D,0x48,0x8E,0x07,0xE6,0xA2,0x77,0xCA,0x54,0x53,0xD0,0x98,0xEA,0x19,0x3D,0xE0,0xFD,0xFD,0xE9,0x42,0x82,0x1B,\
  0x58,0x54,0x03,0x8C,0xAF,0x7F,0xD3,0x37,0x55,0xC5,0xDD,0x74,0x4F,0x23,0x5C,0xE1,0x37,0xE7,0x41,0xAE,0x18,0xA4,0x2E,0xDC
#define HOST_PUBLIC_X_KEY \
  0x5E,0xA1,0x2E,0xA1,0xF9,0x40,0xF5,0x1F,0x94,0x11,0x27,0x48,0xBA,0x80,0x7F,0x73,0x9A,0x3C,0xB8,0xE9,0x94,0x55,0xA1,0x79,\
  0xB3,0xAE,0x6E,0x37,0xD3,0xEB,0x00,0x73,0x97,0x15,0x6D,0x9B,0x62,0x86,0xF8,0xC1,0x41,0xDC,0x3D,0x54,0x14,0xB3,0x12,0x43
#define HOST_PUBLIC_Y_KEY \
  0x40,0x96,0x93,0xD5,0x61,0x50,0xDE,0x1C,0x8C,0x4C,0xC1,0x5B,0x29,0x0C,0x6B,0x15,0xF9,0x83,0x39,0xBB,0xB8,0xE0,0x55,0x9D,\
  0xB0,0x57,0xFE,0xF1,0x7A,0x2C,0x1D,0x89,0xA6,0xCA,0xEB,0xEB,0xFF,0x47,0xD9,0x85,0x24,0x7B,0x31,0xB6,0x8F,0x32,0x88,0x4F
#endif

int32_t SecretEstablishment(StSafeA_Handle_t* handle);


/*************************** Key Establishment *****************************/
int32_t SecretEstablishment(StSafeA_Handle_t* handle)
{
  static const uint8_t HostPrivateKey  [] = {HOST_PRIVATE_KEY};
  uint8_t PointReprensentationId = 0;
  int32_t StatusCode = 0;

#ifdef HAL_UART_MODULE_ENABLED
  idx = 0;
  printf("\n\r\n\rKeys establishment demonstration:");
#endif /* HAL_UART_MODULE_ENABLED */

/************* STSAFE-A ephemeral key pair generation *************/

  /* Declare, define and allocate memory for PubCX, PubCY */
  StSafeA_LVBuffer_t PubCX, PubCY;
#if !(STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
#if defined (NIST_P_256) || defined (BRAINPOOL_P_256)
  uint8_t data_PubCX [STSAFEA_XYRS_ECDSA_SHA256_LENGTH] = {0};
  PubCX.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
  uint8_t data_PubCY [STSAFEA_XYRS_ECDSA_SHA256_LENGTH] = {0};
  PubCY.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
#elif defined (NIST_P_384) || defined (BRAINPOOL_P_384)
  uint8_t data_PubCX [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
  PubCX.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
  uint8_t data_PubCY [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
  PubCY.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
#endif
  PubCX.Data = data_PubCX;
  PubCY.Data = data_PubCY;
#endif

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Generate ephemeral key pair using STSAFE-A usable 1 time", ++idx);
  printf("\n\r        => Use StSafeA_GenerateKeyPair API");
#endif /* HAL_UART_MODULE_ENABLED */

  /* Generate ephemeral key pair through STSAFE-A */
  STS_CHK(StatusCode, (int32_t)StSafeA_GenerateKeyPair(handle, STSAFEA_KEY_SLOT_EPHEMERAL, 0x0001U, 1U,
                                                       (STSAFEA_PRVKEY_MODOPER_AUTHFLAG_CMD_RESP_SIGNEN |
                                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_MSG_DGST_SIGNEN |
                                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_KEY_ESTABLISHEN),
#if defined (NIST_P_256)
                                                       STSAFEA_NIST_P_256,
                                                       STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_NIST_P_256),
                                                       &PointReprensentationId,
#elif defined(NIST_P_384)
                                                       STSAFEA_NIST_P_384,
                                                       STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_NIST_P_384), 
                                                       &PointReprensentationId,
#elif defined(BRAINPOOL_P_256)
                                                       STSAFEA_BRAINPOOL_P_256,
                                                       STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_BRAINPOOL_P_256), 
                                                       &PointReprensentationId,
#elif defined(BRAINPOOL_P_384)
                                                       STSAFEA_BRAINPOOL_P_384,
                                                       STSAFEA_GET_XYRS_LEN_FROM_CURVE(STSAFEA_BRAINPOOL_P_384), 
                                                       &PointReprensentationId,
#endif
                                                       &PubCX, &PubCY,STSAFEA_MAC_HOST_CMAC));

  if ((StatusCode == 0) &&      
      (PointReprensentationId == (uint8_t)(STSAFEA_POINT_REPRESENTATION_ID)) &&
      (PubCX.Data != NULL) && (PubCY.Data != NULL))
  {
    /************* Crypto lib : host context init *************/
    mbedtls_ecdsa_context HostCtx;
    mbedtls_ecdsa_init(&HostCtx);
#if defined (NIST_P_256)
    /* Load elliptic curve and base point */
    STS_CHK(StatusCode, mbedtls_ecp_group_load(&HostCtx.grp, MBEDTLS_ECP_DP_SECP256R1));
#elif defined (NIST_P_384)
    /* Load elliptic curve and base point */
    STS_CHK(StatusCode, mbedtls_ecp_group_load(&HostCtx.grp, MBEDTLS_ECP_DP_SECP384R1));
#elif defined (BRAINPOOL_P_256)
    /* Load elliptic curve and base point */
    STS_CHK(StatusCode, mbedtls_ecp_group_load(&HostCtx.grp, MBEDTLS_ECP_DP_BP256R1));
#elif defined (BRAINPOOL_P_384)
    /* Load elliptic curve and base point */
    STS_CHK(StatusCode, mbedtls_ecp_group_load(&HostCtx.grp, MBEDTLS_ECP_DP_BP384R1));
#endif

    /************* Crypto lib : Format ephemeral public key *************/
#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Import the STSAFE-A's ephemeral public key through cryptographic library (private key remains into STSAFE-A)", ++idx);
#endif /* HAL_UART_MODULE_ENABLED */
    const uint16_t InputLength = PubCX.Length + PubCY.Length + (uint16_t)sizeof(PointReprensentationId);
    uint8_t InputBuffer[STSAFE_INPUT_BUFFER_MAX_LEN];
    
    InputBuffer[0] = PointReprensentationId;
    (void)memcpy(&InputBuffer[1U], PubCX.Data, PubCX.Length);
    (void)memcpy(&InputBuffer[PubCX.Length + 1U], PubCY.Data, PubCY.Length);

    mbedtls_ecp_point EphemeralPubKey;
    mbedtls_ecp_point_init(&EphemeralPubKey);
    STS_CHK(StatusCode, mbedtls_ecp_point_read_binary(&HostCtx.grp, &EphemeralPubKey,
                                                      InputBuffer, InputLength));

    /************* Crypto lib : Import the host private key *************/
#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Compute shared secret at host side using cryptographic library with STSAFE-A's ephemeral public key and host private key", ++idx);
#endif /* HAL_UART_MODULE_ENABLED */

    STS_CHK(StatusCode, mbedtls_mpi_read_binary(&HostCtx.d, HostPrivateKey, sizeof(HostPrivateKey)));
    STS_CHK(StatusCode, mbedtls_ecp_check_privkey(&HostCtx.grp, &HostCtx.d));

   /************* CCrypto lib : Compute scalar at host side *************/
    mbedtls_ecp_point HostZ;
    mbedtls_ecp_point_init(&HostZ);
    STS_CHK(StatusCode, mbedtls_ecp_mul(&HostCtx.grp, &HostZ, &HostCtx.d, &EphemeralPubKey, NULL, NULL));
    /* Free memory */
    mbedtls_ecp_point_free(&EphemeralPubKey);
    mbedtls_ecdsa_free(&HostCtx);

    /************* STSAFE-A : Format Host public key *************/   
    StSafeA_LVBuffer_t HostCX, HostCY;
#if defined (NIST_P_256) || defined(BRAINPOOL_P_256)
    HostCX.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
    HostCY.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
#elif defined (NIST_P_384) || defined (BRAINPOOL_P_384)
    HostCX.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
    HostCY.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
#endif
    uint8_t data_HostCX [] = {HOST_PUBLIC_X_KEY};
    HostCX.Data = data_HostCX;
    uint8_t data_HostCY [] = {HOST_PUBLIC_Y_KEY};
    HostCY.Data = data_HostCY;

#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Compute shared secret at STSAFE-A side using STSAFE-A's ephemeral private key and host public key", ++idx);
    printf("\n\r        => Use StSafeA_EstablishKey API");
#endif /* HAL_UART_MODULE_ENABLED */

    /************* STSAFE-A : establish key *************/ 
    /* Declare, define and allocate memory for Shared Secret */
    StSafeA_SharedSecretBuffer_t SharedSecret;
    uint8_t SharedKey_Data[STSAFEA_XYRS_ECDSA_SHA384_LENGTH];
    SharedSecret.SharedKey.Data   = SharedKey_Data;

#if defined (NIST_P_256) || defined(BRAINPOOL_P_256)
    STS_CHK(StatusCode, (int32_t)StSafeA_EstablishKey(handle, STSAFEA_KEY_SLOT_EPHEMERAL, &HostCX, &HostCY, STSAFEA_XYRS_ECDSA_SHA256_LENGTH,
                                                      &SharedSecret, STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_NONE));
#elif defined (NIST_P_384) || defined (BRAINPOOL_P_384)
    STS_CHK(StatusCode, (int32_t)StSafeA_EstablishKey(handle, STSAFEA_KEY_SLOT_EPHEMERAL, &HostCX, &HostCY, STSAFEA_XYRS_ECDSA_SHA384_LENGTH,
                                                      &SharedSecret, STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_NONE));
#endif

    /************* Compare both scalar *************/
    if (StatusCode == 0)
    {
      mbedtls_mpi Z;
      mbedtls_mpi_init(&Z);

      STS_CHK(StatusCode, mbedtls_mpi_read_binary(&Z, SharedSecret.SharedKey.Data, SharedSecret.SharedKey.Length));

      STS_CHK(StatusCode, mbedtls_mpi_cmp_mpi(&HostZ.X, &Z));

#ifdef HAL_UART_MODULE_ENABLED
      printf("\n\r %d. Verify if shared secret is identical (0 means success): %d", ++idx, (int)StatusCode);
#endif /* HAL_UART_MODULE_ENABLED */

      /* Free memory */
      mbedtls_mpi_free(&Z);
    }

    /* Free memory */
    mbedtls_ecp_point_free(&HostZ);
  }

  return StatusCode;
}


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
