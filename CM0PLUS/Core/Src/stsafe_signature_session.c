/**
  ******************************************************************************
  * @file    signature_session.c
  * @author  SMD application team
  * @version V3.3.1
  * @brief   Signature session use case using STSAFE-A and MbedTLS cryptographic library.
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


#if (USE_SIGNATURE_SESSION)
#include "mbedtls/ecdsa.h"


#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }
#define GET_TICK()                          HAL_GetTick()
#define READ_DATA_SIZE                      10U
#define CHALLENGE_SIZE                      256U
#endif /* USE_SIGNATURE_SESSION */

int32_t signature_session(StSafeA_Handle_t* handle);
#if (USE_SIGNATURE_SESSION)
static uint8_t GenerateUnsignedChallenge(StSafeA_Handle_t* handle, uint16_t size, uint8_t* random);
static int32_t GenerateSlot1KeyPair(StSafeA_Handle_t* handle, mbedtls_ecdsa_context* ctx, StSafeA_CurveId_t key_type);
static int32_t SignatureSession(StSafeA_Handle_t* handle, mbedtls_ecdsa_context* ctx);


#ifdef HAL_UART_MODULE_ENABLED
static uint8_t idx = 0;
#endif /* HAL_UART_MODULE_ENABLED */


/************************ Generate Unsigned Bytes Array ************************/
static uint8_t GenerateUnsignedChallenge(StSafeA_Handle_t* handle, uint16_t size, uint8_t* random)
{
  if (random == NULL)
  {
    return (1);
  }

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Generate a %d bytes random number", ++idx, size);
  printf("\n\r    => Use StSafeA_GenerateRandom API");
#endif /* HAL_UART_MODULE_ENABLED */

  StSafeA_LVBuffer_t TrueRandom;
  TrueRandom.Data = random;
  return ((uint8_t)StSafeA_GenerateRandom(handle, STSAFEA_EPHEMERAL_RND, size, &TrueRandom, STSAFEA_MAC_NONE));
}


/********************** Generate key pair through slot 1 **********************/
static int32_t GenerateSlot1KeyPair(StSafeA_Handle_t* handle, mbedtls_ecdsa_context* ctx, StSafeA_CurveId_t key_type)
{
  int32_t                       StatusCode = 0;
  uint8_t                       PointReprensentationId = 0;

  /* Declare, define and allocate memory for PubCX, PubCY */
  StSafeA_LVBuffer_t PubCX, PubCY;
#if !(STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
  uint8_t data_PubCX [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
  PubCX.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
  PubCX.Data = data_PubCX;
  uint8_t data_PubCY [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
  PubCY.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
  PubCY.Data = data_PubCY;
#endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

  /* Generate ephemeral key pair through STSAFE-A's SLOT 1 */
#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Generate key pair through STSAFE-A's slot1 usable 1 time (ephemeral)", ++idx);
  printf("\n\r    => Use StSafeA_GenerateKeyPair API");
#endif /* HAL_UART_MODULE_ENABLED */
  STS_CHK(StatusCode, (int32_t)StSafeA_GenerateKeyPair(handle, STSAFEA_KEY_SLOT_1, 0x0001U, 1U,
                                                       (STSAFEA_PRVKEY_MODOPER_AUTHFLAG_CMD_RESP_SIGNEN   |
                                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_MSG_DGST_SIGNEN   |
                                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_KEY_ESTABLISHEN),
                                                       key_type, STSAFEA_GET_XYRS_LEN_FROM_CURVE(key_type),
                                                       &PointReprensentationId,
                                                       &PubCX, &PubCY,STSAFEA_MAC_HOST_CMAC));

  if ((StatusCode == 0) &&
      (PointReprensentationId == (uint8_t)(STSAFEA_POINT_REPRESENTATION_ID)) &&
      (PubCX.Data != NULL) && (PubCY.Data != NULL))
  {
    /* Import the public key */
#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Import the public key through cryptographic library (private key remains into STSAFE-A)", ++idx);
#endif /* HAL_UART_MODULE_ENABLED */
    if (key_type == STSAFEA_NIST_P_256)
    {
       handle->HashObj.HashType = STSAFEA_SHA_256;
       /* Load elliptic curve and base point */
       STS_CHK(StatusCode, mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1));
    }
    else if (key_type == STSAFEA_NIST_P_384)
    {
       handle->HashObj.HashType = STSAFEA_SHA_384;
       /* Load elliptic curve and base point */
       STS_CHK(StatusCode, mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP384R1));
    }
    else if (key_type == STSAFEA_BRAINPOOL_P_256)
    {
       handle->HashObj.HashType = STSAFEA_SHA_256;
       /* Load elliptic curve and base point */
       STS_CHK(StatusCode, mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_BP256R1));
    }
    else if (key_type == STSAFEA_BRAINPOOL_P_384)
    {
       handle->HashObj.HashType = STSAFEA_SHA_384;
       /* Load elliptic curve and base point */
       STS_CHK(StatusCode, mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_BP384R1));
    }
    else
    {
       StatusCode = 1;
    }
  }

  if (StatusCode == 0)
  {
    /************* Crypto lib : Format slot 1 public key *************/
    const uint16_t InputLength = PubCX.Length + PubCY.Length + (uint16_t)sizeof(PointReprensentationId);
    uint8_t InputBuffer[InputLength];

    InputBuffer[0] = PointReprensentationId;
    (void)memcpy(&InputBuffer[1U], &PubCX.Data[0U], PubCX.Length);
    (void)memcpy(&InputBuffer[PubCX.Length + 1U], &PubCY.Data[0U], PubCY.Length);

    mbedtls_ecp_point PubKey;
    mbedtls_ecp_point_init(&PubKey);
    STS_CHK(StatusCode, mbedtls_ecp_point_read_binary(&ctx->grp, &PubKey, InputBuffer, InputLength));
    STS_CHK(StatusCode, mbedtls_ecp_copy(&ctx->Q, &PubKey));
    mbedtls_ecp_point_free(&PubKey);
  }

  return StatusCode;
}


/************************ Asymmetric Signature Session ************************/
static int32_t SignatureSession(StSafeA_Handle_t* handle, mbedtls_ecdsa_context* ctx)
{
  int32_t                     StatusCode = 0;
  uint16_t                    get_signature_resp_len;
  uint8_t                     Challenge[CHALLENGE_SIZE];
  const uint16_t              ChallengeSize = (uint16_t)rand() % 256U;

  get_signature_resp_len = ((((StSafeA_Handle_t*)handle)->HashObj.HashType == STSAFEA_SHA_384) ?
                           STSAFEA_XYRS_ECDSA_SHA384_LENGTH : STSAFEA_XYRS_ECDSA_SHA256_LENGTH);
    
  StSafeA_LVBuffer_t STS_Read, SignR, SignS;
#if !(STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    uint8_t data_Read [READ_DATA_SIZE] = {0};
    STS_Read.Data = data_Read;
    uint8_t data_SignR [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    SignR.Data = data_SignR;
    uint8_t data_SignS [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    SignS.Data = data_SignS;
#endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Start signature session", ++idx);
  printf("\n\r    => Use StSafeA_StartSignatureSession API");
#endif /* HAL_UART_MODULE_ENABLED */
  /* Start Signature Session */
  STS_CHK(StatusCode, (int32_t)StSafeA_StartSignatureSession(handle, STSAFEA_KEY_SLOT_1, STSAFEA_MAC_NONE));

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Read some bytes through zone 2", ++idx);
  printf("\n\r    => Use StSafeA_Read API");
#endif /* HAL_UART_MODULE_ENABLED */
  /* Read one way counter value */
  STS_CHK(StatusCode, (int32_t)StSafeA_Read(handle, 0, 0, STSAFEA_AC_ALWAYS, 2, 0, READ_DATA_SIZE,
                                            READ_DATA_SIZE, &STS_Read, STSAFEA_MAC_NONE));

  /* Get signature from STSAFE-A */
  STS_CHK(StatusCode, (int32_t)GenerateUnsignedChallenge(handle, ChallengeSize, Challenge));

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Generate signature on the command response sequence since the start of a signature session (including start session response)", ++idx);
  printf("\n\r    => Use StSafeA_GetSignature API");
#endif /* HAL_UART_MODULE_ENABLED */
  STS_CHK(StatusCode, (int32_t)StSafeA_GetSignature(handle, Challenge, ChallengeSize, get_signature_resp_len, &SignR, &SignS, STSAFEA_MAC_NONE));

  /* Verify signature */
  if (StatusCode == 0)
  {
#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Import the signature through cryptographic library", ++idx);
#endif /* HAL_UART_MODULE_ENABLED */
    /* Build both R & S MPI signature */
    mbedtls_mpi R;
    mbedtls_mpi S;
    mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&S);

    STS_CHK(StatusCode, mbedtls_mpi_read_binary(&R, SignR.Data, SignR.Length));
    STS_CHK(StatusCode, mbedtls_mpi_read_binary(&S, SignS.Data, SignS.Length));

    /* Verify signature */
#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Verify the signature using cryptographic library", ++idx);
#endif /* HAL_UART_MODULE_ENABLED */
    STS_CHK(StatusCode, mbedtls_ecdsa_verify(&ctx->grp, ((StSafeA_Handle_t*)handle)->HashObj.HashRes,
                        STSAFEA_GET_HASH_SIZE((uint32_t)((StSafeA_Handle_t*)handle)->HashObj.HashType), &ctx->Q, &R, &S));

    mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&S);
  }

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Signature session demonstration result (0 means success): %d", ++idx, (int)StatusCode);
#endif /* HAL_UART_MODULE_ENABLED */

  return (StatusCode);
}

#endif /* USE_SIGNATURE_SESSION */

/***************** Signature Session *******************/
int32_t signature_session(StSafeA_Handle_t* handle)
{
#if (USE_SIGNATURE_SESSION)
  int32_t StatusCode = 0;
  mbedtls_ecdsa_context ctx;

#ifdef HAL_UART_MODULE_ENABLED
  idx = 0;
  printf("\n\r\n\rSignature session demonstration:");
#endif /* HAL_UART_MODULE_ENABLED */

  /* Build ECDSA context */
  mbedtls_ecdsa_init(&ctx);

  /* Generate key pair through slot 1 */
  STS_CHK(StatusCode, GenerateSlot1KeyPair(handle, &ctx, STSAFEA_NIST_P_384));

  /* Asymmetric signature session */
  STS_CHK(StatusCode, SignatureSession(handle, &ctx));

  mbedtls_ecdsa_free(&ctx);

  return StatusCode;
#else
  return 1;
#endif /* USE_SIGNATURE_SESSION */
}


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
