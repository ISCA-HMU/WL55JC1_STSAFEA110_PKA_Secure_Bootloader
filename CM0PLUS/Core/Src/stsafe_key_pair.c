/**
  ******************************************************************************
  * @file    ephemeral_key.c
  * @author  SMD application team
  * @version V3.3.0
  * @brief   Ephemeral key use case using STSAFE-A and MbedTLS cryptographic library.
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
#include "stsafea_crypto.h"

#include "stsafea_core.h"

#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"


#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }

#define GET_TICK()                          HAL_GetTick()

int32_t key_pair_generation(StSafeA_Handle_t* handle);
static uint8_t GenerateUnsignedChallenge(StSafeA_Handle_t* handle, uint8_t size, uint8_t* random);
static int32_t KeyPairGenerationVerification(StSafeA_Handle_t* handle, StSafeA_CurveId_t key_type);
#ifdef HAL_UART_MODULE_ENABLED
static uint8_t idx = 0;
#endif /* HAL_UART_MODULE_ENABLED */


/************************ Generate Unsigned Bytes Array ************************/
static uint8_t GenerateUnsignedChallenge(StSafeA_Handle_t* handle, uint8_t size, uint8_t* random)
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


/************************ Ephemeral key generation ************************/
static int32_t KeyPairGenerationVerification(StSafeA_Handle_t* handle, StSafeA_CurveId_t key_type)
{
  int32_t StatusCode = 0;
  uint8_t PointReprensentationId = 0;

  /* Declare, define and allocate memory for PubCX, PubCY */
  StSafeA_LVBuffer_t PubCX, PubCY;
#if !(STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
  uint8_t data_PubCX [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
  PubCX.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
  PubCX.Data = data_PubCX;
  uint8_t data_PubCY [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
  PubCY.Length = STSAFEA_XYRS_ECDSA_SHA384_LENGTH;
  PubCY.Data = data_PubCY;
#endif

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Generate key pair through STSAFE-A's private key slot 1", ++idx);
    printf("\n\r    => Use StSafeA_GenerateKeyPair API");
#endif /* HAL_UART_MODULE_ENABLED */

  /* Generate key pair for private key slot and return public key */
  STS_CHK(StatusCode, (int32_t)StSafeA_GenerateKeyPair(handle, STSAFEA_KEY_SLOT_1, 1U, 1U,
                                                       (STSAFEA_PRVKEY_MODOPER_AUTHFLAG_CMD_RESP_SIGNEN |
                                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_MSG_DGST_SIGNEN   |
                                                        STSAFEA_PRVKEY_MODOPER_AUTHFLAG_KEY_ESTABLISHEN),
                                                        key_type, STSAFEA_XYRS_ECDSA_SHA384_LENGTH,
                                                        &PointReprensentationId,
                                                        &PubCX, &PubCY, STSAFEA_MAC_HOST_CMAC));

  if ((StatusCode == 0) &&
      (PointReprensentationId == STSAFEA_POINT_REPRESENTATION_ID) &&
      (PubCX.Data != NULL) && (PubCY.Data != NULL))
  { 
#if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    /* Store public key */
    uint8_t stored_PubCX [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    (void)memcpy(&stored_PubCX, PubCX.Data, PubCX.Length);
    PubCX.Data = stored_PubCX;

    uint8_t stored_PubCY [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    (void)memcpy(&stored_PubCY, PubCY.Data, PubCY.Length);
    PubCY.Data = stored_PubCY;
#endif

    /* Declare, define and allocate memory for Signature & Hash */
    StSafeA_LVBuffer_t Hash;
//    uint8_t data_Hash [STSAFEA_GET_HASH_SIZE((uint16_t)STSAFEA_SHA_384)] = {0};
    uint8_t data_Hash [STSAFEA_SHA_384_LENGTH] = {0};
    Hash.Length = STSAFEA_GET_HASH_SIZE((uint16_t)STSAFEA_SHA_384);
    Hash.Data = data_Hash;

    /* Generate challenge & hash */
    STS_CHK(StatusCode, (int32_t)GenerateUnsignedChallenge(handle, Hash.Length, Hash.Data));
#ifdef HAL_UART_MODULE_ENABLED
    printf("\n\r %d. Compute hash using cryptographic library", ++idx);
#endif /* HAL_UART_MODULE_ENABLED */
    mbedtls_sha512(Hash.Data, Hash.Length, data_Hash, 1);

#ifdef HAL_UART_MODULE_ENABLED
  if (StatusCode == 0U)
  {
    printf("\n\r %d. Generate signature using STSAFE-A's private key stored into slot 1", ++idx);
    printf("\n\r    => Use StSafeA_GenerateSignature API");
  }
#endif /* HAL_UART_MODULE_ENABLED */

    /* Generate signature of Hash(random) */
    StSafeA_LVBuffer_t OutR, OutS;
#if !(STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    uint8_t data_OutR [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    OutR.Data = data_OutR;
    uint8_t data_OutS [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
    OutS.Data = data_OutS;
#endif
    STS_CHK(StatusCode, (int32_t)StSafeA_GenerateSignature(handle, STSAFEA_KEY_SLOT_1, Hash.Data, STSAFEA_SHA_384,
                                                           STSAFEA_XYRS_ECDSA_SHA384_LENGTH,
                                                           &OutR, &OutS, STSAFEA_MAC_NONE, STSAFEA_ENCRYPTION_NONE));

    /* Verify signature */
    if ((StatusCode == 0) && (OutR.Data != NULL) && (OutS.Data != NULL))
    {
#ifdef HAL_UART_MODULE_ENABLED
      printf("\n\r %d. Verify message signature using STSAFE-A", ++idx);
      printf("\n\r    => Use StSafeA_VerifyMessageSignature API");
#endif /* HAL_UART_MODULE_ENABLED */

      /* Verify message signature */
      StSafeA_VerifySignatureBuffer_t Verif;
#if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    uint8_t data_OutR [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
		(void)memcpy(data_OutR, OutR.Data, OutR.Length);
    OutR.Data = data_OutR;
    uint8_t data_OutS [STSAFEA_XYRS_ECDSA_SHA384_LENGTH] = {0};
		(void)memcpy(data_OutS, OutS.Data, OutS.Length);
    OutS.Data = data_OutS;
#endif
      STS_CHK(StatusCode, (int32_t)StSafeA_VerifyMessageSignature(handle, key_type, &PubCX, &PubCY, &OutR, &OutS, &Hash, &Verif, STSAFEA_MAC_NONE));

      /* Check signature validity */
      if ((StatusCode == 0) && (Verif.SignatureValidity == 0U))
      {
        StatusCode = (int32_t)~0U;
      }
    }
  }

#ifdef HAL_UART_MODULE_ENABLED
  printf("\n\r %d. Signature verification result (0 means success): %d", ++idx, (int)StatusCode);
#endif /* HAL_UART_MODULE_ENABLED */

  return (StatusCode);
}


/***************** Ephemeral key *******************/
int32_t key_pair_generation(StSafeA_Handle_t* handle)
{
  int32_t StatusCode = 0;

#ifdef HAL_UART_MODULE_ENABLED
  idx = 0;
  printf("\n\r\n\rKey pair generation demonstration:");
#endif /* HAL_UART_MODULE_ENABLED */

  /* Ephemeral key generation and verification */
  STS_CHK(StatusCode, KeyPairGenerationVerification(handle, STSAFEA_BRAINPOOL_P_384));

  return StatusCode;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
