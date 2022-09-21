/**
 ******************************************************************************
 * @file    authentication.c
 * @author  SMD application team
 * @version V3.3.1
 * @brief   Authentication use case using STSAFE-A and MbedTLS cryptographic library.
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

#include "usart.h"

#include "stsafea_core.h"
#include "stsafea_crypto.h"

#include "stsafe_authentication.h"
#include "stsafe_common.h"
#include "stsafe_certs.h"

#include "x509.h"
#include "pka.h"
#include "prime256v1.h"
#include "mbedtls/sha256.h"

static STSAFE_Status_t ExtractParseVerifyCertificate(StSafeA_Handle_t *handle);
static STSAFE_Status_t PeripheralAuthentication(StSafeA_Handle_t *handle);

PKA_ECDSAVerifInTypeDef in = {0};
__IO uint32_t operationComplete = 0;

const uint32_t SigVer_Result = SET;

/************************ ExtractParseVerifyCertificate ************************/
static STSAFE_Status_t ExtractParseVerifyCertificate(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;
  intCert_stt STS_Certificate, psslCASelfSignedCertificate;
  uint32_t flags;
  uint16_t CertificateSize = 0;

  uint8_t hash_digest[32] = {0};

  static uint8_t CASelfSignedCertificate_SPL2[] = {CA_SELF_SIGNED_CERTIFICATE_01};
  static uint8_t CASelfSignedCertificate_SPL1[] = {CA_SELF_SIGNED_CERTIFICATE_91};
  static uint8_t CASelfSignedCertificate_DEMO[] = {CA_SELF_SIGNED_CERTIFICATE_DEMO};

  StSafeA_LVBuffer_t sts_read;

#if (!STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
  uint8_t data_sts_read[NUMBER_OF_BYTES_TO_GET_CERTIFICATE_SIZE];
  sts_read.Length = NUMBER_OF_BYTES_TO_GET_CERTIFICATE_SIZE;
  sts_read.Data = data_sts_read;
#endif

  LOG("Extracting the leaf certificate from the STSAFE A110, parsing it and verifying it\r\n");

  LOG("  Going to retrieve the leaf certificate stored in STSAFE A110 Zone 0\r\n");

  // Extract the first 4 bytes of the STSAFE A110 X509 leaf certificate which provide the size of the certificate.
  STS_CHK(StatusCode, (int32_t)StSafeA_Read(handle, 0, 0, STSAFEA_AC_ALWAYS, 0, 0, NUMBER_OF_BYTES_TO_GET_CERTIFICATE_SIZE, NUMBER_OF_BYTES_TO_GET_CERTIFICATE_SIZE, &sts_read, STSAFEA_MAC_NONE));

  // Calculate the size of the leaf certificate to receive from the STSAFE A110 device.
  if (StatusCode == 0)
  {
    switch (sts_read.Data[1])
    {
      case 0x81U:
	CertificateSize = (uint16_t) sts_read.Data[2] + 3U;
	break;

      case 0x82U:
	CertificateSize = (((uint16_t) sts_read.Data[2]) << 8) + sts_read.Data[3] + 4U;
	break;

      default:
	if (sts_read.Data[1] < 0x81U)
	{
	  CertificateSize = sts_read.Data[1];
	}
	break;
    }

    LOG("  Leaf certificate size: %d bytes\r\n", CertificateSize);

    if (CertificateSize == 0)
    {
      return STATUS_CERT_NOT_FOUND;
    }

    LOG("  Extracting the leaf certificate from STSAFE A110 Zone 0\r\n");

    StSafeA_LVBuffer_t sts_read_cert;
#if (!STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    uint8_t data_sts_read_cert[CertificateSize];
    sts_read_cert.Length = CertificateSize;
    sts_read_cert.Data = data_sts_read_cert;
#endif
    // Extract the leaf X509 certificate from STSAFE A110 Zone 0.
    STS_CHK(StatusCode, (int32_t)StSafeA_Read(handle, 0, 0, STSAFEA_AC_ALWAYS, 0, 0, CertificateSize, CertificateSize, &sts_read_cert, STSAFEA_MAC_NONE));

    if (StatusCode == 0)
    {
      LOG("  Leaf certificate extracted from STSAFE A110 Zone 0\r\n");

      // Parse the Leaf Certificate
      initIntCert(&STS_Certificate);
      STS_CHK(StatusCode, parseCert(sts_read_cert.Data, &STS_Certificate, NULL));

      if (StatusCode != 0U)
      {
	return STATUS_CERT_PARSE_ERROR;
      }

      // Parse the CA Certificate
      initIntCert(&psslCASelfSignedCertificate);
      STS_CHK(StatusCode, parseCert(CASelfSignedCertificate_SPL2, &psslCASelfSignedCertificate, NULL));

      if (StatusCode != 0U)
      {
	return STATUS_CERT_PARSE_ERROR;
      }

//      StSafeA_SHA_Init(handle->HashObj.HashType, &handle->HashObj.HashCtx);
//      StSafeA_SHA_Update(handle->HashObj.HashType, &handle->HashObj.HashCtx, STS_Certificate.tbs, STS_Certificate.tbsSize);
//      StSafeA_SHA_Final(handle->HashObj.HashType, &handle->HashObj.HashCtx, hash_digest);

      mbedtls_sha256_context ctx2;

      mbedtls_sha256_init(&ctx2);
      mbedtls_sha256_starts(&ctx2, 0); /* SHA-256, not 224 */

      /* Simulating multiple fragments */
      mbedtls_sha256_update(&ctx2, STS_Certificate.tbs, STS_Certificate.tbsSize);

      mbedtls_sha256_finish(&ctx2, hash_digest);


      LOG("Hash: %02X %02X %02X %02X\r\n", hash_digest[0], hash_digest[1], hash_digest[2], hash_digest[3]);
//
//      (void)SHA256_Init(&ctx);
//      (void)SHA256_Append(&ctx, child->tbs, child->tbsSize);
//      (void)SHA256_Finish(&ctx, digest, &digestSize);

//      void StSafeA_InitHASH(StSafeA_Handle_t *pStSafeA)
//
//      void StSafeA_ComputeHASH(StSafeA_Handle_t *pStSafeA)

      /* Set input parameters */
      in.primeOrderSize = prime256v1_Order_len;
      in.modulusSize = prime256v1_Prime_len;
      in.coefSign = prime256v1_A_sign;
      in.coef = prime256v1_absA;
      in.modulus = prime256v1_Prime;
      in.basePointX = prime256v1_GeneratorX;
      in.basePointY = prime256v1_GeneratorY;
      in.primeOrder = prime256v1_Order;

      in.pPubKeyCurvePtX = psslCASelfSignedCertificate.PubKey.pX;
      in.pPubKeyCurvePtY = psslCASelfSignedCertificate.PubKey.pY;
      in.RSign = STS_Certificate.Sign.pR;
      in.SSign = STS_Certificate.Sign.pS;
      in.hash = hash_digest;

      LOG("to verify\r\n");

      /* Launch the verification */
      if (HAL_PKA_ECDSAVerif_IT(&hpka, &in) != HAL_OK)
      {
	LOG("Verification problem\r\n");

//	Error_Handler();
      }
      else
      {
	LOG("verification executed ok\r\n");
      }

      /* Wait until the interrupt is triggered */
      while (operationComplete == 0)
	;
      operationComplete = 0;

      /* Compare to expected result */
      if (HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) != SigVer_Result)
      {
//	Error_Handler();
	LOG("Invalid Certificate\r\n");
      }
      else
      {
	LOG("Valid Certificate\r\n");
      }

//      //Parse STSAFE A110 X509 leaf certificate
//      mbedtls_x509_crt_init(&STS_Certificate);
//      StatusCode = mbedtls_x509_crt_parse(&STS_Certificate, sts_read_cert.Data, CertificateSize);
//
//      if (StatusCode == 0U)
//      {
//	printf("  Parsed leaf certificate\r\n");
//      }
//      else
//      {
//	printf("  Failed to parse leaf certificate\r\n");
//
//	return STATUS_CERT_PARSE_ERROR;
//      }
//
//      /*
//       * Initially, check if the root certificate is SPL2 profile.
//       * Parse the CA SPL2 certificate.
//       */
//      mbedtls_x509_crt_init(&psslCASelfSignedCertificate);
//      STS_CHK(StatusCode, mbedtls_x509_crt_parse(&psslCASelfSignedCertificate, CASelfSignedCertificate_SPL2, sizeof(CASelfSignedCertificate_SPL2)));
//
//      // Forced to 1 due to self signed certificate generated by a non trusted authority (STMicroelectronics).
//      if (StatusCode == 0)
//      {
//	psslCASelfSignedCertificate.ca_istrue = 1;
//      }
//
//      printf("  Going to verify if the STSAFE A110 leaf certificate was signed by the trusted CA SPL2 profile certificate, please wait...\r\n");
//
//      // Verify STSAFE A110 X509 self signed leaf certificate.
//      STS_CHK(StatusCode, mbedtls_x509_crt_verify(&STS_Certificate, &psslCASelfSignedCertificate, NULL, NULL, &flags, NULL, NULL));
//
//      // Check if root certificate is SPL1 profile because it was not SPL2.
//      if (StatusCode != 0)
//      {
//	printf("  Verification with SPL2 certificate failed, verifying with SPL1 profile certificate\r\n");
//
//	// Unallocate all previous certificate data.
//	mbedtls_x509_crt_free(&psslCASelfSignedCertificate);
//
//	// Parse CA SPL1 profile certificate.
//	mbedtls_x509_crt_init(&psslCASelfSignedCertificate);
//	StatusCode = mbedtls_x509_crt_parse(&psslCASelfSignedCertificate, CASelfSignedCertificate_SPL1, sizeof(CASelfSignedCertificate_SPL1));
//
//	// Forced to 1 due to self signed certificate generated by a non trusted authority (STMicroelectronics).
//	if (StatusCode == 0)
//	{
//	  psslCASelfSignedCertificate.ca_istrue = 1;
//	}
//
//	// Verify STSAFE A110 X509 self signed leaf certificate.
//	STS_CHK(StatusCode, mbedtls_x509_crt_verify(&STS_Certificate, &psslCASelfSignedCertificate, NULL, NULL, &flags, NULL, NULL));
//      }
//
//      // Check if root certificate is the one from Engineering Samples.
//      if (StatusCode != 0)
//      {
//	printf("  Verification with SPL1 certificate failed, verifying with engineering samples certificate\r\n");
//
//	// Unallocate all previous certificate data.
//	mbedtls_x509_crt_free(&psslCASelfSignedCertificate);
//
//	// Parse engineering samples certificate.
//	mbedtls_x509_crt_init(&psslCASelfSignedCertificate);
//	StatusCode = mbedtls_x509_crt_parse(&psslCASelfSignedCertificate, CASelfSignedCertificate_DEMO, sizeof(CASelfSignedCertificate_DEMO));
//
//	// Forced to 1 due to self signed certificate generated by a non trusted authority (STMicroelectronics).
//	if (StatusCode == 0)
//	{
//	  psslCASelfSignedCertificate.ca_istrue = 1;
//	}
//
//	// Verify STSAFE A110 X509 self signed leaf certificate.
//	STS_CHK(StatusCode, mbedtls_x509_crt_verify(&STS_Certificate, &psslCASelfSignedCertificate, NULL, NULL, &flags, NULL, NULL));
//      }
//
//      // Free CA certificate structure.
//      mbedtls_x509_crt_free(&psslCASelfSignedCertificate);
//
//      if (StatusCode == 0)
//      {
//	printf("  Leaf certificate verification was successful\r\n");
//
//	// Check if ECDSA public context can perform operations.
//	if (mbedtls_pk_can_do(&STS_Certificate.pk, MBEDTLS_PK_ECDSA) == 0)
//	{
//	  return STATUS_ERROR;
//	}
//
//	/* Load public key into context */
//	STS_CHK(StatusCode, mbedtls_ecdsa_from_keypair(ctx, mbedtls_pk_ec(STS_Certificate.pk)));
//
//	// Set hash type regarding SLOT 0 key pair length (public key length into certificate).
//	if (((mbedtls_pk_get_len(&(STS_Certificate.pk)) / 16U) - 2U) == 0U)
//	{
//	  ((StSafeA_Handle_t*) handle)->HashObj.HashType = STSAFEA_SHA_256;
//	}
//	else
//	{
//	  ((StSafeA_Handle_t*) handle)->HashObj.HashType = STSAFEA_SHA_384;
//	}
//      }
//
//      // Free STSAFE-A's X509 certificate structure.
//      mbedtls_x509_crt_free(&STS_Certificate);
    }
  }
  return StatusCode;
}

/************************ Peripheral Authentication ************************/
static STSAFE_Status_t PeripheralAuthentication(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;
//  uint8_t Hash[STSAFEA_GET_HASH_SIZE(STSAFEA_SHA_256)];
//
//  StSafeA_LVBuffer_t SignR, SignS;
//#if (!STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
//  uint8_t data_SignR[STSAFEA_XYRS_ECDSA_SHA256_LENGTH];
//  SignR.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
//  SignR.Data = data_SignR;
//  uint8_t data_SignS[STSAFEA_XYRS_ECDSA_SHA256_LENGTH];
//  SignS.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
//  SignS.Data = data_SignS;
//#endif
//
//  printf("Authenticating the STSAFE A110 peripheral\r\n");
//
//  /* Generate challenge & hash */
//  StatusCode = (int32_t) GenerateUnsignedChallenge(handle, (uint16_t) sizeof(Hash), Hash);
//
//  printf("  Make a SHA256 hash from the random bytes\r\n");
//  mbedtls_sha256(Hash, sizeof(Hash), Hash, 0);
//
//  if (StatusCode == 0U)
//  {
//    printf("  Going to generate signature of hash using STSAFE A110 private key stored into Key Slot 0\r\n");
//  }
//  else
//  {
//    printf("  Failed to generate random bytes, aborting [STSAFE error %d]\r\n", (int) StatusCode);
//    return STATUS_RANDOM_GEN_ERROR;
//  }
//
//  /* Generate signature of Hash(random) */
//  STS_CHK(StatusCode, (int32_t)StSafeA_GenerateSignature(handle, STSAFEA_KEY_SLOT_0, Hash, STSAFEA_SHA_256, STSAFEA_XYRS_ECDSA_SHA256_LENGTH, &SignR, &SignS, STSAFEA_MAC_NONE, STSAFEA_ENCRYPTION_NONE));
//
//  /* Verify signature */
//  if (StatusCode == 0)
//  {
//    /* Build both R & S MPI signature */
//    mbedtls_mpi R;
//    mbedtls_mpi S;
//
//    mbedtls_mpi_init(&R);
//    mbedtls_mpi_init(&S);
//
//    STS_CHK(StatusCode, mbedtls_mpi_read_binary(&R, SignR.Data, SignR.Length));
//    STS_CHK(StatusCode, mbedtls_mpi_read_binary(&S, SignS.Data, SignS.Length));
//
//    printf("  Verify the generated signature's validity using cryptographic library with the public key of STSAFE A110 Slot 0 key pair found in the leaf certificate\r\n");
//
//    /* Verify signature */
//    STS_CHK(StatusCode, mbedtls_ecdsa_verify(&ctx->grp, Hash, sizeof(Hash), &ctx->Q, &R, &S));
//
//    mbedtls_mpi_free(&R);
//    mbedtls_mpi_free(&S);
//  }

  return StatusCode;
}

/**
 * @brief  Process completed callback.
 * @param  hpka PKA handle
 * @retval None
 */
//void HAL_PKA_OperationCpltCallback(PKA_HandleTypeDef *hpka)
//{
//  operationComplete = 1;
//}
//
///**
// * @brief  Error callback.
// * @param  hpka PKA handle
// * @retval None
// */
//void HAL_PKA_ErrorCallback(PKA_HandleTypeDef *hpka)
//{
//
//}

/***************** Authentication *******************/
int32_t Authentication(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;
//  mbedtls_ecdsa_context ctx;

  LOG("Authentication of STSAFE A110 device\r\n");

  /* Build ECDSA context */
//  mbedtls_ecdsa_init(&ctx);
  /* Extract & verify X509 Certificate */
  STS_CHK(StatusCode, ExtractParseVerifyCertificate(handle));

//  /* Peripheral Authentication */
//  STS_CHK(StatusCode, PeripheralAuthentication(handle, &ctx));
//
//  mbedtls_ecdsa_free(&ctx);

  LOG("Peripheral authentication status: (0 is success): %d\r\n", (int) StatusCode);

  return StatusCode;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
