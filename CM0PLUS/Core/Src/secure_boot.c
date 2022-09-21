/*
 * --------------------------------
 * Secure Bootloader Implementation
 * --------------------------------
 */

#include "secure_boot.h"

uint8_t operation_status = 0;

static SB_Status_t SB_GetCertificateSize(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint16_t *certificate_size);
static SB_Status_t SB_RetrieveCertificate(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint8_t *retrieved_certificate);
static SB_Status_t SB_ParseCertificate(uint8_t *raw_certificate, intCert_stt *parsed_certificate);
static SB_Status_t SB_VerifyCertificate(intCert_stt *cert_to_verify, intCert_stt *ca_cert);
static SB_Status_t SB_VerifySTSAFEPeripheral(StSafeA_Handle_t *pStSafeA, intCert_stt *leaf_certificate);
static SB_Status_t SB_VerifyUserApplication(intCert_stt *developer_certificate);

void SB_JumpToApplication(uint32_t address_offset);

/**
 * @brief   SB_GetCertificateSize()
 *          This command reads a specified data partition zone to retrieve the size of a certificate if available.
 *
 * @note    No notes currently.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 * @param   zone: The data partition zone where the certificate is located.
 * @param   offset: The offset inside the data partition zone where the certificate is located.
 * @param   certificate_size: Used to store the retrieved certificate size that should be returned to the caller function.
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
static SB_Status_t SB_GetCertificateSize(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint16_t *certificate_size)
{
  SB_Status_t SB_status = SB_OK;
  StSafeA_ResponseCode_t STSAFE_status = STSAFEA_OK;

  StSafeA_LVBuffer_t sts_read;
  uint8_t data_sts_read[NUMBER_OF_BYTES_TO_EXTRACT_CERTIFICATE_SIZE];
  uint16_t calculated_certificate_size = 0;

  sts_read.Length = NUMBER_OF_BYTES_TO_EXTRACT_CERTIFICATE_SIZE;
  sts_read.Data = data_sts_read;

  // Extract the first 4 bytes of the STSAFE A110 X509 certificate which provide the size of the certificate.
  STS_CHK(STSAFE_status, (int32_t) StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, offset, NUMBER_OF_BYTES_TO_EXTRACT_CERTIFICATE_SIZE, NUMBER_OF_BYTES_TO_EXTRACT_CERTIFICATE_SIZE, &sts_read, STSAFEA_MAC_NONE));

  // Calculate the size of the certificate to receive from the STSAFE A110 device.
  if (STSAFE_status == STSAFEA_OK)
  {
    switch (sts_read.Data[1])
    {
      case 0x81U:
	calculated_certificate_size = (uint16_t) sts_read.Data[2] + 3U;
	break;

      case 0x82U:
	calculated_certificate_size = (((uint16_t) sts_read.Data[2]) << 8) + sts_read.Data[3] + 4U;
	break;

      default:
	if (sts_read.Data[1] < 0x81U)
	{
	  calculated_certificate_size = sts_read.Data[1];
	}
	break;
    }

    // Return error if a certificate was not found
    if (calculated_certificate_size == 0)
    {
      return STATUS_CERT_NOT_FOUND;
    }
  }

  // Store the certificate size that will be accessible by the caller function.
  *certificate_size = calculated_certificate_size;

  return SB_status;
}

/**
 * @brief   SB_RetrieveCertificate()
 *          Read a certificate from a data partition zone.
 *
 * @note    No notes currently.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 * @param   zone: The data partition zone where the certificate is located.
 * @param   offset: The offset inside the data partition zone where the certificate is located.
 * @param   retrieved_certificate: The certificate in raw bytes that must be returned to the caller function.
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
static SB_Status_t SB_RetrieveCertificate(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint8_t *retrieved_certificate)
{
  uint16_t current_offset = offset;
  uint8_t i;

  SB_Status_t SB_status = SB_OK;
  StSafeA_ResponseCode_t STSAFE_status = STSAFEA_OK;

  StSafeA_LVBuffer_t sts_read_cert;
  uint16_t certificate_size = 0;

  // Get the size of the certificate.
  SB_status = SB_GetCertificateSize(pStSafeA, zone, offset, &certificate_size);

  // Extract the X509 certificate from STSAFE A110 Zone.
  if (SB_status == SB_OK)
  {
    LOG("  Certificate size: %s%d bytes%s\r\n", LIGHT_CYAN, certificate_size, NO_COLOR);

    if (certificate_size > MAX_ZONE_READ_BYTES_WITHOUT_RMAC)
    {
      sts_read_cert.Length = MAX_ZONE_READ_BYTES_WITHOUT_RMAC;
      sts_read_cert.Data = retrieved_certificate;

      for (i = 0; i < (certificate_size / MAX_ZONE_READ_BYTES_WITHOUT_RMAC); i++)
      {
	// Extract the X509 certificate from STSAFE A110 Zone.
	STS_CHK(STSAFE_status, (int32_t)StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, current_offset, MAX_ZONE_READ_BYTES_WITHOUT_RMAC, MAX_ZONE_READ_BYTES_WITHOUT_RMAC, &sts_read_cert, STSAFEA_MAC_NONE));

	current_offset += MAX_ZONE_READ_BYTES_WITHOUT_RMAC;

	sts_read_cert.Data += MAX_ZONE_READ_BYTES_WITHOUT_RMAC;
	sts_read_cert.Length = MAX_ZONE_READ_BYTES_WITHOUT_RMAC;

	if (STSAFE_status != STSAFEA_OK)
	{
	  return SB_CERT_NOT_FOUND;
	}
      }

      if (STSAFE_status == STSAFEA_OK)
      {
	sts_read_cert.Length = certificate_size % MAX_ZONE_READ_BYTES_WITHOUT_RMAC;

	if (sts_read_cert.Length != 0U)
	{
	  // Extract the X509 certificate from STSAFE A110 Zone.
	  STS_CHK(STSAFE_status, (int32_t)StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, current_offset, (certificate_size % MAX_ZONE_READ_BYTES_WITHOUT_RMAC), (certificate_size % MAX_ZONE_READ_BYTES_WITHOUT_RMAC), &sts_read_cert, STSAFEA_MAC_NONE));

	  if (STSAFE_status != STSAFEA_OK)
	  {
	    return SB_CERT_NOT_FOUND;
	  }
	}
      }
    }
    else
    {
      sts_read_cert.Length = certificate_size;
      sts_read_cert.Data = retrieved_certificate;

      // Extract the X509 certificate from STSAFE A110 Zone.
      STS_CHK(STSAFE_status, (int32_t)StSafeA_Read(pStSafeA, 0, 0, STSAFEA_AC_ALWAYS, zone, 0, certificate_size, certificate_size, &sts_read_cert, STSAFEA_MAC_NONE));

      if (STSAFE_status != STSAFEA_OK)
      {
	return SB_CERT_NOT_FOUND;
      }
    }
  }

  return SB_status;
}

/**
 * @brief   SB_ParseCertificate()
 *          Parse a certificate from raw data.
 *
 * @note    No notes currently.
 *
 * @param   raw_certificate: the certificate in raw bytes to be parsed (input).
 * @param   parsed_certificate: the parsed certificate (output).
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
static SB_Status_t SB_ParseCertificate(uint8_t *raw_certificate, intCert_stt *parsed_certificate)
{
  SB_Status_t SB_status = SB_OK;

  // Initialize the certificate.
  initIntCert(parsed_certificate);

  // Parse the certificate.
  SB_status = parseCert(raw_certificate, parsed_certificate, NULL);

  if (SB_status != SB_OK)
  {
    return STATUS_CERT_PARSE_ERROR;
  }

  return SB_status;
}

/**
 * @brief   SB_VerifyCertificate()
 *          Verify a certificate's validity according to a trusted CA certificate.
 *
 * @note    No notes currently.
 *
 * @param   cert_to_verify: The certificate that we need to verify (MUST be parsed with SB_ParseCertificate() first).
 * @param   ca_cert: The CA certificate that we trust (MUST be parsed with SB_ParseCertificate() first).
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
static SB_Status_t SB_VerifyCertificate(intCert_stt *cert_to_verify, intCert_stt *ca_cert)
{
  SB_Status_t SB_status = SB_OK;

  PKA_ECDSAVerifInTypeDef PKA_parameters = {0};

  uint8_t hash_digest[SHA256_SIZE] = {0};

  mbedtls_sha256(cert_to_verify->tbs, cert_to_verify->tbsSize, hash_digest, SHA256);

  // Set PKA fixed parameters.
  PKA_parameters.primeOrderSize = prime256v1_Order_len;
  PKA_parameters.modulusSize = prime256v1_Prime_len;
  PKA_parameters.coefSign = prime256v1_A_sign;
  PKA_parameters.coef = prime256v1_absA;
  PKA_parameters.modulus = prime256v1_Prime;
  PKA_parameters.basePointX = prime256v1_GeneratorX;
  PKA_parameters.basePointY = prime256v1_GeneratorY;
  PKA_parameters.primeOrder = prime256v1_Order;

  // Set PKA signature related parameters.
  PKA_parameters.pPubKeyCurvePtX = ca_cert->PubKey.pX;
  PKA_parameters.pPubKeyCurvePtY = ca_cert->PubKey.pY;
  PKA_parameters.RSign = cert_to_verify->Sign.pR;
  PKA_parameters.SSign = cert_to_verify->Sign.pS;
  PKA_parameters.hash = hash_digest;

  /* Launch the verification */
  if (HAL_PKA_ECDSAVerif_IT(&hpka, &PKA_parameters) != HAL_OK)
  {
    LOG("  PKA ECDSA verification process failed\r\n");

    return SB_PKA_VERIFY_PROCESS_ERROR;
  }

  // Wait until a PKA interrupt is triggered.
  while (operation_status == 0)
  {
  }

  /* Compare to expected result */
  if (HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) != PKA_CERT_VERIFY_OK)
  {
    LOG("  PKA report: %sInvalid Certificate%s\r\n", YELLOW, NO_COLOR);
  }
  else
  {
    LOG("  PKA report: %sValid Certificate%s\r\n", GREEN, NO_COLOR);
  }

  operation_status = 0;

  return SB_status;
}

/**
 * @brief   SB_VerifySTSAFEPeripheral()
 *          Verify a STSAFE A110 peripheral according to its leaf certificate.
 *
 * @note    No notes currently.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 * @param   leaf_certificate: The leaf certificate that is retrieved from the STSAFE A110 peripheral.
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
static SB_Status_t SB_VerifySTSAFEPeripheral(StSafeA_Handle_t *pStSafeA, intCert_stt *leaf_certificate)
{
  SB_Status_t SB_status = SB_OK;
  StSafeA_ResponseCode_t STSAFE_status = STSAFEA_OK;

  PKA_ECDSAVerifInTypeDef PKA_parameters = {0};

  uint8_t hash_digest[SHA256_SIZE] = {0};

  StSafeA_LVBuffer_t SignR, SignS;
  uint8_t data_SignR[STSAFEA_XYRS_ECDSA_SHA256_LENGTH];
  SignR.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
  SignR.Data = data_SignR;
  uint8_t data_SignS[STSAFEA_XYRS_ECDSA_SHA256_LENGTH];
  SignS.Length = STSAFEA_XYRS_ECDSA_SHA256_LENGTH;
  SignS.Data = data_SignS;

  // Command the STSAFE A110 peripheral to generate 32 random bytes.
  STS_CHK(STSAFE_status, (int32_t) GenerateUnsignedChallenge(pStSafeA, (uint16_t) SHA256_SIZE, hash_digest));

  LOG("  Hash the random number\r\n");

  // Generate SHA256 digest from the random bytes.
  mbedtls_sha256(hash_digest, SHA256_SIZE, hash_digest, SHA256);

  LOG("  Request from STSAFE A110 to generate a signature of the hash\r\n");

  // Generate signature of the hash digest.
  STS_CHK(STSAFE_status, (int32_t)StSafeA_GenerateSignature(pStSafeA, STSAFEA_KEY_SLOT_0, hash_digest, STSAFEA_SHA_256, STSAFEA_XYRS_ECDSA_SHA256_LENGTH, &SignR, &SignS, STSAFEA_MAC_NONE, STSAFEA_ENCRYPTION_NONE));

  if (STSAFE_status == STSAFEA_OK)
  {
    // Set PKA fixed parameters.
    PKA_parameters.primeOrderSize = prime256v1_Order_len;
    PKA_parameters.modulusSize = prime256v1_Prime_len;
    PKA_parameters.coefSign = prime256v1_A_sign;
    PKA_parameters.coef = prime256v1_absA;
    PKA_parameters.modulus = prime256v1_Prime;
    PKA_parameters.basePointX = prime256v1_GeneratorX;
    PKA_parameters.basePointY = prime256v1_GeneratorY;
    PKA_parameters.primeOrder = prime256v1_Order;

    // Set PKA signature related parameters.
    PKA_parameters.pPubKeyCurvePtX = leaf_certificate->PubKey.pX;
    PKA_parameters.pPubKeyCurvePtY = leaf_certificate->PubKey.pY;
    PKA_parameters.RSign = SignR.Data;
    PKA_parameters.SSign = SignS.Data;
    PKA_parameters.hash = hash_digest;

    /* Launch the verification */
    if (HAL_PKA_ECDSAVerif_IT(&hpka, &PKA_parameters) != HAL_OK)
    {
      LOG("  PKA ECDSA verification process failed\r\n");

      return SB_PKA_VERIFY_PROCESS_ERROR;
    }

    // Wait until a PKA interrupt is triggered.
    while (operation_status == 0)
    {
    }

    /* Compare to expected result */
    if (HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) != PKA_CERT_VERIFY_OK)
    {
      LOG("  PKA report: %sInvalid STSAFE A110 peripheral%s\r\n", YELLOW, NO_COLOR);
    }
    else
    {
      LOG("  PKA report: %sValid STSAFE A110 peripheral%s\r\n", GREEN, NO_COLOR);
    }
  }

  operation_status = 0;

  return SB_status;
}

/**
 * @brief   SB_VerifyUserApplication()
 *          Verify the user application based on the developer's certificate.
 *
 * @note    The user application is supposed to signed with the private key of the trusted developer.
 *
 * @param   developer_certificate: The certificate of the developer which is used to verify the user application signature.
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
static SB_Status_t SB_VerifyUserApplication(intCert_stt *developer_certificate)
{
  SB_Status_t SB_status = SB_OK;

  PKA_ECDSAVerifInTypeDef PKA_parameters = {0};

  uint8_t hash_digest[SHA256_SIZE] = {0};

  uint8_t SignRLengthPosition = 0;
  uint8_t SignSLengthPosition = 0;

  uint8_t SignRSize = 0;
  uint8_t SignSSize = 0;

  uint8_t SignRPosition = 0;
  uint8_t SignSPosition = 0;

  UserAppTrustInfo_t *user_app_trust_info = (UserAppTrustInfo_t*) (FLASH_BASE + USER_APP_TRUST_INFO_OFFSET);

  uint8_t *fw_size_ptr = user_app_trust_info->FirmwareSize;
  uint32_t firmware_size = (fw_size_ptr[0] << 24) | (fw_size_ptr[1] << 16) | (fw_size_ptr[2] << 8) | (fw_size_ptr[3]);

  uint8_t *magic_number_ptr = user_app_trust_info->MagicNumber;
  uint32_t magic_number = (magic_number_ptr[0] << 24) | (magic_number_ptr[1] << 16) | (magic_number_ptr[2] << 8) | (magic_number_ptr[3]);

  uint8_t *address_offset_ptr = user_app_trust_info->AddressOffset;
  uint32_t address_offset = (address_offset_ptr[0] << 24) | (address_offset_ptr[1] << 16) | (address_offset_ptr[2] << 8) | (address_offset_ptr[3]);

  SignRLengthPosition = 3;
  SignSLengthPosition = user_app_trust_info->FirmwareSignature[3] + SignRLengthPosition + 2;

  SignRSize = user_app_trust_info->FirmwareSignature[SignRLengthPosition];
  SignSSize = user_app_trust_info->FirmwareSignature[SignSLengthPosition];

  uint8_t signR[SignRSize];
  uint8_t signS[SignSSize];

  /*
   * ECDSA requires the values to be unsigned integers.
   * Thus the r and S-values are padded with an extra 0x00 byte if the highest bit indicates a negative value (highest bit is 1).
   * If either the r or the S-value has the highest bit set then it needs extra padding of 1 byte which results in a 71-byte-signature.
   * If the highest bits of both values are set, then both need padding of one byte each resulting in a 72-byte-signature.
   *
   * In other words, if the r sign requires 1 byte padding it ends up being 33 bytes long.
   * The same applies for the s sign.
   *
   * The PKA accelerator, though, does require only the 32 bytes of the r and s signs without the padding.
   * If the padding is present the PKA will fail to verify the signature.
   *
   * The next if statements check the lengths of the r and s signs and if found to be 33 they only copy the clear r or s sign without the padding.
   */
  SignRPosition = SignRLengthPosition + 1;
  SignSPosition = SignSLengthPosition + 1;

  if(SignRSize == 33)
  {
    SignRPosition += 1;
  }

  if(SignSSize == 33)
  {
    SignSPosition += 1;
  }

  memcpy(signR, (user_app_trust_info->FirmwareSignature) + (SignRPosition), 32);
  memcpy(signS, (user_app_trust_info->FirmwareSignature) + (SignSPosition), 32);

  if ((magic_number == MAGIC_NUMBER) && (firmware_size > 0))
  {
    LOG("  Magic number and firmware size valid\r\n");

    LOG("  %sMagic Number:%s   0x%08X\r\n", LIGHT_CYAN, NO_COLOR, magic_number);
    LOG("  %sFirmware size:%s  %d [0x%08X]\r\n", LIGHT_CYAN, NO_COLOR, firmware_size, firmware_size);
    LOG("  %sAddress Offset:%s 0x%08X\r\n", LIGHT_CYAN, NO_COLOR, address_offset);

    // Generate SHA256 digest from the random bytes.
    mbedtls_sha256((uint8_t*) (address_offset), firmware_size, hash_digest, SHA256);

    LOG("  User application hash:\r\n  ");

    for (int i = 0; i < 32; i++)
    {
      LOG("%02X", hash_digest[i]);
    }

    LOG("\r\n");

    if (SB_status == SB_OK)
    {
      // Set PKA fixed parameters.
      PKA_parameters.primeOrderSize = prime256v1_Order_len;
      PKA_parameters.modulusSize = prime256v1_Prime_len;
      PKA_parameters.coefSign = prime256v1_A_sign;
      PKA_parameters.coef = prime256v1_absA;
      PKA_parameters.modulus = prime256v1_Prime;
      PKA_parameters.basePointX = prime256v1_GeneratorX;
      PKA_parameters.basePointY = prime256v1_GeneratorY;
      PKA_parameters.primeOrder = prime256v1_Order;

      // Set PKA signature related parameters.
      PKA_parameters.pPubKeyCurvePtX = developer_certificate->PubKey.pX;
      PKA_parameters.pPubKeyCurvePtY = developer_certificate->PubKey.pY;
      PKA_parameters.RSign = signR;
      PKA_parameters.SSign = signS;
      PKA_parameters.hash = hash_digest;

      /* Launch the verification */
      if (HAL_PKA_ECDSAVerif_IT(&hpka, &PKA_parameters) != HAL_OK)
      {
	LOG("  PKA ECDSA verification process failed\r\n");

	return SB_PKA_VERIFY_PROCESS_ERROR;
      }

      // Wait until a PKA interrupt is triggered.
      while (operation_status == 0)
      {
      }

      // Compare to expected result.
      if (HAL_PKA_ECDSAVerif_IsValidSignature(&hpka) != PKA_CERT_VERIFY_OK)
      {
	LOG("  PKA report: %sInvalid user application%s\r\n", YELLOW, NO_COLOR);

	LOG("%s%s%s\r\n", YELLOW, INVALID_BANNER, NO_COLOR);

	return SB_INVALID_USER_APP;
      }
      else
      {
	LOG("  PKA report: %sValid user application%s\r\n", GREEN, NO_COLOR);

	LOG("%s%s%s\r\n", GREEN, VALID_BANNER, NO_COLOR);

	SB_JumpToApplication(address_offset);
      }
    }
  }
  else
  {
    LOG("  %sNo user application found%s\r\n", YELLOW, NO_COLOR);

    return SB_INVALID_MAGIC_NUMBER;
  }

  operation_status = 0;

  return SB_status;
}

/**
 * @brief   SB_JumpToApplication()
 *          This function performs the jump to the user application in flash.
 *          It first, carries out the following operations
 *          - De-initialize the clock and peripheral configuration.
 *          - Stop the systick.
 *          - Then, call the RSSLIB_PFUNC->CloseExitHDP() function that does the following:
 *            - Closes the Hide Protection area (HDP).
 *            - Jumps to the trusted user application.
 *
 * @note    No notes currently.
 *
 * @param   address_offset: The address offset in flash to jump to (location of the trusted user application).
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
void SB_JumpToApplication(uint32_t address_offset)
{
    LOG("  %sJumping to application%s\r\n\r\n", LIGHT_CYAN, NO_COLOR);

    HAL_RCC_DeInit();
    HAL_DeInit();

    SysTick->CTRL = 0;
    SysTick->LOAD = 0;
    SysTick->VAL  = 0;

    RSSLIB_PFUNC->CloseExitHDP(RSSLIB_HDP_AREA1, address_offset);
}

/**
 * @brief  Process completed callback.
 * @param  hpka PKA handle
 * @retval None
 */
void HAL_PKA_OperationCpltCallback(PKA_HandleTypeDef *hpka)
{
  operation_status = PKA_OPERATION_COMPLETE_CALLBACK;
}

/**
 * @brief  Error callback.
 * @param  hpka PKA handle
 * @retval None
 */
void HAL_PKA_ErrorCallback(PKA_HandleTypeDef *hpka)
{
  operation_status = PKA_OPERATION_ERROR_CALLBACK;
}

/**
 * @brief   SB_Boot()
 *          Boot in a secure manner, that is:
 *          - Authenticate the STSAFE A110 peripheral and its certificate.
 *          - Authenticate the user application.
 *          - Jump to the user application.
 *
 * @note    No notes currently.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 *
 * @retval  SB_OK if success, an error code otherwise.
 */
SB_Status_t SB_Boot(StSafeA_Handle_t *pStSafeA)
{
  SB_Status_t SB_status = SB_OK;

  uint8_t raw_leaf_certificate[MAX_CERTIFICATE_SIZE];
  uint8_t raw_CA_self_signed_certificate_SPL2[] = {CA_SELF_SIGNED_CERTIFICATE_01};
  uint8_t raw_developer_certificate[MAX_CERTIFICATE_SIZE];

  intCert_stt leaf_certificate;
  intCert_stt ca_certificate;
  intCert_stt developer_certificate;

  LOG("->Retrieve leaf certificate from zone 0\r\n");

  // Retrieve the STSAFE A110 leaf certificate from data partition zone 0.
  SB_RetrieveCertificate(pStSafeA, ZONE0, 0, raw_leaf_certificate);

  LOG("->Retrieve trusted developer's certificate from zone 2\r\n");

  // Retrieve the developer's certificate from data partition zone 2.
  SB_RetrieveCertificate(pStSafeA, ZONE2, 0, raw_developer_certificate);

  LOG("->Parse the leaf certificate\r\n");

  // Parse the leaf certificate.
  SB_ParseCertificate(raw_leaf_certificate, &leaf_certificate);

  LOG("->Parse the root CA certificate\r\n");

  // Parse the CA certificate.
  SB_ParseCertificate(raw_CA_self_signed_certificate_SPL2, &ca_certificate);

  LOG("->Parse the trusted developer's certificate\r\n");

  // Parse the developer's certificate.
  SB_ParseCertificate(raw_developer_certificate, &developer_certificate);

#if LOG_CERTS_ALLOWED == 1
  LOG("\r\nLeaf Certificate:\r\n");

  // Print the leaf certificate.
  printParsedCert(&leaf_certificate);

  LOG("\r\nCA Certificate:\r\n");

  // Print the CA certificate.
  printParsedCert(&ca_certificate);

  LOG("\r\nDeveloper Certificate:\r\n");

  // Print the developer's certificate.
  printParsedCert(&developer_certificate);
#endif

  LOG("->Verify leaf certificate based on root CA certificate\r\n");

  // Verify that the STSAFE A110 leaf certificate is signed by the trusted STMicroelectronic's CA certificate.
  SB_VerifyCertificate(&leaf_certificate, &ca_certificate);

  LOG("->Verify STSAFE A110 peripheral based on leaf certificate\r\n");

  // Verify that the STSAFE A110 peripheral can be trusted.
  SB_VerifySTSAFEPeripheral(pStSafeA, &leaf_certificate);

  LOG("->Verify user application based on developer's certificate\r\n");

  // Verify the signature of the user application before jumping in it.
  SB_VerifyUserApplication(&developer_certificate);

  return SB_status;
}

