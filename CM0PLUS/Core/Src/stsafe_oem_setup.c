/*
 * --------------------------------------------------------------------
 * OEM STSAFE Peripheral Setup Prior to Releasing the Product to Market
 * --------------------------------------------------------------------
 */

#include "stsafe_oem_setup.h"

static OEM_Status_t OEM_STSafeA110_GenerateLocalEnvelopeKeys(StSafeA_Handle_t *pStSafeA);
static OEM_Status_t OEM_STSafeA110_GenerateHostCipherMACKey(StSafeA_Handle_t *pStSafeA);
static OEM_Status_t OEM_STSafeA110_ZonePutCertificate(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint8_t *certificate, uint16_t certificate_size);

/**
 * @brief   OEM_PrintHexDerToHexArray()
 *          Get as input a string of the DER certificate in HEX and print it as a HEX array.
 *
 * @note    It is only useful to make it easier when having a DER file that needs to be used a a C array.
 *          The output will be 16 HEX bytes per row.
 *
 * @example A DER HEX string like "5EFA230C" will be printed as "0x5E,0xFA,0x23,0x0C"
 *
 * @param   hex_der: A pointer to the string containing the DER in HEX.
 *
 * @retval  OEM_OK if success, an error code otherwise.
 */
OEM_Status_t OEM_PrintHexDerToHexArray(char *hex_der)
{
  int i, j;

  OEM_Status_t OEM_status = OEM_OK;

  uint32_t remain_bytes = strlen(hex_der) % 32;
  uint32_t certificate_size = strlen(hex_der);
  uint32_t rows = (uint32_t) certificate_size / 32;

  // Print all the full rows.
  for (i = 0; i < rows; i++)
  {
    for (j = 0; j < 16; j++)
    {
      LOG("0x%c%c,", hex_der[(i * 32) + (j * 2)], hex_der[(i * 32) + (j * 2) + 1]);
    }

    LOG("\r\n");
  }

  // Print the remaining bytes that are not part of a full row except for the last byte.
  for (j = 0; j < ((remain_bytes / 2) - 1); j++)
  {
    LOG("0x%c%c,", hex_der[(rows * 32) + (j * 2)], hex_der[(rows * 32) + (j * 2) + 1]);
  }

  // Print the last byte.
  LOG("0x%c%c", hex_der[(rows * 32) + (j * 2)], hex_der[(rows * 32) + (j * 2) + 1]);

  LOG("\r\n");

  return OEM_status;
}

/**
 * @brief   OEM_STSafeA110_GenerateLocalEnvelopeKeys()
 *          This function requests from the STSAFE A110 to generate the two local envelope keys if not present.
 *
 * @note    The Local Envelope Key Slot 0 will generate a 128-bit key.
 *          The Local Envelope Key Slot 1 will generate a 256-bit key.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 *
 * @retval  OEM_OK if success, an error code otherwise.
 */
static OEM_Status_t OEM_STSafeA110_GenerateLocalEnvelopeKeys(StSafeA_Handle_t *pStSafeA)
{
  OEM_Status_t OEM_status = OEM_OK;
  StSafeA_ResponseCode_t STSAFE_status = STSAFEA_OK;

  StSafeA_LocalEnvelopeKeyTableBuffer_t LocalEnvelopeKeyTable;
  StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t LocalEnvelopeInfoSlot0, LocalEnvelopeInfoSlot1;

  LOG("Querying the STSAFE A110 slots for local envelope keys presence\r\n\r\n");

  STS_CHK(STSAFE_status, (int32_t)StSafeA_LocalEnvelopeKeySlotQuery(pStSafeA, &LocalEnvelopeKeyTable, &LocalEnvelopeInfoSlot0, &LocalEnvelopeInfoSlot1, STSAFEA_MAC_NONE));

  LOG("Summary of the %d found Envelope Key Slots:\r\n\r\n", LocalEnvelopeKeyTable.NumberOfSlots);

  LOG("| Slot | Key Presence | Key Length |\r\n");
  LOG("|   %d  |       %d      |     %2d     |\r\n", LocalEnvelopeInfoSlot0.SlotNumber, LocalEnvelopeInfoSlot0.PresenceFlag, LocalEnvelopeInfoSlot0.KeyLength ? 32 : 16);
  LOG("|   %d  |       %d      |     %2d     |\r\n\r\n", LocalEnvelopeInfoSlot1.SlotNumber, LocalEnvelopeInfoSlot1.PresenceFlag, LocalEnvelopeInfoSlot1.KeyLength ? 32 : 16);

  // If not already present, generate a 128-bit local envelope key in local envelope key slot 0.
  if ((STSAFE_status == 0) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot0.SlotNumber == 0U) && (LocalEnvelopeInfoSlot0.PresenceFlag == 0U))
  {
    LOG("Local Envelope Key Slot 0 is empty\r\nCommand the STSAFE A110 to generate a 128-bit local envelope key for slot 0\r\n");

    STSAFE_status = (int32_t) StSafeA_GenerateLocalEnvelopeKey(pStSafeA, STSAFEA_KEY_SLOT_0, STSAFEA_KEY_TYPE_AES_128, NULL, 0U, STSAFEA_MAC_NONE);
  }

  // If not already present, generate a 256-bit local envelope key in local envelope key slot 1.
  if ((STSAFE_status == 0) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot1.SlotNumber == 1U) && (LocalEnvelopeInfoSlot1.PresenceFlag == 0U))
  {
    LOG("Local Envelope Key Slot 1 is empty\r\nCommand the STSAFE A110 to generate a 256-bit local envelope key for slot 1\r\n");

    STSAFE_status = (int32_t) StSafeA_GenerateLocalEnvelopeKey(pStSafeA, STSAFEA_KEY_SLOT_1, STSAFEA_KEY_TYPE_AES_256, NULL, 0U, STSAFEA_MAC_NONE);
  }

  return OEM_status;
}

/*
 * Check the presence of the host MAC and cipher keys.
 * If they are not present, put the desired keys to the Host Key Slot of the STSAFE A110 peripheral.
 */

/**
 * @brief   OEM_STSafeA110_GenerateHostCipherMACKey()
 *          This function requests from the STSAFE A110 to generate the host's MAC and cipher keys if not present.
 *
 * @note    No notes currently.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 *
 * @retval  OEM_OK if success, an error code otherwise.
 */
static OEM_Status_t OEM_STSafeA110_GenerateHostCipherMACKey(StSafeA_Handle_t *pStSafeA)
{
  OEM_Status_t OEM_status = OEM_OK;
  StSafeA_ResponseCode_t STSAFE_status = STSAFEA_OK;

  uint32_t index;
  uint64_t ptr;
  StSafeA_HostKeySlotBuffer_t HostKeySlot;

// @formatter:off
  uint8_t Host_MAC_Cipher_Key[2U * STSAFEA_HOST_KEY_LENGTH] =
  {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, /* Host MAC key */
    0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88 /* Host cipher key */
  };
// @formatter:on

  if (!(IS_FLASH_PAGE(PAGE_NUMBER)))
  {
    LOG("Flash page out of range\r\n");

    return STATUS_FLASH_RANGE_ERROR;
  }

  LOG("Querying the STSAFE A110 host MAC and cipher keys presence\r\n\r\n");

  /* Check if host cipher key & host MAC key are populated */
  STS_CHK(STSAFE_status, (int32_t)StSafeA_HostKeySlotQuery(pStSafeA, &HostKeySlot, STSAFEA_MAC_NONE));

  LOG("Summary of the Host Key Slot:\r\n\r\n");

  LOG("| Key Presence | Key Length | CMAC Sequence Counter |\r\n");
  LOG("|      %d       |     %2d     |  %20d |\r\n\r\n", HostKeySlot.HostKeyPresenceFlag, HostKeySlot.Length ? 32 : 16, (int) HostKeySlot.HostCMacSequenceCounter);

  // Enter if no host MAC and cipher keys are populated.
  if ((STSAFE_status == 0) && (HostKeySlot.HostKeyPresenceFlag == 0U))
  {
    LOG("Put the host MAC and cipher keys to the STSAFE A110 Host Key Slot\r\n");

    /* Send both keys to STSAFE */
    STS_CHK(STSAFE_status, (int32_t)StSafeA_PutAttribute(pStSafeA, STSAFEA_TAG_HOST_KEY_SLOT, Host_MAC_Cipher_Key, 2U * STSAFEA_HOST_KEY_LENGTH, STSAFEA_MAC_NONE));

    LOG("Store the host MAC and cipher keys in the flash memory\r\n");

    // Save the host MAC and cipher keys to the FLASH.
    STS_CHK(STSAFE_status, (int32_t )HAL_FLASH_Unlock());

    if (STSAFE_status == 0)
    {
      __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_PROGERR | FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR | FLASH_FLAG_SIZERR | FLASH_FLAG_PGSERR | FLASH_FLAG_MISERR | FLASH_FLAG_FASTERR | FLASH_FLAG_RDERR | FLASH_FLAG_OPTVERR);
      FLASH_EraseInitTypeDef FlashErase = {FLASH_TYPEERASE_PAGES, PAGE_NUMBER, 1};

      uint32_t PageError;

      STSAFE_status = (int32_t) HAL_FLASHEx_Erase(&FlashErase, &PageError);

      if ((STSAFE_status == 0) && PageError == 0xFFFFFFFFU)
      {
	for (index = 0; index < 2U * STSAFEA_HOST_KEY_LENGTH; index += 8U)
	{
	  (void) memcpy(&ptr, &Host_MAC_Cipher_Key[index], sizeof(ptr));

	  if (HAL_OK != HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, FLASH_BASE + FLASH_SIZE - 2U * STSAFEA_HOST_KEY_LENGTH + index, ptr))
	  {
	    STSAFE_status++;
	    break;
	  }
	}
      }

      STS_CHK(STSAFE_status, (int32_t )HAL_FLASH_Lock());
    }
  }

  return OEM_status;;
}

/**
 * @brief   OEM_STSafeA110_ZonePutCertificate()
 *          This function writes a certificate to a specified offset of a data partition zone.
 *
 * @note    No notes currently.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 *
 * @retval  OEM_OK if success, an error code otherwise.
 */
static OEM_Status_t OEM_STSafeA110_ZonePutCertificate(StSafeA_Handle_t *pStSafeA, uint8_t zone, uint16_t offset, uint8_t *certificate, uint16_t certificate_size)
{
  OEM_Status_t OEM_status = OEM_OK;
  StSafeA_ResponseCode_t STSAFE_status = STSAFEA_OK;

  StSafeA_LVBuffer_t pInLVData;

  pInLVData.Length = certificate_size;
  pInLVData.Data = (uint8_t *) certificate;

  LOG("Certificate size: %d\r\n", certificate_size);

  // Write the certificate to the specified data partition zone.
  STS_CHK(STSAFE_status, (int32_t)StSafeA_Update(pStSafeA, STSAFEA_FLAG_TRUE, STSAFEA_FLAG_FALSE, STSAFEA_FLAG_FALSE, STSAFEA_AC_ALWAYS, zone, offset, &pInLVData, STSAFEA_MAC_HOST_CRMAC));

  if (STSAFE_status == STSAFEA_OK)
  {
    LOG("Writing certificate to Data Partition Zone %d: OK\r\n", zone);
  }
  else
  {
    LOG("Writing certificate to Data Partition Zone %d: Failed[%d]\r\n", zone, STSAFE_status);
  }

  return OEM_status;
}

/**
 * @brief   OEM_STSafeA110Setup()
 *          This function makes the initial set up of the STSAFE 110 peripheral.
 *          So far it makes the following configurations:
 *          - Check and generate the Host's MAC and cipher keys if not present.
 *          - Check and generate the local envelope keys if not present.
 *          - Store the trusted developer's certificate used to verify the user application.
 *
 * @note    This function should be executed in the OEM side prior to releasing the product to market.
 *
 * @param   pStSafeA: STSAFE-A1xx object pointer.
 *
 * @retval  OEM_OK if success, an error code otherwise.
 */
OEM_Status_t OEM_STSafeA110_Setup(StSafeA_Handle_t *pStSafeA)
{
  OEM_Status_t OEM_status = OEM_OK;

  uint8_t developer_certificate[] = {DEVELOPER_CERTIFICATE};

  uint16_t certificate_size = sizeof(developer_certificate);

  // Generate the STSAFE A110 local envelope keys.
  OEM_STSafeA110_GenerateLocalEnvelopeKeys(pStSafeA);

  // Generate the STSAFE A110 host MAC and cipher keys.
  OEM_STSafeA110_GenerateHostCipherMACKey(pStSafeA);

  // Write the developer's certificate to data partition zone 2.
  OEM_STSafeA110_ZonePutCertificate(pStSafeA, ZONE2, 0, developer_certificate, certificate_size);

  return OEM_status;
}
