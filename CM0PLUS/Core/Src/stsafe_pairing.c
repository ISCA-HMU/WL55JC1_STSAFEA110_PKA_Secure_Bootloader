/**
 ******************************************************************************
 * @file    pairing.c
 * @author  SMD application team
 * @version V3.1.2
 * @brief   Pairing use case using STSAFE-A.
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
#include <stdio.h>

#include "stm32wlxx_nucleo.h"

#include "stsafea_interface_conf.h"
#include "stsafe_pairing.h"
#include "stsafe_common.h"

#ifdef MCU_PLATFORM_INCLUDE
#include MCU_PLATFORM_INCLUDE
#endif /* MCU_PLATFORM_INCLUDE */

#include "stsafea_core.h"

#define PAGE_NUMBER 127

int32_t check_local_envelope_key(StSafeA_Handle_t *handle);
int32_t check_host_keys(StSafeA_Handle_t *handle);

/*
 * Check the presence of local envelope keys and generate if not present.
 *
 * ATTENTION: Remember that there are 2 Local Envelope Key Slots available.
 */
int32_t check_local_envelope_key(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;
  StSafeA_LocalEnvelopeKeyTableBuffer_t LocalEnvelopeKeyTable;
  StSafeA_LocalEnvelopeKeyInformationRecordBuffer_t LocalEnvelopeInfoSlot0, LocalEnvelopeInfoSlot1;

  printf("Querying the STSAFE A110 slots for local envelope keys presence\r\n\r\n");

  STS_CHK(StatusCode, (int32_t)StSafeA_LocalEnvelopeKeySlotQuery(handle, &LocalEnvelopeKeyTable, &LocalEnvelopeInfoSlot0, &LocalEnvelopeInfoSlot1, STSAFEA_MAC_NONE));

  printf("Summary of the %d found Envelope Key Slots:\r\n\r\n", LocalEnvelopeKeyTable.NumberOfSlots);

  printf("| Slot | Key Presence | Key Length |\r\n");
  printf("|   %d  |       %d      |     %2d     |\r\n", LocalEnvelopeInfoSlot0.SlotNumber, LocalEnvelopeInfoSlot0.PresenceFlag, LocalEnvelopeInfoSlot0.KeyLength ? 32 : 16);
  printf("|   %d  |       %d      |     %2d     |\r\n\r\n", LocalEnvelopeInfoSlot1.SlotNumber, LocalEnvelopeInfoSlot1.PresenceFlag, LocalEnvelopeInfoSlot1.KeyLength ? 32 : 16);

  // If not already present, generate a 128-bit local envelope key in local envelope key slot 0.
  if ((StatusCode == 0) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot0.SlotNumber == 0U) && (LocalEnvelopeInfoSlot0.PresenceFlag == 0U))
  {
    printf("Local Envelope Key Slot 0 is empty\r\nCommand the STSAFE A110 to generate a 128-bit local envelope key for slot 0\r\n");

    StatusCode = (int32_t) StSafeA_GenerateLocalEnvelopeKey(handle, STSAFEA_KEY_SLOT_0, STSAFEA_KEY_TYPE_AES_128, NULL, 0U, STSAFEA_MAC_NONE);
  }

  // If not already present, generate a 256-bit local envelope key in local envelope key slot 1.
  if ((StatusCode == 0) && (LocalEnvelopeKeyTable.NumberOfSlots != 0U) && (LocalEnvelopeInfoSlot1.SlotNumber == 1U) && (LocalEnvelopeInfoSlot1.PresenceFlag == 0U))
  {
    printf("Local Envelope Key Slot 1 is empty\r\nCommand the STSAFE A110 to generate a 256-bit local envelope key for slot 1\r\n");

    StatusCode = (int32_t) StSafeA_GenerateLocalEnvelopeKey(handle, STSAFEA_KEY_SLOT_1, STSAFEA_KEY_TYPE_AES_256, NULL, 0U, STSAFEA_MAC_NONE);
  }

  return StatusCode;
}

/*
 * Check the presence of the host MAC and cipher keys.
 * If they are not present, put the desired keys to the Host Key Slot of the STSAFE A110 peripheral.
 */
int32_t check_host_keys(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;

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
    printf("Flash page out of range\r\n");

    return STATUS_FLASH_RANGE_ERROR;
  }

  printf("Querying the STSAFE A110 host MAC and cipher keys presence\r\n\r\n");

  /* Check if host cipher key & host MAC key are populated */
  STS_CHK(StatusCode, (int32_t)StSafeA_HostKeySlotQuery(handle, &HostKeySlot, STSAFEA_MAC_NONE));

  printf("Summary of the Host Key Slot:\r\n\r\n");

  printf("| Key Presence | Key Length | CMAC Sequence Counter |\r\n");
  printf("|      %d       |     %2d     |  %20d |\r\n\r\n", HostKeySlot.HostKeyPresenceFlag, HostKeySlot.Length ? 32 : 16, (int) HostKeySlot.HostCMacSequenceCounter);

  // Enter if no host MAC and cipher keys are populated.
  if ((StatusCode == 0) && (HostKeySlot.HostKeyPresenceFlag == 0U))
  {
#if USE_HOST_KEYS_GENERATED_BY_STSAFE_A110 == 1
    // Generate 32 random bytes where the first 16 bytes will be used as the MAC key and the rest 16 bytes as the cipher key.
    STS_CHK(StatusCode, (int32_t)GenerateUnsignedChallenge(handle, 2 * STSAFEA_HOST_KEY_LENGTH, Host_MAC_Cipher_Key));
#endif

    printf("Put the host MAC and cipher keys to the STSAFE A110 Host Key Slot\r\n");

    /* Send both keys to STSAFE */
    STS_CHK(StatusCode, (int32_t)StSafeA_PutAttribute(handle, STSAFEA_TAG_HOST_KEY_SLOT, Host_MAC_Cipher_Key, 2U * STSAFEA_HOST_KEY_LENGTH, STSAFEA_MAC_NONE));

    printf("Store the host keys in the flash memory");

    // Save the host MAC and cipher keys to the FLASH.
    STS_CHK(StatusCode, (int32_t )HAL_FLASH_Unlock());

    if (StatusCode == 0)
    {
      __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_EOP | FLASH_FLAG_OPERR | FLASH_FLAG_PROGERR | FLASH_FLAG_WRPERR | FLASH_FLAG_PGAERR | FLASH_FLAG_SIZERR | FLASH_FLAG_PGSERR | FLASH_FLAG_MISERR | FLASH_FLAG_FASTERR | FLASH_FLAG_RDERR | FLASH_FLAG_OPTVERR);
      FLASH_EraseInitTypeDef FlashErase = {FLASH_TYPEERASE_PAGES, PAGE_NUMBER, 1};

      uint32_t PageError;

      StatusCode = (int32_t) HAL_FLASHEx_Erase(&FlashErase, &PageError);

      if ((StatusCode == 0) && PageError == 0xFFFFFFFFU)
      {
	for (index = 0; index < 2U * STSAFEA_HOST_KEY_LENGTH; index += 8U)
	{
	  (void) memcpy(&ptr, &Host_MAC_Cipher_Key[index], sizeof(ptr));

	  if (HAL_OK != HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, FLASH_BASE + FLASH_SIZE - 2U * STSAFEA_HOST_KEY_LENGTH + index, ptr))
	  {
	    StatusCode++;
	    break;
	  }
	}
      }

      STS_CHK(StatusCode, (int32_t )HAL_FLASH_Lock());
    }
  }

  return StatusCode;
}

int32_t Pairing(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;

  printf("Pairing the MCU with the STSAFE A110 module\r\n");

  /* Check local envelope key */
  STS_CHK(StatusCode, check_local_envelope_key(handle));

  /* Check cipher key & host CMAC key and provide flash sector where save both keys */
  STS_CHK(StatusCode, check_host_keys(handle));

  return StatusCode;
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
