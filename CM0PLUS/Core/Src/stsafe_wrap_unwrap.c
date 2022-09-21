/**
 ******************************************************************************
 * @file    wrap_unwrap.c
 * @author  SMD application team
 * @version V3.1.1
 * @brief   Wrap unwrap use case using STSAFE-A and MbedTLS cryptographic library.
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
#include "stsafe_common.h"
#include "stsafe_wrap_unwrap.h"
#include "stsafe_data_partition.h"

#define ENVELOPE_SIZE                       96   /* non-zero multiple of 8 bytes; max 480(=8*60) */
#define WRAP_RESPONSE_SIZE                  (ENVELOPE_SIZE + 8) /* Local Envelope response data is 8-bytes longer than the working key (see User Manual). */

/*************************** Wrap Unwrap Envelope ************************/
int32_t WrapUnwrap(StSafeA_Handle_t *handle, uint8_t slot)
{
  int32_t StatusCode = 0;

  // Used to store the data to wrap.
  uint8_t Random[ENVELOPE_SIZE];

  printf("Wrap/Unwrap local envelope\r\n");

  /* Declare, define and allocate memory for Wrap Local Envelope */
#if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
  StSafeA_LVBuffer_t LocalEnvelope;
#else
  StSafeA_LVBuffer_t LocalEnvelope;

  // Used to store the response data from the STSAFE A110 which is the wrapped data.
  uint8_t data_LocalEnvelope[WRAP_RESPONSE_SIZE] = {0};
  LocalEnvelope.Length = WRAP_RESPONSE_SIZE;
  LocalEnvelope.Data = data_LocalEnvelope;
#endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

  printf("Request from the STSAFE A110 to generate %d bytes of random data that will be wrapped\r\n", ENVELOPE_SIZE);

  STS_CHK(StatusCode, (int32_t)GenerateUnsignedChallenge(handle, (uint8_t) ENVELOPE_SIZE, Random));

  printf("Request from the STSFAFE A110 to wrap the data to a local envelope\r\n");

  // Wrap local envelope using key slot as argument.
  STS_CHK(StatusCode, (int32_t)StSafeA_WrapLocalEnvelope(handle, slot, &Random[0], ENVELOPE_SIZE, &LocalEnvelope, STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_COMMAND));

  if (StatusCode == 0)
  {
#if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    /* Store Wrapped Local Envelope */
    uint8_t data_WrappedEnvelope[WRAP_RESPONSE_SIZE];
    (void)memcpy(data_WrappedEnvelope, LocalEnvelope.Data, LocalEnvelope.Length);
    LocalEnvelope.Data = data_WrappedEnvelope;
#endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

    /* Declare, define and allocate memory for Unwrap Local Envelope */
#if (STSAFEA_USE_OPTIMIZATION_SHARED_RAM)
    StSafeA_LVBuffer_t UnwrappedEnvelope;
#else
    StSafeA_LVBuffer_t UnwrappedEnvelope;
    uint8_t data_UnwrappedEnvelope[ENVELOPE_SIZE] = {0};
    UnwrappedEnvelope.Length = ENVELOPE_SIZE;
    UnwrappedEnvelope.Data = data_UnwrappedEnvelope;
#endif /* STSAFEA_USE_OPTIMIZATION_SHARED_RAM */

    printf("Request from the STSFAFE A110 to unwrap the data from a local envelope\r\n");

    // Unwrap local envelope using key in slot as argument.
    STS_CHK(StatusCode, (int32_t)StSafeA_UnwrapLocalEnvelope(handle, slot, LocalEnvelope.Data, LocalEnvelope.Length, &UnwrappedEnvelope, STSAFEA_MAC_HOST_CMAC, STSAFEA_ENCRYPTION_RESPONSE));

    printf("Verify unwrap local envelope is identical to initial generated envelope\r\n");

    if ((StatusCode == 0) && (memcmp(&Random[0], &UnwrappedEnvelope.Data[0], ENVELOPE_SIZE) != 0))
    {
      StatusCode = (int32_t) ~0U;
    }
  }

#ifdef HAL_UART_MODULE_ENABLED
  printf("Local envelope result (0 means success): %d\r\n", (int) StatusCode);
#endif /* HAL_UART_MODULE_ENABLED */

  return (StatusCode);
}

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
