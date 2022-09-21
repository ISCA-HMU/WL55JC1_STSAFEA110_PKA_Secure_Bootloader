/**
  ******************************************************************************
  * @file    all_use_cases.c
  * @author  SMD application team
  * @version V3.1.1
  * @brief   All use cases using STSAFE-A and MbedTLS cryptographic library.
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
#include "stsafea_interface_conf.h"
#ifdef MCU_PLATFORM_INCLUDE
#include MCU_PLATFORM_INCLUDE
#endif /* MCU_PLATFORM_INCLUDE */

#include <stsafe_all_use_cases.h>
#include <stsafe_authentication.h>
#include <stsafe_key_pair.h>
#include <stsafe_secret_establishment.h>
#if (USE_SIGNATURE_SESSION)
#include "signature_session.h"
#endif
#include <stsafe_wrap_unwrap.h>

#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }


/***************** All Use Cases *******************/
int32_t all_use_cases(StSafeA_Handle_t* pHandle)
{
  int32_t               StatusCode = 0;

  /* Authentication */
  STS_CHK(StatusCode, Authentication(pHandle));

  /* Ephemeral Key */
  STS_CHK(StatusCode, key_pair_generation(pHandle));

  /* Key Establishment */
  STS_CHK(StatusCode, SecretEstablishment(pHandle));

#if (USE_SIGNATURE_SESSION)
  /* Signature Session */
  STS_CHK(StatusCode, signature_session(pHandle));
#endif

  /* Wrap Unwrap */
  STS_CHK(StatusCode, WrapUnwrap(pHandle, STSAFEA_KEY_SLOT_0));

  return StatusCode;
}


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
