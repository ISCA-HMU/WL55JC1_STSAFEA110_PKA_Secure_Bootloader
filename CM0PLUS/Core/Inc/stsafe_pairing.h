/**
  ******************************************************************************
  * @file    pairing.h
  * @author  SMD application team
  * @version V3.1.0
  * @brief   Pairing use case header file.
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


#ifndef PAIRING_H
#define PAIRING_H

#include "stsafea_core.h"

/*
 * If set to 1 it will let the True RNG of the STSAGE A110 to generate the host MAC and cipher keys.
 */
#define USE_HOST_KEYS_GENERATED_BY_STSAFE_A110 0

int32_t Pairing(StSafeA_Handle_t* handle);

#endif /* PAIRING_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
