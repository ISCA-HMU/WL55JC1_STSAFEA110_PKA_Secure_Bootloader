/**
  ******************************************************************************
  * @file    ephemeral_key.h
  * @author  SMD application team
  * @version V3.1.0
  * @brief   Ephemeral key use case header file.
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


#ifndef KEY_PAIR_H
#define KEY_PAIR_H

#include "stsafea_core.h"

int32_t key_pair_generation(StSafeA_Handle_t* handle);

#endif /* KEY_PAIR_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
