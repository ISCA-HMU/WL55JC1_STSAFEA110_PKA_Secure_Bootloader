/**
  ******************************************************************************
  * @file    stm32l4xx_nucleo_bus.h
  * @author  MCD Application Team
  * @brief   STM32L4xx_Nucleo  board support package
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2017 STMicroelectronics International N.V.
  * All rights reserved.</center></h2>
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted, provided that the following conditions are met:
  *
  * 1. Redistribution of source code must retain the above copyright notice,
  *    this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  *    this list of conditions and the following disclaimer in the documentation
  *    and/or other materials provided with the distribution.
  * 3. Neither the name of STMicroelectronics nor the names of other
  *    contributors to this software may be used to endorse or promote products
  *    derived from this software without specific written permission.
  * 4. This software, including modifications and/or derivative works of this
  *    software, must execute solely and exclusively on microcontroller or
  *    microprocessor devices manufactured by or for STMicroelectronics.
  * 5. Redistribution and use of this software other than as permitted under
  *    this license is void and will automatically terminate your rights under
  *    this license.
  *
  * THIS SOFTWARE IS PROVIDED BY STMICROELECTRONICS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS, IMPLIED OR STATUTORY WARRANTIES, INCLUDING, BUT NOT
  * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
  * PARTICULAR PURPOSE AND NON-INFRINGEMENT OF THIRD PARTY INTELLECTUAL PROPERTY
  * RIGHTS ARE DISCLAIMED TO THE FULLEST EXTENT PERMITTED BY LAW. IN NO EVENT
  * SHALL STMICROELECTRONICS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
  * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STM32L4xx_NUCLEO_BUS_H
#define STM32L4xx_NUCLEO_BUS_H

#ifdef __cplusplus
 extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32wlxx_nucleo_conf.h"
#include "stm32wlxx_nucleo.h"

/** @addtogroup BSP
  * @{
  */


/** @addtogroup STM32L4xx_NUCLEO
  * @{
  */


/** @addtogroup STM32L4xx_NUCLEO_BUS
  * @{
  */


/** @defgroup STM32L4xx_NUCLEO_BUS_Exported_Constants STM32L4xx NUCLEO BUS Exported Constants
  * @{
  */
#ifndef BUS_I2C2_FREQUENCY
   #define BUS_I2C2_FREQUENCY  100000U /* Frequency of I2Cn = 100 KHz*/
#endif

#define BUS_I2C2_INSTANCE                       I2C2

#define BUS_I2C2_CLK_ENABLE()                   __HAL_RCC_I2C2_CLK_ENABLE()
#define BUS_I2C2_CLK_DISABLE()                  __HAL_RCC_I2C2_CLK_DISABLE()

#define BUS_I2C2_SDA_GPIO_PIN                   GPIO_PIN_15
#define BUS_I2C2_SCL_GPIO_PIN                   GPIO_PIN_12

#define BUS_I2C2_SDA_GPIO_PORT                  GPIOA
#define BUS_I2C2_SCL_GPIO_PORT                  GPIOA

#define BUS_I2C2_SDA_GPIO_AF                    GPIO_AF4_I2C2
#define BUS_I2C2_SCL_GPIO_AF                    GPIO_AF4_I2C2

#define BUS_I2C2_SDA_GPIO_CLK_ENABLE()          __HAL_RCC_GPIOA_CLK_ENABLE()
#define BUS_I2C2_SCL_GPIO_CLK_ENABLE()          __HAL_RCC_GPIOA_CLK_ENABLE()

#ifndef BUS_I2C2_POLL_TIMEOUT
   #define BUS_I2C2_POLL_TIMEOUT                0x1000U
#endif

/**
  * @}STM32L4xx_NUCLEO_BUS_Exported_Constants
  */


/** @defgroup STM32L4xx_NUCLEO_BUS_Private_Types STM32L4xx NUCLEO BUS Private types
  * @{
  */
#if (USE_HAL_I2C_REGISTER_CALLBACKS == 1) 
typedef struct
{
  pI2C_CallbackTypeDef  pMspInitCb;
  pI2C_CallbackTypeDef  pMspDeInitCb;
}BSP_I2C_Cb_t;
#endif /* (USE_HAL_I2C_REGISTER_CALLBACKS == 1) */

/**
  * @}STM32L4xx_NUCLEO_BUS_Private_Types
  */


/** @defgroup STM32L4XX_NUCLEO_LOW_LEVEL_Exported_Variables LOW LEVEL Exported Constants
  * @{
  */
#ifdef HAL_I2C_MODULE_ENABLED
//extern I2C_HandleTypeDef hbus_i2c2;
#endif /* HAL_I2C_MODULE_ENABLED */

/**
  * @}STM32L4XX_NUCLEO_LOW_LEVEL_Exported_Variables
  */


/** @addtogroup STM32L4xx_NUCLEO_BUS_Exported_Functions
  * @{
  */
int32_t HW_IO_Init(void);

#ifdef HAL_I2C_MODULE_ENABLED
HAL_StatusTypeDef new_MX_I2C2_Init(I2C_HandleTypeDef *phi2c, uint32_t timing);
int32_t BSP_I2C2_Init(void);
int32_t BSP_I2C2_DeInit(void);
int32_t BSP_I2C2_IsReady(uint16_t DevAddr, uint32_t Trials);
int32_t BSP_I2C2_WriteReg(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length);
int32_t BSP_I2C2_ReadReg(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length);
int32_t BSP_I2C2_WriteReg16(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length);
int32_t BSP_I2C2_ReadReg16(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length);
int32_t BSP_I2C2_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length);
int32_t BSP_I2C2_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length);
#endif /* HAL_I2C_MODULE_ENABLED */


int32_t BSP_GetTick(void);

#if defined(HAL_I2C_MODULE_ENABLED) && (USE_HAL_I2C_REGISTER_CALLBACKS == 1)
int32_t BSP_I2C2_RegisterDefaultMspCallbacks (void);
int32_t BSP_I2C2_RegisterMspCallbacks (BSP_I2C_Cb_t *Callbacks);
#endif /* HAL_I2C_MODULE_ENABLED && (USE_HAL_I2C_REGISTER_CALLBACKS == 1) */

/**
  * @}STM32L4xx_NUCLEO_BUS_Exported_Functions
  */


/**
  * @}STM32L4xx_NUCLEO_BUS
  */

/**
  * @}STM32L4xx_NUCLEO
  */


/**
  * @}BSP
  */


#ifdef __cplusplus
}
#endif

#endif /* STM32L4xx_NUCLEO_BUS_H */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
