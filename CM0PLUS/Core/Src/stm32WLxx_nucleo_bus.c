/**
  ******************************************************************************
  * @file    stm32l4xx_nucleo_bus.c
  * @author  MCD Application Team
  * @brief   STM32L4xx_Nucleo board support package
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2018 STMicroelectronics International N.V.
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
  *    software, must execute solely and exclusively on micro-controller or
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

/* Includes ------------------------------------------------------------------*/
#include <stm32WLxx_nucleo_bus.h>

#include "stm32wlxx_nucleo_errno.h"

#include "i2c.h"
/** @addtogroup BSP
  * @{
  */

/** @addtogroup STM32L4xx_NUCLEO
  * @{
  */

/** @defgroup STM32L4xx_NUCLEO_BUS STM32L4xx_NUCLEO BUS
  * @{
  */

#define DIV_ROUND_CLOSEST(x, d)  (((x) + ((d) / 2U)) / (d))

#define I2C_ANALOG_FILTER_ENABLE               1U
#define I2C_ANALOG_FILTER_DELAY_MIN            50U     /* ns */
#define I2C_ANALOG_FILTER_DELAY_MAX            260U    /* ns */
#define I2C_ANALOG_FILTER_DELAY_DEFAULT        2U      /* ns */

#define VALID_PRESC_NBR                        100U
#define PRESC_MAX                              16U
#define SCLDEL_MAX                             16U
#define SDADEL_MAX                             16U
#define SCLH_MAX                               256U
#define SCLL_MAX                               256U
#define I2C_DNF_MAX                            16U
#define NSEC_PER_SEC                           1000000000UL


/**
  * struct i2c_charac - private i2c specification timing
  * @rate: I2C bus speed (Hz)
  * @rate_min: 80% of I2C bus speed (Hz)
  * @rate_max: 100% of I2C bus speed (Hz)
  * @fall_max: Max fall time of both SDA and SCL signals (ns)
  * @rise_max: Max rise time of both SDA and SCL signals (ns)
  * @hddat_min: Min data hold time (ns)
  * @vddat_max: Max data valid time (ns)
  * @sudat_min: Min data setup time (ns)
  * @l_min: Min low period of the SCL clock (ns)
  * @h_min: Min high period of the SCL clock (ns)
  */
struct i2c_specs 
{
  uint32_t rate;
  uint32_t rate_min;
  uint32_t rate_max;
  uint32_t fall_max;
  uint32_t rise_max;
  uint32_t hddat_min;
  uint32_t vddat_max;
  uint32_t sudat_min;
  uint32_t l_min;
  uint32_t h_min;
};

enum i2c_speed 
{
  I2C_SPEED_STANDARD  = 0U, /* 100 kHz */
  I2C_SPEED_FAST      = 1U, /* 400 kHz */
  I2C_SPEED_FAST_PLUS = 2U, /* 1 MHz */
};

/**
  * struct i2c_setup - private I2C timing setup parameters
  * @rise_time: Rise time (ns)
  * @fall_time: Fall time (ns)
  * @dnf: Digital filter coefficient (0-16)
  * @analog_filter: Analog filter delay (On/Off)
  */
struct i2c_setup 
{
  uint32_t rise_time;
  uint32_t fall_time;
  uint32_t dnf;
  uint32_t analog_filter;
};

/**
  * struct i2c_timings - private I2C output parameters
  * @node: List entry
  * @presc: Prescaler value
  * @scldel: Data setup time
  * @sdadel: Data hold time
  * @sclh: SCL high period (master mode)
  * @scll: SCL low period (master mode)
  */
struct i2c_timings 
{
  uint32_t presc;
  uint32_t scldel;
  uint32_t sdadel;
  uint32_t sclh;
  uint32_t scll;
};

static const struct i2c_specs i2c_specs[] = 
{
  [I2C_SPEED_STANDARD] = 
  {
    .rate = 100000,
    .rate_min = 100000,
    .rate_max = 120000,
    .fall_max = 300,
    .rise_max = 1000,
    .hddat_min = 0,
    .vddat_max = 3450,
    .sudat_min = 250,
    .l_min = 4700,
    .h_min = 4000,
  },
  [I2C_SPEED_FAST] = 
  {
    .rate = 400000,
    .rate_min = 320000,
    .rate_max = 400000,
    .fall_max = 300,
    .rise_max = 300,
    .hddat_min = 0,
    .vddat_max = 900,
    .sudat_min = 100,
    .l_min = 1300,
    .h_min = 600,
  },
  [I2C_SPEED_FAST_PLUS] = 
  {
    .rate = 1000000,
    .rate_min = 800000,
    .rate_max = 1000000,
    .fall_max = 120,
    .rise_max = 120,
    .hddat_min = 0,
    .vddat_max = 450,
    .sudat_min = 50,
    .l_min = 500,
    .h_min = 260,
  },
};

static const struct i2c_setup i2c_user_setup[] = 
{
  [I2C_SPEED_STANDARD] = 
  {
    .rise_time = 400,
    .fall_time = 100,
    .dnf = I2C_ANALOG_FILTER_DELAY_DEFAULT,
    .analog_filter = 1,
  },
  [I2C_SPEED_FAST] = 
  {
    .rise_time = 250,
    .fall_time = 100,
    .dnf = I2C_ANALOG_FILTER_DELAY_DEFAULT,
    .analog_filter = 1,
  },
  [I2C_SPEED_FAST_PLUS] = 
  { 
    .rise_time = 60,
    .fall_time = 100,
    .dnf = I2C_ANALOG_FILTER_DELAY_DEFAULT,
    .analog_filter = 1,
  },
};

/** @defgroup STM32L4xx_NUCLEO_BUS_Exported_Variables
  * @{
  */
#ifdef HAL_I2C_MODULE_ENABLED
//I2C_HandleTypeDef hbus_i2c2;
#endif /* HAL_I2C_MODULE_ENABLED */

#if (USE_HAL_I2C_REGISTER_CALLBACKS == 1)
static uint32_t IsI2C1MspCbValid = 0;
#endif /* USE_HAL_I2C_REGISTER_CALLBACKS */ 

/**
  * @}STM32L4xx_NUCLEO_BUS_Exported_Variables
  */


/** @defgroup STM32L4xx_NUCLEO_BUS_Private_Function_Prototypes
  * @{
  */
#ifdef HAL_I2C_MODULE_ENABLED
static void I2C2_MspInit(I2C_HandleTypeDef *hI2c);
static void I2C2_MspDeInit(I2C_HandleTypeDef *hI2c);
static uint32_t I2C_GetTiming(uint32_t clock_src_hz, uint32_t i2cfreq_hz);
#endif /* HAL_I2C_MODULE_ENABLED */

/**
  * @}STM32L4xx_NUCLEO_BUS_Private_Function_Prototypes
  */


/** @defgroup STM32L4xx_NUCLEO_BUS_Exported_Functions
  * @{
  */ 

/**
  * @brief  Additional IO pins configuration needed.
  * @param  none
  * @retval 0 in case of success, an error code otherwise
  */
int32_t HW_IO_Init(void)
{
#if 1
  /* !!!! Following code has no impact using X-NUCLEO-SAFEA1 board */
  /* !!!! Usefull using METKEY board (not anymore available) */
  GPIO_InitTypeDef GPIO_InitStruct;

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /* Configure GPIO pin : RST Pin */
  GPIO_InitStruct.Pin = GPIO_PIN_14;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /* Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_14, GPIO_PIN_SET);
  HAL_Delay(50);
#endif

  return BSP_ERROR_NONE;
}

#ifdef HAL_I2C_MODULE_ENABLED
/**
  * @brief  MX I2C1 Inititialization as generated by CubeMX.
  * @param  phi2c : I2C handle.
  * @param  timing : I2C timings as described in the I2C peripheral V2 and V3.
  * @retval Prescaler dividor
  */
__weak HAL_StatusTypeDef new_MX_I2C2_Init(I2C_HandleTypeDef *phi2c, uint32_t timing)
{
  phi2c->Init.Timing           = timing;
  phi2c->Init.OwnAddress1      = 0;
  phi2c->Init.AddressingMode   = I2C_ADDRESSINGMODE_7BIT;
  phi2c->Init.DualAddressMode  = I2C_DUALADDRESS_DISABLE;
  phi2c->Init.OwnAddress2      = 0;
  phi2c->Init.GeneralCallMode  = I2C_GENERALCALL_DISABLE;
  phi2c->Init.NoStretchMode    = I2C_NOSTRETCH_DISABLE;

  if(HAL_I2C_Init(phi2c) != HAL_OK)
  {
    return HAL_ERROR;
  }

  if (HAL_I2CEx_ConfigAnalogFilter(phi2c, I2C_ANALOGFILTER_DISABLE) != HAL_OK)
  {
    return HAL_ERROR;
  }

  if (HAL_I2CEx_ConfigDigitalFilter(phi2c, I2C_ANALOG_FILTER_DELAY_DEFAULT) != HAL_OK)
  {
    return HAL_ERROR;
  }

  return HAL_OK;
}

/**
  * @brief  Initializes I2C HAL.
  * @retval BSP status
  */
int32_t BSP_I2C2_Init(void)
{
  int32_t ret = BSP_ERROR_NONE;

  hi2c2.Instance  = I2C2;

  if (HAL_I2C_GetState(&hi2c2) == HAL_I2C_STATE_RESET)
  {
#if (USE_HAL_I2C_REGISTER_CALLBACKS == 0)
    /* Init the I2C Msp */
    HAL_I2C_MspInit(&hi2c2);
//    I2C2_MspInit(&hi2c2);
#else
    if(IsI2c2MspCbValid == 0U)
    {
      if(BSP_I2C2_RegisterDefaultMspCallbacks() != BSP_ERROR_NONE)
      {
        return BSP_ERROR_MSP_FAILURE;
      }
    }
#endif
    /* Init the I2C */
//    if (MX_I2C2_Init(&hbus_i2c2, I2C_GetTiming (HAL_RCC_GetPCLK2Freq(), BUS_I2C2_FREQUENCY )) != HAL_OK)

    MX_I2C2_Init();

//    if (MX_I2C2_Init() != HAL_OK)
//    {
//      ret = BSP_ERROR_BUS_FAILURE;
//    }
//    else if( HAL_I2CEx_ConfigAnalogFilter(&hbus_i2c2, I2C_ANALOGFILTER_ENABLE) != HAL_OK)
//    {
//      ret = BSP_ERROR_BUS_FAILURE;
//    }
//    else
//    {
//      ret = BSP_ERROR_NONE;
//    }
  }

  return ret;
}

/**
  * @brief  DeInitializes I2C HAL.
  * @retval BSP status
  */
int32_t BSP_I2C2_DeInit(void)
{ 
  int32_t ret  = BSP_ERROR_NONE;

#if (USE_HAL_I2C_REGISTER_CALLBACKS == 0)
  /* DeInit the I2C */ 
  I2C2_MspDeInit(&hi2c2);
#endif

  /* DeInit the I2C */ 
  if(HAL_I2C_DeInit(&hi2c2) != HAL_OK)
  {
    ret = BSP_ERROR_BUS_FAILURE;
  }

  return ret;  
}

/**
  * @brief  Check whether the I2C bus is ready.
  * @retval DevAddr : I2C device address
  * @retval Trials : Check trials number
  */
int32_t BSP_I2C2_IsReady(uint16_t DevAddr, uint32_t Trials)
{
  int32_t ret;

  if(HAL_I2C_IsDeviceReady(&hi2c2, DevAddr, Trials, BUS_I2C2_POLL_TIMEOUT) != HAL_OK)
  {
    ret = BSP_ERROR_BUSY;
  }
  else
  {
    ret = BSP_ERROR_NONE;
  }

  return ret;
}

/**
  * @brief  Write a value in a register of the device through BUS.
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to write
  * @param  pData  Pointer to data buffer to write
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t BSP_I2C2_WriteReg(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length)
{
  int32_t ret;
  uint32_t hal_error;

  if(HAL_I2C_Mem_Write(&hi2c2, (uint8_t)DevAddr,
                       (uint16_t)Reg, I2C_MEMADD_SIZE_8BIT,
                       (uint8_t *)pData, Length, BUS_I2C2_POLL_TIMEOUT) == HAL_OK)
  {
    ret = BSP_ERROR_NONE;
  }
  else
  {
    hal_error = HAL_I2C_GetError(&hi2c2);
    if( hal_error == HAL_I2C_ERROR_AF)
    {
      return BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE;
    }
    else
    {
      ret =  BSP_ERROR_PERIPH_FAILURE;
    }
  }
  return ret;
}

/**
  * @brief  Read a register of the device through BUS
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to read
  * @param  pData  Pointer to data buffer to read
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t  BSP_I2C2_ReadReg(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length)
{
  int32_t ret;
  uint32_t hal_error;

  if (HAL_I2C_Mem_Read(&hi2c2, DevAddr, (uint16_t)Reg,
                       I2C_MEMADD_SIZE_8BIT, pData,
                       Length, BUS_I2C2_POLL_TIMEOUT) == HAL_OK)
  {
    ret = BSP_ERROR_NONE;
  }
  else
  {
    hal_error = HAL_I2C_GetError(&hi2c2);
    if( hal_error == HAL_I2C_ERROR_AF)
    {
      return BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE;
    }
    else
    {
      ret =  BSP_ERROR_PERIPH_FAILURE;
    }
  }
  return ret;
}

/**
  * @brief  Write a value in a register of the device through BUS.
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to write
  * @param  pData  Pointer to data buffer to write
  * @param  Length Data Length
  * @retval BSP statu
  */
int32_t BSP_I2C2_WriteReg16(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length)
{
  int32_t ret;
  uint32_t hal_error;

  if(HAL_I2C_Mem_Write(&hi2c2, (uint8_t)DevAddr,
                       (uint16_t)Reg, I2C_MEMADD_SIZE_16BIT,
                       (uint8_t *)pData, Length, BUS_I2C2_POLL_TIMEOUT) == HAL_OK)
  {
    ret = BSP_ERROR_NONE;
  }
  else
  {
    hal_error = HAL_I2C_GetError(&hi2c2);
    if( hal_error == HAL_I2C_ERROR_AF)
    {
      return BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE;
    }
    else
    {
      ret =  BSP_ERROR_PERIPH_FAILURE;
    }
  }
  return ret;
}

/**
  * @brief  Read a register of the device through BUS
  * @param  DevAddr Device address on Bus.
  * @param  Reg    The target register address to read
  * @param  pData  Pointer to data buffer to read
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t  BSP_I2C2_ReadReg16(uint16_t DevAddr, uint16_t Reg, uint8_t *pData, uint16_t Length)
{
  int32_t ret;
  uint32_t hal_error;
  
  if (HAL_I2C_Mem_Read(&hi2c2, DevAddr, (uint16_t)Reg,
                       I2C_MEMADD_SIZE_16BIT, pData,
                       Length, BUS_I2C2_POLL_TIMEOUT) == HAL_OK)
  {
    ret = BSP_ERROR_NONE;
  }
  else
  {
    hal_error = HAL_I2C_GetError(&hi2c2);
    if( hal_error == HAL_I2C_ERROR_AF)
    {
      return BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE;
    }
    else
    {
      ret =  BSP_ERROR_PERIPH_FAILURE;
    }
  }
  return ret;
}

/**
  * @brief  Send data through BUS.
  * @param  DevAddr Device address on Bus.
  * @param  pData  Pointer to data buffer to write
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t BSP_I2C2_Send(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
  int32_t ret;
  uint32_t hal_error;

  if (HAL_I2C_Master_Transmit(&hi2c2,
                              DevAddr, 
                              pData, 
                              Length, 
                              BUS_I2C2_POLL_TIMEOUT) == HAL_OK)
  {
    ret = BSP_ERROR_NONE;
  }
  else
  {
    hal_error = HAL_I2C_GetError(&hi2c2);
    if( hal_error == HAL_I2C_ERROR_AF)
    {
      return BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE;
    }
    else
    {
      ret =  BSP_ERROR_PERIPH_FAILURE;
    }
  }
  return ret;
}

/**
  * @brief  Receive data through BUS
  * @param  DevAddr Device address on Bus.
  * @param  pData  Pointer to data buffer to read
  * @param  Length Data Length
  * @retval BSP status
  */
int32_t  BSP_I2C2_Recv(uint16_t DevAddr, uint8_t *pData, uint16_t Length)
{
  int32_t ret;
  uint32_t hal_error;

  if (HAL_I2C_Master_Receive(&hi2c2,
                              DevAddr, 
                              pData, 
                              Length, 
                              BUS_I2C2_POLL_TIMEOUT) == HAL_OK)
  {
    ret = BSP_ERROR_NONE;
  }
  else
  {
    hal_error = HAL_I2C_GetError(&hi2c2);
    if( hal_error == HAL_I2C_ERROR_AF)
    {
      return BSP_ERROR_BUS_ACKNOWLEDGE_FAILURE;
    }
    else
    {
      ret =  BSP_ERROR_PERIPH_FAILURE;
    }
  }
  return ret;
}

#if (USE_HAL_I2C_REGISTER_CALLBACKS == 1)
/**
  * @brief Register Default I2C1 Bus Msp Callbacks
  * @retval BSP status
  */
int32_t BSP_I2C1_RegisterDefaultMspCallbacks (void)
{
  __HAL_I2C_RESET_HANDLE_STATE(&hbus_i2c2);

  /* Register MspInit Callback */
  if(HAL_I2C_RegisterCallback(&hbus_i2c2, HAL_I2C_MSPINIT_CB_ID, I2C2_MspInit) != HAL_OK)
  {
    return BSP_ERROR_PERIPH_FAILURE;
  }

  /* Register MspDeInit Callback */
  if(HAL_I2C_RegisterCallback(&hbus_i2c2, HAL_I2C_MSPDEINIT_CB_ID, I2C2_MspDeInit) != HAL_OK)
  {
    return BSP_ERROR_PERIPH_FAILURE;
  }

  IsI2c2MspCbValid = 1;

  return BSP_ERROR_NONE;  
}

/**
  * @brief Register I2C1 Bus Msp Callback registering
  * @param Callbacks     pointer to I2C1 MspInit/MspDeInit callback functions
  * @retval BSP status
  */
int32_t BSP_I2C2_RegisterMspCallbacks (BSP_I2C2_Cb_t *Callbacks)
{
  __HAL_I2C_RESET_HANDLE_STATE(&hbus_i2c2);

  /* Register MspInit Callback */
  if(HAL_I2C_RegisterCallback(&hbus_i2c2, HAL_I2C_MSPINIT_CB_ID, Callbacks->pMspI2cInitCb) != HAL_OK)
  {
    return BSP_ERROR_PERIPH_FAILURE;
  }

  /* Register MspDeInit Callback */
  if(HAL_I2C_RegisterCallback(&hbus_i2c2, HAL_I2C_MSPDEINIT_CB_ID, Callbacks->pMspI2cDeInitCb) != HAL_OK)
  {
    return BSP_ERROR_PERIPH_FAILURE;
  }

  IsI2c2MspCbValid = 1;

  return BSP_ERROR_NONE;  
}
#endif /* (USE_HAL_I2C_REGISTER_CALLBACKS == 1) */
#endif /* HAL_I2C_MODULE_ENABLED */

/**
  * @brief  Return system tick (ms) function .
  * @retval Current HAL time base time stamp
  */
int32_t BSP_GetTick(void)
{
  return (int32_t)HAL_GetTick();
}

/** @addtogroup STM32L4xx_NUCLEO_BUS_Private_Function_Prototypes
  * @{
  */

#ifdef HAL_I2C_MODULE_ENABLED
/**
  * @brief  Initializes I2C MSP.
  * @param  hI2c  I2C handler
  * @retval None
  */
static void I2C2_MspInit(I2C_HandleTypeDef *hI2c)
{
  GPIO_InitTypeDef  gpio_init;

  /* Enable I2C clock */
  BUS_I2C2_CLK_ENABLE();

  /* Enable GPIO clock */
  BUS_I2C2_SDA_GPIO_CLK_ENABLE();
  BUS_I2C2_SCL_GPIO_CLK_ENABLE();

  /* Configure I2C SDA Line */
  gpio_init.Pin = BUS_I2C2_SDA_GPIO_PIN;
  gpio_init.Mode = GPIO_MODE_AF_OD;
  gpio_init.Pull = GPIO_NOPULL;
  gpio_init.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  gpio_init.Alternate = BUS_I2C2_SDA_GPIO_AF;
  HAL_GPIO_Init(BUS_I2C2_SDA_GPIO_PORT, &gpio_init);

  /* Configure I2C SCL Line */
  gpio_init.Pin = BUS_I2C2_SCL_GPIO_PIN;
  gpio_init.Mode = GPIO_MODE_AF_OD;
  gpio_init.Pull = GPIO_NOPULL;
  gpio_init.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  gpio_init.Alternate = BUS_I2C2_SCL_GPIO_AF;
  HAL_GPIO_Init(BUS_I2C2_SCL_GPIO_PORT, &gpio_init);
}

/**
  * @brief  DeInitializes I2C MSP.
  * @param  hI2c  I2C handler
  * @retval None
  */
static void I2C2_MspDeInit(I2C_HandleTypeDef *hI2c)
{
  /* Disable I2C clock */
  __HAL_RCC_I2C2_CLK_DISABLE();

  /* DeInitialize peripheral GPIOs */
  HAL_GPIO_DeInit(BUS_I2C2_SDA_GPIO_PORT, BUS_I2C2_SDA_GPIO_PIN);
  HAL_GPIO_DeInit(BUS_I2C2_SCL_GPIO_PORT, BUS_I2C2_SCL_GPIO_PIN);
}
#endif /* HAL_I2C_MODULE_ENABLED */


#ifdef HAL_I2C_MODULE_ENABLED
/**
  * @brief  Convert the I2C Frequency into I2C timing.
  * @param  clock_src_hz : I2C source clock in HZ.
  * @param  i2cfreq_hz : I2C frequency in Hz.
  * @retval Prescaler dividor
  */        
static uint32_t I2C_GetTiming(uint32_t clock_src_hz, uint32_t i2cfreq_hz)
{
  uint32_t ret = 0;
  uint32_t speed = 0;
  uint32_t is_valid_speed = 0; 
  uint32_t p_prev = PRESC_MAX;
  uint32_t i2cclk;
  uint32_t i2cspeed;
  uint32_t clk_error_prev;
  uint32_t tsync;
  uint32_t af_delay_min, af_delay_max;
  uint32_t dnf_delay;
  uint32_t clk_min, clk_max;
  int32_t sdadel_min, sdadel_max;
  int32_t scldel_min;
  struct i2c_timings *s;
  struct i2c_timings valid_timing[VALID_PRESC_NBR];
  uint32_t p, l, a, h;
  uint32_t valid_timing_nbr = 0;  

  if((clock_src_hz == 0U) || (i2cfreq_hz == 0U))
  {
    ret = 0;
  }
  else
  {
    for (uint32_t i =0 ; i <=  (uint32_t)I2C_SPEED_FAST_PLUS ; i++)
    {
      if ((i2cfreq_hz >= i2c_specs[i].rate_min) &&
          (i2cfreq_hz <= i2c_specs[i].rate_max))
      {
        is_valid_speed = 1;
        speed = i;
        break;
      }
    }

    if(is_valid_speed != 0U)  
    {
      i2cclk = DIV_ROUND_CLOSEST(NSEC_PER_SEC, clock_src_hz);
      i2cspeed = DIV_ROUND_CLOSEST(NSEC_PER_SEC, i2cfreq_hz);

      clk_error_prev = i2cspeed;

      /*  Analog and Digital Filters */
      af_delay_min =((i2c_user_setup[speed].analog_filter == 1U)? I2C_ANALOG_FILTER_DELAY_MIN : 0U);
      af_delay_max =((i2c_user_setup[speed].analog_filter == 1U)? I2C_ANALOG_FILTER_DELAY_MAX : 0U);

      dnf_delay = i2c_user_setup[speed].dnf * i2cclk;
      
      sdadel_min = (int32_t)i2c_user_setup[speed].fall_time - (int32_t)i2c_specs[speed].hddat_min -
                   (int32_t)af_delay_min - (int32_t)(((int32_t)i2c_user_setup[speed].dnf + 3) * (int32_t)i2cclk);

      sdadel_max = (int32_t)i2c_specs[speed].vddat_max - (int32_t)i2c_user_setup[speed].rise_time -
                   (int32_t)af_delay_max - (int32_t)(((int32_t)i2c_user_setup[speed].dnf + 4) * (int32_t)i2cclk);

      scldel_min = (int32_t)i2c_user_setup[speed].rise_time + (int32_t)i2c_specs[speed].sudat_min;

      if (sdadel_min <= 0)
      {
        sdadel_min = 0;
      }

      if (sdadel_max <= 0)
      {
        sdadel_max = 0;
      }

      /* Compute possible values for PRESC, SCLDEL and SDADEL */
      for (p = 0; p < PRESC_MAX; p++) 
      {
        for (l = 0; l < SCLDEL_MAX; l++) 
        {
          uint32_t scldel = (l + 1U) * (p + 1U) * i2cclk;

          if (scldel < (uint32_t)scldel_min)
          {
            continue;
          }

          for (a = 0; a < SDADEL_MAX; a++) 
          {
            uint32_t sdadel = (a * (p + 1U) + 1U) * i2cclk;

            if (((sdadel >= (uint32_t)sdadel_min) && (sdadel <= (uint32_t)sdadel_max))&& (p != p_prev)) 
            {
              valid_timing[valid_timing_nbr].presc = p;
              valid_timing[valid_timing_nbr].scldel = l;
              valid_timing[valid_timing_nbr].sdadel = a;
              p_prev = p;
              valid_timing_nbr ++;

              if(valid_timing_nbr >= VALID_PRESC_NBR)
              {
                /* max valid timing buffer is full, use only these values*/
                goto  Compute_scll_sclh;
              }
            }
          }
        }
      }

      if (valid_timing_nbr == 0U) 
      {
        return 0;
      }

    Compute_scll_sclh: 
      tsync = af_delay_min + dnf_delay + (2U * i2cclk);
      s = NULL;
      clk_max = NSEC_PER_SEC / i2c_specs[speed].rate_min;
      clk_min = NSEC_PER_SEC / i2c_specs[speed].rate_max;

      /*
      * Among Prescaler possibilities discovered above figures out SCL Low
      * and High Period. Provided:
      * - SCL Low Period has to be higher than Low Period of tehs SCL Clock
      *   defined by I2C Specification. I2C Clock has to be lower than
      *   (SCL Low Period - Analog/Digital filters) / 4.
      * - SCL High Period has to be lower than High Period of the SCL Clock
      *   defined by I2C Specification
      * - I2C Clock has to be lower than SCL High Period
      */
      for (uint32_t count = 0; count < valid_timing_nbr; count++) 
      {          
        uint32_t prescaler = (valid_timing[count].presc + 1U) * i2cclk;

        for (l = 0; l < SCLL_MAX; l++) 
        {
          uint32_t tscl_l = (l + 1U) * prescaler + tsync;

          if ((tscl_l < i2c_specs[speed].l_min) || (i2cclk >= ((tscl_l - af_delay_min - dnf_delay) / 4U))) 
          {
            continue;
          }

          for (h = 0; h < SCLH_MAX; h++) 
          {
            uint32_t tscl_h = (h + 1U) * prescaler + tsync;
            uint32_t tscl = tscl_l + tscl_h + i2c_user_setup[speed].rise_time + i2c_user_setup[speed].fall_time;

            if ((tscl >= clk_min) && (tscl <= clk_max) && (tscl_h >= i2c_specs[speed].h_min) && (i2cclk < tscl_h)) 
            {
              int32_t clk_error = (int32_t)tscl - (int32_t)i2cspeed;

              if (clk_error < 0)
              {
                clk_error = -clk_error;
              }

              /* save the solution with the lowest clock error */
              if ((uint32_t)clk_error < clk_error_prev) 
              {
                clk_error_prev = (uint32_t)clk_error;
                valid_timing[count].scll = l;
                valid_timing[count].sclh = h;
                s = &valid_timing[count];
              }
            }
          }
        }
      }

      if (s == NULL) 
      {
        return 0;
      }

      ret = ((s->presc  & 0x0FU) << 28) |
            ((s->scldel & 0x0FU) << 20) |
            ((s->sdadel & 0x0FU) << 16) |
            ((s->sclh & 0xFFU) << 8) |
            ((s->scll & 0xFFU) << 0);
    }
  }

  return ret;
}
#endif /* HAL_I2C_MODULE_ENABLED */

/**
  * @}STM32L4xx_NUCLEO_BUS_Private_Function_Prototypes
  */


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


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
