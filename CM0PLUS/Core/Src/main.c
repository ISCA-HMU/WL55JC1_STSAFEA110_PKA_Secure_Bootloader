/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * <h2><center>&copy; Copyright (c) 2021 STMicroelectronics.
 * All rights reserved.</center></h2>
 *
 * This software component is licensed by ST under BSD 3-Clause license,
 * the "License"; You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                        opensource.org/licenses/BSD-3-Clause
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "crc.h"
#include "i2c.h"
#include "pka.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include "stsafe_authentication.h"
#include "stsafe_pairing.h"
#include "stsafe_data_partition.h"
#include "stsafe_wrap_unwrap.h"
#include "stm32wlxx_nucleo.h"
#include "secure_boot.h"
#include "stsafe_oem_setup.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define OEM_MODE 0

#define BUTTON_RELEASED      1U
#define BUTTON_PRESSED       0U

#define I2C_DEVICE_ADDRESS   0x0020

#define PAGE_NUMBER 127
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */

// @formatter:off
uint8_t Host_MAC_Cipher_Key_Dummy[2U * STSAFEA_HOST_KEY_LENGTH] =
{
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, /* Host MAC key */
  0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66, 0x77, 0x77, 0x88, 0x88  /* Host cipher key */
};

// @formatter:on
uint64_t ptr;
int32_t StatusCode = 0;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
 * @brief  The application entry point.
 * @retval int
 */
int main(void)
{
  /* USER CODE BEGIN 1 */

  uint8_t status_code;
  StSafeA_Handle_t stsafea_handle;

  /* STSAFE MW requires a data buffer to send/receive bytes over the bus.
   For memory optimization reasons it's up to the application to allocate it,
   so that the application can deallocate it when STSAFE services are not required anymore */
  uint8_t a_rx_tx_stsafea_data[STSAFEA_BUFFER_MAX_SIZE];

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_I2C2_Init();
  MX_PKA_Init();
  MX_USART2_UART_Init();
  MX_CRC_Init();
  /* USER CODE BEGIN 2 */

  /* Configure LEDS */
  (void) BSP_LED_Init(LED1);
  (void) BSP_LED_Init(LED2);
  (void) BSP_LED_Init(LED3);

  /* Configure BUTTON_USER */
  (void) BSP_PB_Init(BUTTON_SW1, BUTTON_MODE_GPIO);

  clear_screen();
#if OEM_MODE == 1
  LOG("%sNUCLEO-WL55JC1 STSAFE A110 OEM Mode%s\r\n", LIGHT_CYAN, NO_COLOR);
  LOG("%s-----------------------------------%s\r\n", LIGHT_CYAN, NO_COLOR);
#else
  LOG("%sNUCLEO-WL55JC1 STSAFE A110 Secure Bootloader with PKA Support%s\r\n", LIGHT_CYAN, NO_COLOR);
  LOG("%s-------------------------------------------------------------%s\r\n", LIGHT_CYAN, NO_COLOR);
#endif

  /* Create STSAFE-A's handle */
  status_code = (uint8_t) StSafeA_Init(&stsafea_handle, a_rx_tx_stsafea_data);

  if (status_code != STSAFEA_OK)
  {
    LOG("%STSAFE A110 Handle Init Status: %d%s\r\n", YELLOW, NO_COLOR, status_code);
  }

  if (HAL_I2C_IsDeviceReady(&hi2c2, I2C_DEVICE_ADDRESS << 1, 3, 1000) == HAL_OK)
  {
#if OEM_MODE == 1
    if (OEM_STSafeA110_Setup(&stsafea_handle) == OEM_OK)
    {
      (void) BSP_LED_On(LED1);
    }
    else
    {
      (void) BSP_LED_On(LED3);
    }
#else
    if (SB_Boot(&stsafea_handle) == SB_OK)
    {
      (void) BSP_LED_On(LED1);
    }
    else
    {
      (void) BSP_LED_On(LED3);
    }
#endif
  }
  else
  {
    LOG("%sDevice not ready: 0x%02X error%s\r\n", YELLOW, NO_COLOR, status_code);
  }

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
 * @brief  This function is executed in case of error occurrence.
 * @retval None
 */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
