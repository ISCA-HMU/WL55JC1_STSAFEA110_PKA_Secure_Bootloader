/**
  ******************************************************************************
  * @file    usart.h
  * @brief   This file contains all the function prototypes for
  *          the usart.c file
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                        opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef __USART_H__
#define __USART_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* USER CODE BEGIN Includes */
#include "string.h"
/* USER CODE END Includes */

extern UART_HandleTypeDef huart2;

/* USER CODE BEGIN Private defines */
#define LOG_BUFFER_SIZE 128

/*
 * Black        0;30     Dark Gray     1;30
 * Red          0;31     Light Red     1;31
 * Green        0;32     Light Green   1;32
 * Brown/Orange 0;33     Yellow        1;33
 * Blue         0;34     Light Blue    1;34
 * Purple       0;35     Light Purple  1;35
 * Cyan         0;36     Light Cyan    1;36
 * Light Gray   0;37     White         1;37
 * No Color        0
 *
 *
 *- Position the Cursor:
 *  \033[<L>;<C>H
 *     Or
 *  \033[<L>;<C>f
 *  puts the cursor at line L and column C.
 *- Move the cursor up N lines:
 *  \033[<N>A
 *- Move the cursor down N lines:
 *  \033[<N>B
 *- Move the cursor forward N columns:
 *  \033[<N>C
 *- Move the cursor backward N columns:
 *  \033[<N>D
 *
 *- Clear the screen, move to (0,0):
 *  \033[2J
 *- Erase to end of line:
 *  \033[K
 *
 *- Save cursor position:
 *  \033[s
 *- Restore cursor position:
 *  \033[u
 */

#define GREEN      "\033[0;32m"
#define RED        "\033[0;31m"
#define LIGHT_CYAN "\033[1;36m"
#define YELLOW     "\033[0;33m"
#define NO_COLOR   "\033[0m"

#define LOG_ALLOWED       1U
#define LOG_CERTS_ALLOWED 0U
/* USER CODE END Private defines */

void MX_USART2_UART_Init(void);

/* USER CODE BEGIN Prototypes */
void print(char *);
void clear_screen();
int _write(int fd, char* ptr, int len);
void LOG(const char *format, ...);

extern char log_buffer[LOG_BUFFER_SIZE];
/* USER CODE END Prototypes */

#ifdef __cplusplus
}
#endif

#endif /* __USART_H__ */

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
