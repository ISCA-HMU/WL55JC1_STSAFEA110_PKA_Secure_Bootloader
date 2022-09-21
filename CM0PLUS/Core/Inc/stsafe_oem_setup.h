#ifndef INC_STSAFE_OEM_SETUP_H_
#define INC_STSAFE_OEM_SETUP_H_

#include "usart.h"

#include "stsafea_core.h"
#include "stsafe_common.h"
#include "stsafe_certs.h"

#define PAGE_NUMBER 127

typedef enum {

  OEM_OK    = 0x00U,
  OEM_ERROR = 0x01U

} OEM_Status_t;

OEM_Status_t OEM_PrintHexDerToHexArray(char *hex_der);
OEM_Status_t OEM_STSafeA110_Setup(StSafeA_Handle_t *pStSafeA);

#endif /* INC_STSAFE_OEM_SETUP_H_ */
