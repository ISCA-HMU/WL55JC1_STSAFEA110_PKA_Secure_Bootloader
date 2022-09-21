#ifndef INC_STSAFE_COMMON_H_
#define INC_STSAFE_COMMON_H_

#include <stdio.h>
#include "stsafea_core.h"

#define STS_CHK(ret, f)                     if ((ret) == 0) { (ret) = (f); }
#define GET_TICK()                          HAL_GetTick()

#define ZONE0 0
#define ZONE1 1
#define ZONE2 2
#define ZONE3 3
#define ZONE4 4
#define ZONE5 5
#define ZONE6 6
#define ZONE7 7

#define MAX_ZONE_READ_BYTES_WITH_RMAC 500
#define MAX_ZONE_READ_BYTES_WITHOUT_RMAC 504

typedef enum {

  STATUS_OK                = 0x00U,
  STATUS_ERROR             = 0x01U,
  STATUS_CERT_NOT_FOUND    = 0x02U,
  STATUS_CERT_PARSE_ERROR  = 0x03U,
  STATUS_CERT_VERIFY_ERROR = 0x04U,
  STATUS_RANDOM_GEN_ERROR  = 0x05U,
  STATUS_FLASH_RANGE_ERROR = 0x06U

} STSAFE_Status_t;

uint8_t GenerateUnsignedChallenge(StSafeA_Handle_t *handle, uint8_t size, uint8_t *random);

#endif /* INC_STSAFE_COMMON_H_ */
