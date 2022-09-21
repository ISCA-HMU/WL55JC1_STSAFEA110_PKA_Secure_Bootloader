#ifndef INC_SECURE_BOOT_H_
#define INC_SECURE_BOOT_H_

#include "stdio.h"

#include "usart.h"

#include "stsafea_core.h"
#include "stsafe_common.h"
#include "stsafe_certs.h"

// To parse certificates
#include "x509.h"

// For SHA256 digest.
#include "mbedtls/sha256.h"

// To use PKA for verifying certificates through hardware acceleration.
#include "pka.h"
#include "prime256v1.h"

#if LOG_ALLOWED == 1
#include "x509_prints.h"
#endif

#define MAGIC_NUMBER 0x53544D32

#define SHA256 0
#define SHA224 1

#define SHA256_SIZE 32

#define PKA_CERT_VERIFY_OK    1U
#define PKA_CERT_VERIFY_ERROR 0U

#define PKA_OPERATION_COMPLETE_CALLBACK 1U
#define PKA_OPERATION_ERROR_CALLBACK    2U

#define NUMBER_OF_BYTES_TO_EXTRACT_CERTIFICATE_SIZE 4

#define MAX_CERTIFICATE_SIZE 600

#define MAX_ECDSA_SIGNATURE_LENGTH 72

#define SET_VECTOR_TABLE 0

#define USER_APP_TRUST_INFO_PAGE 63
#define USER_APP_TRUST_INFO_OFFSET (USER_APP_TRUST_INFO_PAGE * FLASH_PAGE_SIZE)


#define VALID_BANNER      \
"  ---------------------\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^###^^\r\n\
  ^^^^^^^^^^^^^^@@$$@^^\r\n\
  ^^^^^^^^^^^##$$$@#^^^\r\n\
  ^^#@$@^^^#@$$$@#^^^^^\r\n\
  ^^#@@$$@@$$$#^^^^^^^^\r\n\
  ^^^^^#$$$$@^^^^^^^^^^\r\n\
  ^^^^^^^##^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ---------------------"

#define INVALID_BANNER    \
"  ---------------------\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^#$#^^^^^^#$@^^^^^\r\n\
  ^^^#WWWM#^^#$WWW$^^^^\r\n\
  ^^^^^@MWWM$WWW@#^^^^^\r\n\
  ^^^^^^^MMWWMM#^^^^^^^\r\n\
   ^^^^^@MMWMMWWM@#^^^^^\r\n\
  ^^^@WWWM@^^#$WWW$^^^^\r\n\
  ^^^^#$#^^^^^^#$@^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ^^^^^^^^^^^^^^^^^^^^^\r\n\
  ---------------------"

// Function pointer definition.
typedef void (*pFunction)(void);

typedef struct UserAppTrustInfo
{
    uint8_t MagicNumber[4];
    uint8_t AddressOffset[4];
    uint8_t FirmwareSize[4];
    uint8_t FirmwareSignature[MAX_ECDSA_SIGNATURE_LENGTH];

}UserAppTrustInfo_t;

typedef enum {

  SB_OK                       = 0x00U,
  SB_ERROR                    = 0x01U,
  SB_CERT_NOT_FOUND           = 0x02U,
  SB_CERT_PARSE_ERROR         = 0x03U,
  SB_CERT_VERIFY_ERROR        = 0x04U,
  SB_PKA_VERIFY_PROCESS_ERROR = 0x05U,
  SB_INVALID_MAGIC_NUMBER     = 0x06U,
  SB_INVALID_USER_APP         = 0x07U

} SB_Status_t;

SB_Status_t SB_Boot(StSafeA_Handle_t *handle);

#endif /* INC_SECURE_BOOT_H_ */
