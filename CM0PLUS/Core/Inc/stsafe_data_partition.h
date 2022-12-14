#ifndef INC_STSAFE_DATA_PARTITION_H_
#define INC_STSAFE_DATA_PARTITION_H_

#include <stdio.h>
#include "stsafea_core.h"

#define LORAWAN_DEVICE_EUI  { 0x00, 0x80, 0xE1, 0x15, 0x05, 0x00, 0xD5, 0xE6 }
#define LORAWAN_JOIN_EUI    { 0x70, 0xB3, 0xD5, 0x7E, 0xD0, 0x04, 0x1B, 0x24 }
#define LORAWAN_APP_KEY     { 0x3E, 0x7B, 0x03, 0x12, 0x07, 0x99, 0x41, 0x82, 0x28, 0xC5, 0x10, 0xC6, 0x74, 0x3C, 0xC7, 0xD0 }
#define LORAWAN_NWK_KEY     { 0x3E, 0x7B, 0x03, 0x12, 0x07, 0x99, 0x41, 0x82, 0x28, 0xC5, 0x10, 0xC6, 0x74, 0x3C, 0xC7, 0xD0 }

// @formatter:off
#define LEAF_CERT_DER_STYLE       0x00
#define LEAF_CERT_HEX_ARRAY_STYLE 0x01

#define LEAF_CERT_OUTPUT_FORMAT LEAF_CERT_DER_STYLE

/*
 * STSAFE-A110 EVAL2
 * Identity: STSAFE-A110 EVAL2
 * Verified by: STM STSAFE-A PROD CA 01
 * Expires: 02/26/2050
 *
 * Subject Name
 * C (Country):	FR
 * O (Organization):	STMicroelectronics
 * CN (Common Name):	STSAFE-A110 EVAL2
 * Issuer Name
 * C (Country):	NL
 * O (Organization):	STMicroelectronics nv
 * CN (Common Name):	STM STSAFE-A PROD CA 01
 * Issued Certificate
 * Version:	3
 * Serial Number:	02 09 60 9D 81 21 CC 22 5B 01 39
 * Not Valid Before:	2020-02-26
 * Not Valid After:	2050-02-26
 * Certificate Fingerprints
 * SHA1:	9E 7A 7D C0 55 8A 19 AC A5 81 A5 C9 80 BB FD BC B2 F2 2E 47
 * MD5:	D7 29 78 C1 38 6F 7D 13 CF 4E 85 8C 73 BD 18 1F
 * Public Key Info
 * Key Algorithm:	Elliptic Curve
 * Key Parameters:	06 08 2A 86 48 CE 3D 03 01 07
 * Key Size:	256
 * Key SHA1 Fingerprint:	D1 DB F5 77 6A C9 09 5F EA 75 BD 75 79 FE 9C EB 25 5C 78 D4
 * Public Key:	04 BB B0 18 24 37 7A 35 EC 76 E1 80 D1 D3 94 8D 6A C8 F0 37 8F F8 0E BF CE 2F F3 1C 15 45 5D 52 DE 9F 7D 1E 46 D6 E1 A7 1A 1A 86 DB 2A 0F A1 74 2D E7 FA 94 18 42 B5 E2 66 01 FF 9E D1 3E 0A A2 6C
 * Signature
 * Signature Algorithm:	SHA256 with ECDSA
 * Signature:	30 46 02 21 00 CE C9 0B AC CC 33 52 74 00 2A F0 B4 80 8F FF A3 04 41 69 82 CF 22 1C 2D 27 E7 DA A6 0D 79 B8 76 02 21 00 C1 73 B4 0C 1E 37 3A 71 01 8A AD C1 42 81 31 41 C1 FA C2 A7 4A 3E 28 FD 08 1B 34 23 9F 88 A6 86
 */
#define LEAF_CERT { 0x30,0x82,0x01,0x8F,0x30,0x82,0x01,0x34,0xA0,0x03,0x02,0x01,0x02,0x02,0x0B,0x02,0x09,0x60,0x9D,0x81,\
                    0x21,0xCC,0x22,0x5B,0x01,0x39,0x30,0x0A,0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x30,0x4F,\
                    0x31,0x0B,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x4E,0x4C,0x31,0x1E,0x30,0x1C,0x06,0x03,0x55,\
                    0x04,0x0A,0x0C,0x15,0x53,0x54,0x4D,0x69,0x63,0x72,0x6F,0x65,0x6C,0x65,0x63,0x74,0x72,0x6F,0x6E,0x69,\
                    0x63,0x73,0x20,0x6E,0x76,0x31,0x20,0x30,0x1E,0x06,0x03,0x55,0x04,0x03,0x0C,0x17,0x53,0x54,0x4D,0x20,\
                    0x53,0x54,0x53,0x41,0x46,0x45,0x2D,0x41,0x20,0x50,0x52,0x4F,0x44,0x20,0x43,0x41,0x20,0x30,0x31,0x30,\
                    0x20,0x17,0x0D,0x32,0x30,0x30,0x32,0x32,0x36,0x30,0x30,0x30,0x30,0x30,0x30,0x5A,0x18,0x0F,0x32,0x30,\
                    0x35,0x30,0x30,0x32,0x32,0x36,0x30,0x30,0x30,0x30,0x30,0x30,0x5A,0x30,0x46,0x31,0x0B,0x30,0x09,0x06,\
                    0x03,0x55,0x04,0x06,0x13,0x02,0x46,0x52,0x31,0x1B,0x30,0x19,0x06,0x03,0x55,0x04,0x0A,0x0C,0x12,0x53,\
                    0x54,0x4D,0x69,0x63,0x72,0x6F,0x65,0x6C,0x65,0x63,0x74,0x72,0x6F,0x6E,0x69,0x63,0x73,0x31,0x1A,0x30,\
                    0x18,0x06,0x03,0x55,0x04,0x03,0x0C,0x11,0x53,0x54,0x53,0x41,0x46,0x45,0x2D,0x41,0x31,0x31,0x30,0x20,\
                    0x45,0x56,0x41,0x4C,0x32,0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,0x06,0x08,\
                    0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0xBB,0xB0,0x18,0x24,0x37,0x7A,0x35,0xEC,\
                    0x76,0xE1,0x80,0xD1,0xD3,0x94,0x8D,0x6A,0xC8,0xF0,0x37,0x8F,0xF8,0x0E,0xBF,0xCE,0x2F,0xF3,0x1C,0x15,\
                    0x45,0x5D,0x52,0xDE,0x9F,0x7D,0x1E,0x46,0xD6,0xE1,0xA7,0x1A,0x1A,0x86,0xDB,0x2A,0x0F,0xA1,0x74,0x2D,\
                    0xE7,0xFA,0x94,0x18,0x42,0xB5,0xE2,0x66,0x01,0xFF,0x9E,0xD1,0x3E,0x0A,0xA2,0x6C,0x30,0x0A,0x06,0x08,\
                    0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02,0x03,0x49,0x00,0x30,0x46,0x02,0x21,0x00,0xCE,0xC9,0x0B,0xAC,\
                    0xCC,0x33,0x52,0x74,0x00,0x2A,0xF0,0xB4,0x80,0x8F,0xFF,0xA3,0x04,0x41,0x69,0x82,0xCF,0x22,0x1C,0x2D,\
                    0x27,0xE7,0xDA,0xA6,0x0D,0x79,0xB8,0x76,0x02,0x21,0x00,0xC1,0x73,0xB4,0x0C,0x1E,0x37,0x3A,0x71,0x01,\
                    0x8A,0xAD,0xC1,0x42,0x81,0x31,0x41,0xC1,0xFA,0xC2,0xA7,0x4A,0x3E,0x28,0xFD,0x08,0x1B,0x34,0x23,0x9F,\
                    0x88,0xA6,0x86 }
// @formatter:on

typedef struct LoRaWAN_Credentials
{
  uint8_t DeviceEUI[8];
  uint8_t JoinEUI[8];
  uint8_t AppKey[16];
  uint8_t NetworkKey[16];
  uint8_t NetworkKey2[16];

} LoRaWAN_Credentials_t;

int32_t DataPartition(StSafeA_Handle_t *handle);

#endif /* INC_STSAFE_DATA_PARTITION_H_ */
