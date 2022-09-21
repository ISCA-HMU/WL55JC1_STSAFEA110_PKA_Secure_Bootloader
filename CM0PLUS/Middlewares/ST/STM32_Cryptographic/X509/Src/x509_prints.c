/**
  ******************************************************************************
  * @file    x509_prints.c
  * @author  AST Security
  * @version V0.2
  * @date    16-November-2016
  * @brief   informational functions for the x509 parsing
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2016 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */


/** @note these functions are most used for debuggin purpose, don't expect much comments/docs */

#include "x509_prints.h"
#include "x509_subparsing.h"

static void printExtensions(uint32_t extensionsFlags);

/**
* @brief  Print the TAG
* @param[in]  tag of ASN.1 TLV  (got from \ref identifyASN1TLV )
*/
void printTag(int32_t tag)
{
  switch (tag)
  {
  case TAG_BOOLEAN:
    printf("Boolean");
    break;
  case TAG_INTEGER:
    printf("Integer");
    break;
  case TAG_BITSTRING:
    printf("Bistring");
    break;
  case TAG_OCTETSTRING:
    printf("Octectstring");
    break;
  case TAG_NULL:
    printf("Null");
    break;
  case TAG_OBJECT_IDENTIFIER:
    printf("Object Identifier");
    break;
  case TAG_ObjectDescriptor:
    printf("Object Descriptor");
    break;
  case TAG_ENUMERATED:
    printf("Enumerated");
    break;
  case TAG_UTF8String:
    printf("UTF8");
    break;
  case TAG_SEQUENCE:
    printf("Sequence");
    break;
  case TAG_SET:
    printf("Set");
    break;
  case TAG_PrintableString:
    printf("PrintableString");
    break;
  case TAG_IA5String:
    printf("IA5String");
    break;
  case TAG_UTCTime:
    printf("UTCTime");
    break;
  case TAG_GeneralizedTime:
    printf("GeneralizedTime");
    break;
  case TAG_x509VERSION:
    printf("x509VERSION");
    break;
  case TAG_subjectUniqueID:
    printf("subjectUniqueID");
    break;
  case TAG_extensions:
    printf("extensions");
    break;
  case TAG_issuerUniqueID:
    printf("issuerUniqueID");
    break;
  }
}

/**
* @brief  Print the Signature Algorithm
* @param[in]  internal type of SignatureAlgorithm (got from \ref identifySignatureAlgorithm)
*/
void printSignatureAlgorithm(int32_t type)
{
  switch (type)
  {
  case SIG_ECDSA_SHA1:
    printf("ecdsa-with-SHA1");
    break;
  case SIG_ECDSA_SHA224:
    printf("ecdsa-with-SHA224");
    break;	
  case SIG_ECDSA_SHA256:
    printf("ecdsa-with-SHA256");
    break;
  case SIG_ECDSA_SHA384:
    printf("ecdsa-with-SHA384");
    break;
  case SIG_ECDSA_SHA512:
    printf("ecdsa-with-SHA512");
    break;
  default:
    printf("Failed Identification of SignatureAlgorithm");
    break;
  }
}

/**
* @brief  Print the Attribute
* @param[in]  internal type of Attribute (got from \ref identifyAttribute)
*/
void printAttribute(int32_t type)
{
  switch (type)
  {
  case ATTR_CN:
    printf("CommonName");
    break;
  case ATTR_C:
    printf("CountryName");
    break;
  case ATTR_SN:
    printf("SerialNumber");
    break;
  case ATTR_DN:
    printf("DistinguishedName");
    break;
  case ATTR_ON:
    printf("OrganizationalName");
    break;
  case ATTR_OUN:
    printf("OrganizationalUnitName");
    break;
  case ATTR_SOPN:
    printf("StateOrProvinceName");
    break;
  case ATTR_LN:
    printf("LocalityName");
    break;
  case ATTR_UID:
    printf("UniqueIdentifier");
    break;
  default:
    printf("Failed Identification of Attribute");
    break;
  }
}


/**
* @brief  Print the Elliptic Curve Name
* @param[in]  internal type of EllipticCurve (got from \ref identifyEllipticCurve)
*/
void printEllipticCurve(int32_t type)
{
  switch (type)
  {
  case EC_P256:
    printf("P-256");
    break;
  case EC_P384:
    printf("P-384");
    break;
  case EC_P521:
    printf("P-521");
    break;
  case EC_bp256r1:
    printf("brainpoolP256r1");
    break;
  case EC_bp256t1:
    printf("brainpoolP256t1");
    break;
  case EC_bp384r1:
    printf("brainpoolP384r1");
    break;
  case EC_bp384t1:
    printf("brainpoolP384t1");
    break;
  case EC_bp512r1:
    printf("brainpoolP512r1");
    break;
  case EC_bp512t1:
    printf("brainpoolP512t1");
    break;
  default:
    printf("Failed Identification of EllipticCurve");
    break;
  }
}


/**
* @brief  Print a BITSTRING
* @param[in]  *value pointer to the value of a BITSTRING (got from \ref identifyASN1TLV )
* @param[in]  size size (in bytes) of the value field of this BITSTRING (got from \ref identifyASN1TLV )
* @retval    0 Success
* @retval    -1 Failure. The bitstring excludes some of the LSBits of the LSB, which \
*                        this implementation doesn't support
*/
int32_t printBitString(const uint8_t *value, int32_t size)
{
  int32_t i;
  /* The first byte of Value identifies the number of discarded bits in the LSB.
  This is a feature we don't support
  */
  if (value[0] != 0)
  {
    printf("BITSTRING exclues some LSBits, we don't handle that, error!\r\n");
    return(-1);
  }
  /* Print the remaining string */
  for (i = 1; i < size; i++)
  {
    printf("%02X", value[i]);
    if (i % 16 == 0 && i != size - 1)
      printf("\r\n\t\t");
  }
  return(0);
}

/**
* @brief  Print an INTEGER
* @param[in]  *value pointer to the value of a INTEGER (got from \ref identifyASN1TLV )
* @param[in]  size size (in bytes) of the value field of this INTEGER (got from \ref identifyASN1TLV )
* @retval    0 Success
* @retval    -1 Failure. The INTEGER is negative, and \
*                        this implementation doesn't support it
*/
int32_t printInteger(const uint8_t *value, int32_t size)
{
  int32_t i = 0;
  /* The first byte tells us if it's positive or negative. We don't support negative */
  if (value[0] >> 7 == 1)
  {
    printf("Integer is negative, we don't handle that, error!\r\n");
    return(-1);
  }
  /* First byte might be zero in case Integer is positive and first byte >127 */
  /* So skip it */
  if (value[0] == 0)
  {
    i++;
  }
  /* And print the rest */
  for (; i < size; i++)
  {
    printf("%02X", value[i]);
    if (i % 16 == 0 && (i != size - 1) && i != 0)
      printf("\r\n\t\t");
  }
  return(0);
}

/* Print a byte buffer */
static void print_buffer(const char * str, const uint8_t * buf, int32_t bufsize)
{
  int32_t i = 0;
  printf("%s", str);
  for (i = 0; i < bufsize; i++)
  {
    printf("%02X", buf[i]);
  }
  printf("\r\n");
}

/** @brief print informations about a intCert_stt certificate */
void printParsedCert(intCert_stt *intCert)
{
  //printf("Fields: %08X\n", intCert->fields);
  //printFields(intCert->fields);

  printf("x509 Version: %d\r\n", intCert->x509Version + 1);
  if (intCert->serialNumber != NULL && intCert->serialNumberSize > 0)
    print_buffer("SerialNumber: ", intCert->serialNumber, intCert->serialNumberSize);
  if (intCert->issuer != NULL && intCert->issuerSize > 0)
  {
    printf("Issuer:\r\n");
    parsePrintName(intCert->issuer, intCert->issuerSize);
  }
  if (intCert->subject != NULL && intCert->subjectSize > 0)
  {
    printf("Subject:\r\n");
    parsePrintName(intCert->subject, intCert->subjectSize);
  }
  printValidity(intCert->validity);

  printf("SignatureAlgorithm: "); printSignatureAlgorithm(intCert->SignatureAlgorithm); printf("\r\n");
  printf("tbsSignature: "); printSignatureAlgorithm(intCert->signature);  printf("\r\n");
  printf("EllipticCurve: ");  printEllipticCurve(intCert->EllipticCurve); printf("\r\n");
  printf("Cert PubKey: \r\n\t");
  print_buffer("X: ", intCert->PubKey.pX, intCert->PubKey.fsize);
  print_buffer("\tY: ", intCert->PubKey.pY, intCert->PubKey.fsize);
  printf("Cert Signature: \r\n\t");
  print_buffer("r: ", intCert->Sign.pR, intCert->Sign.rSize);
  print_buffer("\ts :", intCert->Sign.pS, intCert->Sign.sSize);

  printExtensions(intCert->extensionsFlags);
}

/**
* @brief  Parse a Name Attribute
* @param[in]  *p pointer to the Name Attribute SET to be parsed
* @param[out] *attribute_st pointer to attribute_stt structure that will be filled
* @param[out] **next_thing output pointer to next TLV
* @note this functions doesn't parse the set correctly, it works most time so it's ok for printing
*       but for certificate checking we need something more advanced 
*/
void simpleParseAttribute(const uint8_t *p, attribute_stt *attribute_st, const uint8_t **next_thing)
{
  int32_t total_size, size, parsed, tag;
  const uint8_t *next = p;
  tag = identifyASN1TLV(next, &parsed, &total_size, &next);
  total_size += parsed;
  if (tag == TAG_SET)
  {
    tag = identifyASN1TLV(next, &parsed, &size, &next);
    if (tag == TAG_SEQUENCE)
    {
      tag = identifyASN1TLV(next, &parsed, &size, &next);
      if (tag == TAG_OBJECT_IDENTIFIER)
      {
        attribute_st->type = identifyAttribute(next, size);
        if (attribute_st->type != -1)
        {
          next += size;
          tag = identifyASN1TLV(next, &parsed, &size, &next);
          attribute_st->strFormat = tag;
          attribute_st->str = next;
          attribute_st->strSize = size;
        }
      }
    }
  }
  *next_thing = p + total_size;
}

/** @brief print the attribute of a name field */
void parsePrintName(const uint8_t *name, int32_t nameSize)
{
  int32_t wholesize, tag, parsed;
  const uint8_t *next;
  attribute_stt attribute_st;
  tag = identifyASN1TLV(name, &parsed, &wholesize, &next);
  if (tag == TAG_SEQUENCE)
  {
    /* Here we are inside the name, now loop */
    while (next < name + nameSize)
    {
      attribute_st.type = -1;
      simpleParseAttribute(next, &attribute_st, &next);
      printf("\t"); printAttribute(attribute_st.type); printf(": ");
      if (attribute_st.type != -1 &&
        (attribute_st.strFormat == TAG_PrintableString ||
        attribute_st.strFormat == TAG_UTF8String)
        )
      {
        int32_t i;
        for (i = 0; i < attribute_st.strSize; i++)
        {
          printf("%c", attribute_st.str[i]);
        }
      }
      else if (attribute_st.type != -1 && attribute_st.strFormat == TAG_BITSTRING)
      {
        printBitString(attribute_st.str, attribute_st.strSize);
      }
      printf("\r\n");
    }      
  }
}

/** @brief print the validity of a certificate */
void printValidity(const uint8_t *validity)
{
  validity_stt notBefore_st, notAfter_st;
  const uint8_t *next;
  parseValidity(validity, &notBefore_st, &notAfter_st, &next);
  printf("Validity:\r\n");
  printf("\tNot Before: %04d-%02d-%02d %02d:%02d:%02d\r\n", notBefore_st.year, notBefore_st.month, notBefore_st.days, notBefore_st.hours, notBefore_st.minutes, notBefore_st.seconds);
  printf("\tNot After:  %04d-%02d-%02d %02d:%02d:%02d\r\n", notAfter_st.year, notAfter_st.month, notAfter_st.days, notAfter_st.hours, notAfter_st.minutes, notAfter_st.seconds);
}

/** @brief print the extensionsFlags field of a certificate */
static void printExtensions(uint32_t extensionsFlags)
{
  printf("List of Extensions:\r\n");
  if ((extensionsFlags & 1) == 1)
  {
    printf("\tBasicConstraints: ");
    if (((extensionsFlags >> 1) & 1) == 1)
    {
      printf("Critical. ");
    }
    if (((extensionsFlags >> 2) & 1) == 1)
    {
      printf("CA certificate. ");
    }
    else
    {
      printf("Not a CA certificate. ");
    }
    if (((extensionsFlags >> 3) & 1) == 1)
    {
      printf("PathSize: %d", (extensionsFlags >> 4) & 15);
    }
    printf("\r\n");
  }
  if (((extensionsFlags >> 8) & 1) == 1)
  {
    printf("\tKeyUsage: ");
    if (((extensionsFlags >> 9) & 1) == 1)
    {
      printf("Critical. ");
    }
    if (((extensionsFlags >> (16+0)) & 1) == 1)
    {
      printf("digitalSignature ");
    }
    if (((extensionsFlags >> (16 + 1)) & 1) == 1)
    {
      printf("contentCommitment ");
    }
    if (((extensionsFlags >> (16 + 2)) & 1) == 1)
    {
      printf("keyEncipherment ");
    }
    if (((extensionsFlags >> (16 + 3)) & 1) == 1)
    {
      printf("dataEncipherment ");
    }
    if (((extensionsFlags >> (16 + 4)) & 1) == 1)
    {
      printf("keyAgreement ");
    }
    if (((extensionsFlags >> (16 + 5)) & 1) == 1)
    {
      printf("keyCertSign ");
    }
    if (((extensionsFlags >> (16 + 6)) & 1) == 1)
    {
      printf("cRLSign ");
    }
    if (((extensionsFlags >> (16 + 7)) & 1) == 1)
    {
      printf("encipherOnly ");
    }
    if (((extensionsFlags >> (15)) & 1) == 1)
    {
      printf("decipherOnly ");
    }
    printf("\r\n");
  }

  if (((extensionsFlags >> 24) & 1) == 1)
  {
    printf("\tExtendedKeyUsage: ");
    if (((extensionsFlags >> 25) & 1) == 1)
    {
      printf("Critical. ");
    }
    printf("\r\n");
  }

}

