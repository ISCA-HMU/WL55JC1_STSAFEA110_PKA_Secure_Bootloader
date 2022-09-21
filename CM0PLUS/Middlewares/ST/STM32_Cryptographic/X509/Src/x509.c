/**
  ******************************************************************************
  * @file    x509.c
  * @author  AST Security
  * @version V0.2
  * @date    24-February-2017
  * @brief   x509 certificate Parser
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2016 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
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


#include <stdint.h>
#include <string.h>
#include "x509.h"
#include "x509_prints.h"
#include "x509_subparsing.h"

/* Parse tbsCertificate */
static void parsetbsCertificate(const uint8_t *tbs, int32_t tbsSize, intCert_stt *intCert);

/**
* @brief  Initialize a certificate (\ref intCert_stt) to an empty one
* @param[in,out]  *cert pointer to the intCert_stt to be initialized
* @note  This functions should be called before parsing a certificate
*/
void initIntCert(intCert_stt *cert)
{
  cert->tbs = NULL;
  cert->tbsSize = -1;
  cert->x509Version = -1;
  cert->serialNumber = NULL;
  cert->serialNumberSize = -1;
  cert->signature = -1;
  cert->issuer = NULL;
  cert->issuerSize = -1;
  cert->validity = NULL;
  cert->validitySize = -1;
  cert->subject = NULL;
  cert->subjectSize = -1;
  cert->EllipticCurve = -1;
  cert->PubKey.fsize = 0;
  cert->PubKey.pX = NULL;
  cert->PubKey.pY = NULL;
  cert->extensions = NULL;
  cert->extensionsSize = -1;

  cert->SignatureAlgorithm = -1;

  cert->Sign.pR = NULL;
  cert->Sign.pS = NULL;
  cert->Sign.rSize = 0;
  cert->Sign.sSize = 0;

  cert->extensionsFlags = 0;
}

/**
* @brief  Copy a certificate (\ref intCert_stt) into another structure
* @param[out]  *copiedCert pointer to the intCert_stt that will be written
* @param[out]  *originalCert pointer to the intCert_stt that will be copied
*/
void copyCert(intCert_stt *copiedCert, const intCert_stt *originalCert)
{
  *copiedCert = *originalCert;
}

/**
* @brief  Parse the extensions part of a certificate
* @param[in]  *extensions pointer to the extensions part of a certificate
* @param[in]  extensionsSize Size of the extensions field
* @param[out] *intCert pointer to the intCert_stt that will be filled
*/
static void parseExtensions(const uint8_t *extensions, int32_t extensionsSize, intCert_stt *intCert)
{
  const uint8_t *next_value;
  int32_t size, tag, parsed;
  extension_stt ext_st = {.type = -1, .value = NULL, .valueSize = 0};
  /* Start parsing the extensions, extensions is a sequence */
  tag = identifyASN1TLV(extensions, &parsed, &size, &next_value); 
  if (tag == TAG_SEQUENCE)
  {
    /* Now we loop over sequences */
    while (next_value < extensions + extensionsSize)
    {
      tag = identifyASN1TLV(next_value, &parsed, &size, &next_value);
      if (tag == TAG_SEQUENCE)
      {      
        parseExtension(next_value, &intCert->extensionsFlags, &ext_st);      
      }
      next_value += size;
    }    
  }
}

/**
* @brief  Parse the tbs part of a certificate
* @param[in]  *tbs pointer to the TBSCertificate field of a certificate 
* @param[in]  *tbsSize size of the TBSCertificate
* @param[out] *intCert pointer to the intCert_stt that will be filled
*/
static void parsetbsCertificate(const uint8_t *tbs, int32_t tbsSize, intCert_stt *intCert)
{
  const uint8_t *next_value;
  int32_t size, tag, parsed;
  /* Start parsing the TBS, tbs is a sequence */
  tag = identifyASN1TLV(tbs, &parsed, &size, &next_value);
  if (tag == TAG_SEQUENCE)
  {
    /* Now we expect the version */
    tag = identifyASN1TLV(next_value, &parsed, &size, &next_value);
    if (tag == TAG_x509VERSION)
    {
      parseX509version(next_value, intCert, &next_value);
    }
    else /* The Version is optional, if it's not present then 0 (v1) is assumed */
    {
      intCert->x509Version = 0;
      next_value -= parsed;
    }
    /* Move on to Serial Number */
    parseInteger(next_value, &intCert->serialNumber, &intCert->serialNumberSize, &next_value);
    /* Parse tbsSignature(Algorihtm)*/
    parseSignatureAlgorithm(next_value, &intCert->signature, &next_value);
    /* Now we face the issuer */
    tag = identifyASN1TLV(next_value, &parsed, &size, &next_value);
    if (tag == TAG_SEQUENCE)
    {
      intCert->issuer = next_value - parsed;
      intCert->issuerSize = size + parsed;
    }    
    next_value += size; /* Issuer is not parsed */
    /* Now we face validity */
    tag = identifyASN1TLV(next_value, &parsed, &size, &next_value);
    if (tag == TAG_SEQUENCE)
    {
      intCert->validity = next_value - parsed;
      intCert->validitySize = size + parsed;
    }
    next_value += size; /* Validity is not parsed */
    /* Now we face Subject */
    tag = identifyASN1TLV(next_value, &parsed, &size, &next_value);
    if (tag == TAG_SEQUENCE)
    {
      intCert->subject = next_value - parsed;
      intCert->subjectSize = size + parsed;
    }
    next_value += size; /* Subject is not parsed */
    /* Now we face SubjectPublicKey */
    parseECCPublicKey(next_value, intCert, &next_value);
    /* Now we face Optional Extensions, but those are optional */
    if (next_value < tbs + tbsSize)
    {
      tag = identifyASN1TLV(next_value, &parsed, &size, &next_value);
      if (tag == TAG_extensions)
      {
        intCert->extensions = next_value;
        intCert->extensionsSize = size;
        parseExtensions(intCert->extensions, intCert->extensionsSize, intCert);
      }
    }    
  }
}

/**
* @brief  Parse an x509 certificate
* @param[in]  *cert pointer to the x509 certificate to be parsed 
* @param[in]  certSize size (in bytes) of the certificate
* @param[out] *intCert pointer to the intCert_stt that will be filled
* @param[out] **next pointer to cert array after the parsed certificate (it can be NULL)
* @return 0 if success, negative numbers for errors
* @retval 0 Success (This is \b not an indicator of the certificate validity)
* @retval ERR_EXPECTED_SEQUENCE A sequence was expected
* @warning The parsed certificated could be empty, it is necessary to call a function
*       which verifies the certificate to be valid before using it.
*/
int32_t parseCert(const uint8_t *cert, intCert_stt *intCert, const uint8_t **next)
{
  int32_t total_size, tag, size, parsed;
  const uint8_t *next_thing;

  initIntCert(intCert);
  /* First we start by looking at the first item, this will be used to set the size of the whole certificate */
  /* Then the parsing of the other subfields will start */
  tag = identifyASN1TLV(cert, &parsed, &total_size, &next_thing);
  if (tag != TAG_SEQUENCE)
  {     
    return(ERR_EXPECTED_SEQUENCE);
  }
//  total_size = total_size + parsed;
  /* Get tbs */
  tag = identifyASN1TLV(next_thing, &parsed, &size, &next_thing);
  if (tag != TAG_SEQUENCE)
  {
    return(ERR_EXPECTED_SEQUENCE);
  }
  intCert->tbs = next_thing-parsed;
  intCert->tbsSize = size+parsed;
  
  /* Get SignatureAlgorithm */
  next_thing += size;
  parseSignatureAlgorithm(next_thing, &intCert->SignatureAlgorithm, &next_thing);

  /* Now we should have the Signature. If it's ECDSA parse it! */
  if (intCert->SignatureAlgorithm != -1)
  {
    parseECDSAsignature(next_thing, intCert, &next_thing);
  }

  /* We have completed the parsing of the TOP level */
  /* Let's move on to parse the tbs */
  parsetbsCertificate(intCert->tbs, intCert->tbsSize, intCert);

  if (next != NULL)
  {
    *next = next_thing;
  }  

  return(0);
}

/**
* @brief  Check that an imported x509 certificate is valid
* @param[in]  *intCert pointer to the parsed x509 certificate to be validated
* @param[in]  *currentTime pointer to a validity_stt with the current DateTime. If NULL no date check is done.
* @return Validity of certificate
* @retval 1 Certificate is Valid
* @retval -1 Certificate is Not Valid
* @warning If currentTime==NULL the check on the validity dates of the certificate will be bypassed.
*/
int32_t isValidCert(const intCert_stt *intCert, const validity_stt *currentTime)
{
  if (
    (intCert->issuer == NULL || intCert->issuerSize == -1) ||
    (intCert->subject == NULL || intCert->subjectSize == -1) ||
    (intCert->serialNumber == NULL || intCert->serialNumberSize == -1) ||
    (intCert->signature == -1 || intCert->SignatureAlgorithm != intCert->signature) ||
    (intCert->validity == NULL || intCert->validitySize == -1) ||
    (intCert->EllipticCurve == -1 || intCert->x509Version == -1)||
    (intCert->PubKey.fsize <= 0 || intCert->PubKey.pX == NULL || intCert->PubKey.pY == NULL) ||
    (intCert->Sign.pR == NULL || intCert->Sign.rSize == -1) ||
    (intCert->Sign.pS == NULL || intCert->Sign.sSize == -1)
    )
  {
    return(-1);
  }

  if (currentTime != NULL)
  {
    validity_stt notBefore_st, notAfter_st;    
    parseValidity(intCert->validity, &notBefore_st, &notAfter_st, NULL);

    if (dateCompare(currentTime, &notBefore_st) < 0)
    {
      return(-1);
    }

    if (dateCompare(currentTime, &notAfter_st) > 0)
    {
      return(-1);
    }
  }

  return(1);
}


/**
* @brief  Check whether a certificate is marked as belonging to a CA
* @param[in]  *cert pointer to the parsed x509 certificate to be checked
* @return CA Status
* @retval -1 certificate doesn't belong to a CA
* @retval 0 certificate belongs to a CA with no pathLenConstraint 
* @retval positive integer, certificate belongs to a CA  pathLenConstraint
*/
int32_t isCA(const intCert_stt *cert)
{
  if (((cert->extensionsFlags >> 0) & 1U) == 1U)
  {
    /* BasicContrain is present */
    if (((cert->extensionsFlags >> 2) & 1U) == 1U)
    {
      /* This is a CA */
      uint32_t tmp = (cert->extensionsFlags >> 4) & 15U;
      return (int32_t)tmp;
    }
  }
  return -1;
}
