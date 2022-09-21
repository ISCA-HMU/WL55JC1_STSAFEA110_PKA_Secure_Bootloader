#include "stsafe_data_partition.h"
#include "stsafe_common.h"


int32_t DataPartitionQuery(StSafeA_Handle_t *handle)
{
  int index = 0;

  StSafeA_ResponseCode_t response = STSAFEA_OK;

  StSafeA_ZoneInformationRecordBuffer_t zone_info_record_buffer[8];
  StSafeA_DataPartitionBuffer_t data_partition_buffer;

  data_partition_buffer.pZoneInfoRecord = zone_info_record_buffer;

  STS_CHK(response, StSafeA_DataPartitionQuery(handle, 8, &data_partition_buffer, STSAFEA_MAC_NONE));

  if (response == STSAFEA_OK)
  {
    printf("Data partition buffer length: %d\r\n", data_partition_buffer.Length);
    printf("Data partition number of zones: %d\r\n", data_partition_buffer.NumberOfZones);

    printf("| Zone  | Zone |   Read AC    | Read Access |  Update AC   | Update Access | Data Segment | One-Way |\r\n");
    printf("| Index | Type | Change Right |  Condition  | Change Right |   Condition   |   Length     | Counter |\r\n");

    for (index = 0; index < 8; index++)
    {
// @formatter:off
      printf("|%6d | %4d |     %s    | %11d |     %s     | %13d | %12d | %7u |\r\n",
	     data_partition_buffer.pZoneInfoRecord[index].Index,
	     data_partition_buffer.pZoneInfoRecord[index].ZoneType,
  	     data_partition_buffer.pZoneInfoRecord[index].ReadAcChangeRight ? "TRUE" : "FALSE",
  	     data_partition_buffer.pZoneInfoRecord[index].ReadAccessCondition,
  	     data_partition_buffer.pZoneInfoRecord[index].UpdateAcChangeRight ? "TRUE" : "FALSE",
  	     data_partition_buffer.pZoneInfoRecord[index].UpdateAccessCondition,
  	     data_partition_buffer.pZoneInfoRecord[index].DataSegmentLength,
  	    (unsigned int)data_partition_buffer.pZoneInfoRecord[index].OneWayCounter);
// @formatter:on
    }
  }

  return response;
}

int32_t UpdateDataPartition(StSafeA_Handle_t *handle)
{
  StSafeA_ResponseCode_t response = STSAFEA_OK;

  LoRaWAN_Credentials_t LoRaWAN_Credentials = {LORAWAN_DEVICE_EUI, LORAWAN_JOIN_EUI, LORAWAN_APP_KEY, LORAWAN_NWK_KEY, LORAWAN_NWK_KEY};

  StSafeA_LVBuffer_t pInLVData;

  pInLVData.Length = 64;
  pInLVData.Data = (uint8_t*) &LoRaWAN_Credentials;

  STS_CHK(response, (int32_t)StSafeA_Update(handle, STSAFEA_FLAG_FALSE, STSAFEA_FLAG_FALSE, STSAFEA_FLAG_FALSE, STSAFEA_AC_ALWAYS, 2, 0, &pInLVData, STSAFEA_MAC_HOST_CRMAC));

  if (response == STSAFEA_OK)
  {
    printf("Writing to Data Partition Zone: OK\r\n");
  }
  else
  {
    printf("Writing to Data Partition Zone: Failed\r\n");
  }

  return response;
}

int32_t ReadDataPartition(StSafeA_Handle_t *handle)
{
  StSafeA_ResponseCode_t response = STSAFEA_OK;

  LoRaWAN_Credentials_t LoRaWAN_Credentials = {0};

  StSafeA_LVBuffer_t pOutLVResponse;

  pOutLVResponse.Length = 64;
  pOutLVResponse.Data = (uint8_t*) &LoRaWAN_Credentials;

  STS_CHK(response, (int32_t)StSafeA_Read(handle, STSAFEA_FLAG_FALSE, STSAFEA_FLAG_FALSE, STSAFEA_AC_ALWAYS, 2, 0, 64, 64, &pOutLVResponse, STSAFEA_MAC_NONE));

  if (response == STSAFEA_OK)
  {
    printf("Reading from Data Partition Zone: OK\r\n\r\n");

    printf("Device EUI:  %02X %02X %02X %02X %02X %02X %02X %02X\r\n", LoRaWAN_Credentials.DeviceEUI[0], LoRaWAN_Credentials.DeviceEUI[1], LoRaWAN_Credentials.DeviceEUI[2], LoRaWAN_Credentials.DeviceEUI[3], LoRaWAN_Credentials.DeviceEUI[4], LoRaWAN_Credentials.DeviceEUI[5], LoRaWAN_Credentials.DeviceEUI[6], LoRaWAN_Credentials.DeviceEUI[7]);
    printf("Join EUI:    %02X %02X %02X %02X %02X %02X %02X %02X\r\n", LoRaWAN_Credentials.JoinEUI[0], LoRaWAN_Credentials.JoinEUI[1], LoRaWAN_Credentials.JoinEUI[2], LoRaWAN_Credentials.JoinEUI[3], LoRaWAN_Credentials.JoinEUI[4], LoRaWAN_Credentials.JoinEUI[5], LoRaWAN_Credentials.JoinEUI[6], LoRaWAN_Credentials.JoinEUI[7]);
    printf("App Key:     %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n", LoRaWAN_Credentials.AppKey[0], LoRaWAN_Credentials.AppKey[1], LoRaWAN_Credentials.AppKey[2], LoRaWAN_Credentials.AppKey[3], LoRaWAN_Credentials.AppKey[4], LoRaWAN_Credentials.AppKey[5], LoRaWAN_Credentials.AppKey[6], LoRaWAN_Credentials.AppKey[7], LoRaWAN_Credentials.AppKey[8], LoRaWAN_Credentials.AppKey[9], LoRaWAN_Credentials.AppKey[10], LoRaWAN_Credentials.AppKey[11], LoRaWAN_Credentials.AppKey[12], LoRaWAN_Credentials.AppKey[13], LoRaWAN_Credentials.AppKey[14], LoRaWAN_Credentials.AppKey[15]);
    printf("Network Key: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n", LoRaWAN_Credentials.NetworkKey[0], LoRaWAN_Credentials.NetworkKey[1], LoRaWAN_Credentials.NetworkKey[2], LoRaWAN_Credentials.NetworkKey[3], LoRaWAN_Credentials.NetworkKey[4], LoRaWAN_Credentials.NetworkKey[5], LoRaWAN_Credentials.NetworkKey[6], LoRaWAN_Credentials.NetworkKey[7], LoRaWAN_Credentials.NetworkKey[8], LoRaWAN_Credentials.NetworkKey[9], LoRaWAN_Credentials.NetworkKey[10], LoRaWAN_Credentials.NetworkKey[11], LoRaWAN_Credentials.NetworkKey[12], LoRaWAN_Credentials.NetworkKey[13], LoRaWAN_Credentials.NetworkKey[14], LoRaWAN_Credentials.NetworkKey[15]);
    printf("Network Key: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n", LoRaWAN_Credentials.NetworkKey2[0], LoRaWAN_Credentials.NetworkKey2[1], LoRaWAN_Credentials.NetworkKey2[2], LoRaWAN_Credentials.NetworkKey2[3], LoRaWAN_Credentials.NetworkKey2[4], LoRaWAN_Credentials.NetworkKey2[5], LoRaWAN_Credentials.NetworkKey2[6], LoRaWAN_Credentials.NetworkKey2[7], LoRaWAN_Credentials.NetworkKey2[8], LoRaWAN_Credentials.NetworkKey2[9], LoRaWAN_Credentials.NetworkKey2[10], LoRaWAN_Credentials.NetworkKey2[11], LoRaWAN_Credentials.NetworkKey2[12], LoRaWAN_Credentials.NetworkKey2[13], LoRaWAN_Credentials.NetworkKey2[14], LoRaWAN_Credentials.NetworkKey2[15]);
  }
  else
  {
    printf("Reading from Data Partition Zone: Error %d\r\n", response);
  }

  return response;
}

int32_t ReadLeafCertificate(StSafeA_Handle_t *handle)
{
  StSafeA_ResponseCode_t response = STSAFEA_OK;

  StSafeA_LVBuffer_t pOutLVResponse;

  uint8_t certificate_data[1696] = {0};

  int index_out, index_in = 0;

  pOutLVResponse.Length = 1696;
  pOutLVResponse.Data = (uint8_t*) certificate_data;

  STS_CHK(response, (int32_t)StSafeA_Read(handle, STSAFEA_FLAG_FALSE, STSAFEA_FLAG_FALSE, STSAFEA_AC_ALWAYS, 0, 0, 403, 403, &pOutLVResponse, STSAFEA_MAC_NONE));

  for (index_out = 0; index_out < 21; index_out++)
  {
    for (index_in = 0; index_in < 20; index_in++)
    {
#if LEAF_CERT_OUTPUT_FORMAT == LEAF_CERT_HEX_ARRAY_STYLE
      /*
       * This output style is useful to create an array that contains the certificate and use it in your C application.
       */
      printf("0x%02X,", pOutLVResponse.Data[(index_out * 20) + index_in]);
#elif LEAF_CERT_OUTPUT_FORMAT == LEAF_CERT_DER_STYLE
      /*
       * The read leaf certificate is a DER-encoded X509 certificate.
       *
       * This output style of the certificate is useful to use it for creating a DER file.
       * Copy the output leaf certificate to a file named for example ascii_cert.der
       *
       * In a linux terminal use the following command to convert it to binary file:
       * xxd -r -p ascii_cert.der > binary_cert.der.
       *
       * Now, by using openssl x509 commands this certificate can be viewed or converted to another format for example PEM.
       */
      printf("%02X", pOutLVResponse.Data[(index_out * 20) + index_in]);
#endif
    }

    printf("\r\n");
  }

  return response;
}

int32_t DataPartition(StSafeA_Handle_t *handle)
{
  int32_t StatusCode = 0;

  printf("STSAFE A110 Data Partitions\r\n");

  /* Read and print the current configuration of the Data Partition Zones of the STSAFE A110*/
  STS_CHK(StatusCode, DataPartitionQuery(handle));

  /* Retrieve the leaf certificate of the STFSAFE A110 from Zone 0*/
  STS_CHK(StatusCode, ReadLeafCertificate(handle));

  /* Write the LoRaWAN credentials of the WL55JC1 board to Zone 1 of the STSAFE A110 */
  STS_CHK(StatusCode, UpdateDataPartition(handle));

  /* Read the LoRaWAN credentials of the WL55JC1 board from Zone 1 of the STSAFE A110 */
  STS_CHK(StatusCode, ReadDataPartition(handle));

  return StatusCode;
}

