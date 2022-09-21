#!/bin/bash

# Get as input a string of the DER certificate in HEX and print it as a HEX array.
# It is only useful to make it easier when having a DER file that needs to be used as a C array.
# The output will be 16 HEX bytes per row.

# Read the developer_certificate.hex and store it in a variable while deleted all new line characters to make it be one line.
HEX_CERT=$(cat developer_certificate.hex | tr -d '\n')

CERTIFICATE_SIZE=${#HEX_CERT}

REMAIN_BYTES=$(($CERTIFICATE_SIZE%32))

ROWS=$(($CERTIFICATE_SIZE/32))

{
echo "#define DEVELOPER_CERTIFICATE \\"
	
# Print all the full rows.
for (( i=0; i<$ROWS; i++ ))
do  
   for (( j=0; j<16; j++ ))
   do  
      POSITION=$(($i*32+$j*2))
      echo -n "0x${HEX_CERT:POSITION:2},"
   done
   echo "\\"
done

# Print the remaining bytes that are not part of a full row except for the last byte.
for (( j=0; j<$(($REMAIN_BYTES/2-1)); j++ ))
do  
   POSITION=$(($i*32+$j*2))
   echo -n "0x${HEX_CERT:POSITION:2},"
done

# Print the last byte.
POSITION=$(($i*32+$j*2))
echo -e "0x${HEX_CERT:POSITION:2}\n"
	
} > developer_certificate_array.h
