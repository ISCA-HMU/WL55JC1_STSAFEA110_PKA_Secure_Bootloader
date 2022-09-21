#!/bin/bash

#Create a binary file that contains the following structure:
#
# | Magic number| User FW Flash Address Offset | User FW Size in HEX Format | User FW ECDSA Signature (DER format) |
# |     4 Bytes |                      4 Bytes |                    4 Bytes |                              70 Bytes|
#
# NOTE:
# ECDSA requires the values to be unsigned integers.
# Thus the r and S-values are padded with an extra 0x00 byte if the highest bit indicates a negative value (highest bit is 1).
# If either the r or the S-value has the highest bit set then it needs extra padding of 1 byte which results in a 71-byte-signature.
# If the highest bits of both values are set, then both need padding of one byte each resulting in a 72-byte-signature.
#
# The ECDSA DER signature format is:
#
# Byte 0x30 which is the header byte to indicate compound structure.
# One byte that encodes the length of the following data.
# Byte 0x02 that is a header byte indicating an integer.
# One byte that encodes the length of the following r value.
# The r value as a big-endian integer.
# Byte 0x02 that is a header byte indicating an integer.
# One byte to encode the length of the following s value.
# The s value as a big-endian integer.
#
# NOTE: This binary must be written to the last flash page of the target STM32 board using the STM32CubeProgrammer.
#       This structure contains info that the Secure Bootloader uses to validate the user application prior to jumping on it.

# The magic number is needed so that the binary file is considered valid by the STM32CubeProgrammer.
MAGIC_NUMBER="53544D32"

# Set the flash address offset where the user application binary will be stored.
ADDRESS_OFFSET="08001800"

# Get the size of the user application binary file.
BINARY_SIZE=$(wc -c < UserApplication_CM0PLUS.bin)

echo "Size of the binary in DER format: $BINARY_SIZE Bytes"

# Get the size of the user application binary file in HEX format.
HEX_BINARY_SIZE=$(printf "%08x" $BINARY_SIZE)

echo "Size of the binary in HEX format: 0x$HEX_BINARY_SIZE"

echo "Signing the user application binary with the developer's private key"

# Sign the user application binary with the developer's private key.
openssl dgst -sha256 -sign developer_private_key.pem -out binary_signature.sig UserApplication_CM0PLUS.bin

openssl dgst -sha256 UserApplication_CM0PLUS.bin

echo "Verifying the correctness of the signature"

openssl dgst -sha256 -verify developer_public_key.pem -signature binary_signature.sig UserApplication_CM0PLUS.bin

# Get the signature in HEX format.
ECDSA_SIGNATURE_DER=$(xxd -p -u binary_signature.sig | tr -d "\n")

echo "ECDSA signature in DER format:"

echo "$ECDSA_SIGNATURE_DER"

echo "$MAGIC_NUMBER$ADDRESS_OFFSET$HEX_BINARY_SIZE$ECDSA_SIGNATURE_DER" | xxd -r -p > trusted_application_struct.bin

echo "Data to be flashed:"
xxd -p -u trusted_application_struct.bin | tr -d "\n"

echo -e "\n"
