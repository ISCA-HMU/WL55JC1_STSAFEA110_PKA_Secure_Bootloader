#!/bin/bash

# Delete previous certificates and keys.
rm *.der *.hex *.pem *.h

# Generate a private key for a curve.
openssl ecparam -name prime256v1 -genkey -noout -out developer_private_key.pem

# Generate corresponding public key.
openssl ec -in developer_private_key.pem -pubout -out developer_public_key.pem

# Create a self-signed certificate.
openssl req -new -x509 -key developer_private_key.pem -out developer_certificate.pem -days 3600

# Convert X509 certificate to DER format.
openssl x509 -in developer_certificate.pem -out developer_certificate.der -outform DER

# Store the developer_certificate.der as HEX.
xxd -u -p developer_certificate.der > developer_certificate.hex

# Store the certificate as a C array in a .h header file.
./developer_certificate_c_array.sh
