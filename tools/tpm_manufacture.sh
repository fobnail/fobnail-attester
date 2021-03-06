#!/usr/bin/env bash

SCRIPT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))

KNC=$SCRIPT_DIR/keys_and_certs
CA_PRIV=$KNC/ca_priv.pem
CA_CERT=$KNC/ca_cert.pem
CA_SRL=$KNC/ca.srl
EK_PUB=$KNC/ek_pub.pem
EK_CSR=$KNC/ek.csr
EK_CERT=$KNC/ek_cert.der
CA_CONFIG=$SCRIPT_DIR/ca.config
EK_CONFIG=$SCRIPT_DIR/ek.config
EK_V3_EXT=$SCRIPT_DIR/ek_v3.ext


TPM2_LOG_FILE=/tmp/tpm_manufacture.log

echo -n "Starting log file at: " > $TPM2_LOG_FILE
date >> $TPM2_LOG_FILE

# All tpm2_* commands may print errors when default TPM engine isn't available
# and other are tried one by one. Send those errors to /dev/null to keep output
# clean.
function tpm2 {
	tpm2_$@ >> $TPM2_LOG_FILE 2>&1
	if [[ $? -ne 0 ]]; then
		echo "'$@' failed, aborting."
		exit
	fi
}

while getopts "fkst" arg; do
	case "${arg}" in
	f) echo "Forcing EK certificate to be written even if it already exists"
		FORCE=1
		;;
	k) echo "Key and certificate files will be left in '$KNC'"
		KEEP_FILES=1
		;;
	s) echo "Sending TPM2_Startup command"
		tpm2_startup -c >> $TPM2_LOG_FILE 2>&1
		;;
	t) TEST=1;;
	esac
done


# Flush transient handles, just in case
tpm2 flushcontext -t

# Test if EK certificate is already present
# Don't use 'tpm2' function, we will handle failure
tpm2_nvread -C o 0x01C00002 1> /dev/null 2>> $TPM2_LOG_FILE

if [[ $? -eq 0 && $FORCE -ne 1 ]]; then
	echo "TPM already has EK certificate, skipping"
	if [[ $TEST -eq 1 ]]; then
		# Don't use 'tpm2' function, stdout is piped to openssl
		tpm2_nvread -C o 0x01C00002 2>> $TPM2_LOG_FILE | \
			openssl x509 -text -noout -inform DER
	fi
	exit
fi

# Create EK from seed imprinted into TPM. For TPM simulator it is randomly
# generated at first start, don't count on it being always the same there.
tpm2 createek --format=pem -u $EK_PUB -c /dev/null


# Generate self-signed CA certificate
# TODO: add option to provide CA key instead of generating new one
openssl req -newkey rsa:2048 -nodes -keyout $CA_PRIV -x509 -days 365 \
        -out $CA_CERT -config $CA_CONFIG

# Create and sign EK certificate
openssl req -new -key $CA_PRIV -out $EK_CSR -config $EK_CONFIG
openssl x509 -req -in $EK_CSR -CA $CA_CERT -CAkey $CA_PRIV -CAserial $CA_SRL \
        -CAcreateserial -extfile $EK_V3_EXT -force_pubkey $EK_PUB \
        -outform der -out $EK_CERT

# If forcing new EK certificate, undefine old one
if [[ $FORCE -eq 1 ]]; then
	tpm2 nvundefine -C o 0x01C00002
fi

# Define and write NV for EK certificate
EK_CERT_SIZE=`stat -c %s $EK_CERT`
tpm2 nvdefine -C o -s $EK_CERT_SIZE 0x01C00002
tpm2 nvwrite -i $EK_CERT -C o 0x01C00002

# Clean up
tpm2 flushcontext -t

if [[ $KEEP_FILES -ne 1 ]]; then
	# CA_CERT is left
	rm $CA_PRIV $CA_SRL $EK_PUB $EK_CSR $EK_CERT
fi

echo -e "\n\nDone."

if [[ $TEST -eq 1 ]]; then
	# Don't use 'tpm2' function, stdout is piped to openssl
	tpm2_nvread -C o 0x01C00002 2>> $TPM2_LOG_FILE | \
		openssl x509 -text -noout -inform DER
else
	echo "To test:
	tpm2_nvread -C o 0x01C00002 | openssl x509 -text -noout -inform DER"
fi
