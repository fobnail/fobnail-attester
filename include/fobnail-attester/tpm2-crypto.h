#ifndef _H_TPM2_CRYPTO
#define _H_TPM2_CRYPTO

#include <qcbor/UsefulBuf.h>

TSS2_RC init_tpm_keys(void);
void tpm_cleanup(void);

UsefulBuf read_ek_cert(void);
UsefulBuf get_aik(void);
UsefulBuf get_signed_rim(uint32_t pcrs, UsefulBuf nonce);
UsefulBuf do_challenge(UsefulBuf in);
UsefulBuf sign_with_aik(UsefulBuf data, UsefulBuf nonce);

#endif /* _H_TPM2_CRYPTO */
