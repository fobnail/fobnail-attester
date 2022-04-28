#ifndef _H_TPM2_CRYPTO
#define _H_TPM2_CRYPTO

#include <qcbor/UsefulBuf.h>

TSS2_RC init_tpm_keys(void);
void tpm_cleanup(void);

UsefulBuf get_ek_cert_chain(void);
UsefulBuf get_aik(void);
UsefulBuf get_signed_rim(UsefulBufC nonce);
UsefulBuf do_challenge(UsefulBuf in);
UsefulBuf do_quote(UsefulBuf in);
UsefulBuf sign_with_aik(UsefulBuf data, UsefulBufC nonce);

#endif /* _H_TPM2_CRYPTO */
