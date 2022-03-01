#ifndef _H_TPM2_CRYPTO
#define _H_TPM2_CRYPTO

#include <qcbor/UsefulBuf.h>

TSS2_RC init_tpm_keys(void);
void tpm_cleanup(void);

UsefulBuf encode_ek(void);
UsefulBuf encode_aik(void);
UsefulBuf encode_aik_marshaled(void);
UsefulBuf do_challenge(UsefulBuf in);

#endif /* _H_TPM2_CRYPTO */
