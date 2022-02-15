#ifndef _H_TPM2_CRYPTO
#define _H_TPM2_CRYPTO

TSS2_RC init_tpm_keys(void);
void tpm_cleanup(void);

TSS2_RC get_marshalled_aik(void **buf, size_t *size);

#endif /* _H_TPM2_CRYPTO */
