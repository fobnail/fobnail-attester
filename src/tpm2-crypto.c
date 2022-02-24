#include <stdio.h>
#include <string.h>
#include <ctype.h>      // isprint, for hexdump
#include <openssl/evp.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <qcbor/qcbor_encode.h>

static ESYS_CONTEXT          *esys_ctx;
static TSS2_TCTI_CONTEXT     *tcti_ctx;
static TPM2B_PUBLIC          *keyPublic;
static TPM2B_PRIVATE         *keyPrivate;

void hexdump(const void *memory, size_t length);
void hexdump(const void *memory, size_t length)
{
	size_t i, j;
	uint8_t *line;
	int all_zero = 0;
	int all_one = 0;
	size_t num_bytes;

	for (i = 0; i < length; i += 16) {
		num_bytes = length - i;
        if (num_bytes > 16) num_bytes = 16;
		line = ((uint8_t *)memory) + i;

		all_zero++;
		all_one++;
		for (j = 0; j < num_bytes; j++) {
			if (line[j] != 0) {
				all_zero = 0;
				break;
			}
		}

		for (j = 0; j < num_bytes; j++) {
			if (line[j] != 0xff) {
				all_one = 0;
				break;
			}
		}

		if ((all_zero < 2) && (all_one < 2)) {
			printf("%#8lx:", i);
			for (j = 0; j < num_bytes; j++)
				printf(" %02x", line[j]);
			for (; j < 16; j++)
				printf("   ");
			printf("  ");
			for (j = 0; j < num_bytes; j++)
				printf("%c", isprint(line[j]) ? line[j] : '.');
			printf("\n");
		} else if ((all_zero == 2) || (all_one == 2)) {
			printf("...\n");
		}
	}
}

static UsefulBuf read_ek_cert(void)
{
    UsefulBuf             ret = NULLUsefulBuf;
    TSS2_RC               tss_ret;
    ESYS_TR               handle;
    ESYS_TR               session;
    TPM2B_NV_PUBLIC      *public;
    TPM2B_MAX_NV_BUFFER  *data;
    TPM2B_AUTH            passwd = {.size=4, .buffer={0x01, 0xC0, 0x00, 0x02}};
    TPM2B_NONCE           nonceCaller = {.size=0x20};
    TPMT_SYM_DEF          sym_null = {.algorithm=TPM2_ALG_NULL};
    uint32_t              chunk_size;
    TPMS_CAPABILITY_DATA *capability_data = NULL;

    Esys_TR_FromTPMPublic(esys_ctx, 0x01C00002, ESYS_TR_NONE, ESYS_TR_NONE,
                          ESYS_TR_NONE, &handle);

    /* No idea why 'tpmKey' and 'bind' aren't ESYS_TR_RH_NULL, but they must be
     * ESYS_TR_NONE or this function will fail
     */
    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_HMAC, &sym_null,
                                    TPM2_ALG_SHA256, &session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        printf("Error: Esys_StartAuthSession() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* To read EK cert we must use password made from NV index handle */
    tss_ret = Esys_TR_SetAuth(esys_ctx, session, &passwd);
    if (tss_ret != TSS2_RC_SUCCESS) {
        printf("Error: Esys_TR_SetAuth() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* Read size of data */
    tss_ret = Esys_NV_ReadPublic(esys_ctx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
                                 ESYS_TR_NONE, &public, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        printf("Error: Esys_NV_ReadPublic() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* Allocate UsefulBuf */
    ret.len = public->nvPublic.dataSize;
    Esys_Free(public);
    ret.ptr = malloc(ret.len);

    /* TPMs have a maximum supported data size for NV operations, read it */
    Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1,
                       NULL, &capability_data);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_GetCapability()\n");
        free(ret.ptr);
        ret = NULLUsefulBuf;
        goto error;
    }
    chunk_size = capability_data->data.tpmProperties.tpmProperty[0].value;
    Esys_Free(capability_data);

    /* Read data in chunks */
    for (uint32_t offset = 0; offset < ret.len; offset += chunk_size) {
        uint32_t to_read = ret.len - offset;
        if (to_read > chunk_size)
            to_read = chunk_size;

        tss_ret = Esys_NV_Read(esys_ctx, handle, handle, session, ESYS_TR_NONE,
                               ESYS_TR_NONE, to_read, offset, &data);
        if (tss_ret != TSS2_RC_SUCCESS) {
            printf("Error: Esys_NV_Read() %s\n", Tss2_RC_Decode(tss_ret));
            Esys_Free(data);
            free(ret.ptr);
            ret = NULLUsefulBuf;
            goto error;
        }

        /* New 'data' is created for every Esys_NV_Read() invocation, data must
         * be copied to final buffer */
        memcpy((uint8_t *)ret.ptr + offset, data->buffer, data->size);
        Esys_Free(data);
    }

    hexdump(ret.ptr, ret.len);

error:
    Esys_FlushContext(esys_ctx, session);
    return ret;
}

UsefulBuf encode_ek(void)
{
    UsefulBuf ek_cert = read_ek_cert();

    if (UsefulBuf_IsNULLOrEmpty(ek_cert))
        fprintf(stderr, "EK certificate can't be read, is this simulated TPM?\n");

    return ek_cert;
}

/* Unmarshaled data uses naturally aligned fields in structures. For
 * calculating "loaded key name" (i.e. hash of public key) we have to use
 * marshaled data.
 */
void get_loaded_aik_name(uint8_t **out_buf, size_t *out_size)
{
    /* Marshaled data will never be bigger than unmarshaled one */
    uint8_t *buf = malloc(sizeof(*keyPublic));
    /* size = 0 will still return properly formatted hash without reading from
     * random places in memory so further functions will work as expected.
     * SHA256 of empty buffer:
     * e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     */
    size_t size = 0;
    EVP_MD_CTX *mdctx;
    const EVP_MD* md = EVP_sha256();
    TSS2_RC rc;

    /* Add 2 bytes for algorithm ID */
    *out_buf = malloc(EVP_MD_size(md) + 2);

    if (keyPublic == NULL) {
        fprintf(stderr,
                "Error: get_marshalled_aik() called without AIK available\n");
    } else {
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublic, buf, sizeof(*keyPublic),
                                          &size);
        if (rc != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Err: Marshal() failed: %s\n", Tss2_RC_Decode(rc));
            size = 0;
        }
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit(mdctx, md);
    /* First 2 bytes are the size (big endian!) of rest of the buffer */
    EVP_DigestUpdate(mdctx, buf + 2, keyPublic->size);
    /* It also frees mdctx. Skip 2 bytes for algorithm ID */
    EVP_DigestFinal(mdctx, (*out_buf) + 2, NULL);

    /* TPM2_ALG_SHA256 with correct endianness. TODO: add other if needed */
    (*out_buf)[0] = 0;
    (*out_buf)[1] = 0x0B;

    *out_size = EVP_MD_size(md) + 2;
}

static UsefulBuf _encode_aik(UsefulBuf buf, UsefulBuf lkn)
{
    /* From TCG Trusted Platform Module Library Part 2: Structures rev 01.59:
     *   A TPM (...) supporting RSA shall support two primes and an exponent of
     *   zero. An exponent of zero indicates that the exponent is the default of
     *   2^16 + 1. Support for other values is optional.
     */
    /* TODO: is endianness correct? */
    uint32_t exponent = keyPublic->publicArea.parameters.rsaDetail.exponent;
    if (exponent == 0)
        exponent = 0x00010001;

    TPM2B_PUBLIC_KEY_RSA *unique = (TPM2B_PUBLIC_KEY_RSA *)
                                   &keyPublic->publicArea.unique;
    UsefulBufC modulus = {&unique->buffer, unique->size};

   /* Set up the encoding context with the output buffer */
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, buf);

    /* Proceed to output all the items, letting the internal error
     * tracking do its work */
    QCBOREncode_OpenMap(&ctx);
        QCBOREncode_AddUInt64ToMap(&ctx, "type", 1);     /* Assume RSA */
        QCBOREncode_OpenMapInMap(&ctx, "key");
            QCBOREncode_AddBytesToMap(&ctx, "n", modulus);
            QCBOREncode_AddUInt64ToMap(&ctx, "e", exponent);
        QCBOREncode_CloseMap(&ctx);
        QCBOREncode_AddBytesToMap(&ctx, "loaded_key_name", UsefulBuf_Const(lkn));
    QCBOREncode_CloseMap(&ctx);

    /* Get the pointer and length of the encoded output. If there was
     * any encoding error, it will be returned here */
    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&ctx, &EncodedCBOR);
    if(uErr != QCBOR_SUCCESS) {
        printf("QCBOR error: %d\n", uErr);
        return NULLUsefulBuf;
    } else {
        return UsefulBuf_Unconst(EncodedCBOR);
    }
}

UsefulBuf encode_aik(void)
{
    UsefulBuf ret = NULLUsefulBuf;
    UsefulBuf lkn;

    get_loaded_aik_name((uint8_t **)&lkn.ptr, &lkn.len);

    /* First call obtains the size of required output buffer, second call
     * actually encodes data.
     *
     * There is also QCBOREncode_FinishGetSize(), but it internally calls
     * QCBOREncode_Finish(). We need properly allocated buffer passed to
     * QCBOREncode_Init() so we would have to call it twice anyway.
     */
    ret = _encode_aik(SizeCalculateUsefulBuf, lkn);

    ret.ptr = malloc(ret.len);
    ret = _encode_aik(ret, lkn);

    return ret;
}

/* Release any transient objects that may have been allocated by commands.
 *
 * Note: this also unloads EK, which (along with AIK) will be needed for further
 * steps. Both of them would have to be recreated or (re-)loaded for each task
 * that requires them, or skipped here from flushing (in which case this
 * function doesn't even have to be called for each step). They still should be
 * flushed when whole application is terminated.
 */
static void flush_tpm_contexts(ESYS_CONTEXT *esys_ctx)
{
    TPMI_YES_NO more_data = TPM2_YES;
    TPM2_HANDLE hndl = TPM2_TRANSIENT_FIRST;

    while (more_data == TPM2_YES) {
        TPMS_CAPABILITY_DATA *cap_data = NULL;
        TPML_HANDLE          *hlist;
        ESYS_TR               tr_handle;

        Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                           TPM2_CAP_HANDLES, hndl, 1,
                           &more_data, &cap_data);

        hlist = &cap_data->data.handles;
        if (hlist->count == 0)
            break;

        hndl = hlist->handle[0];
        printf("Flushing object with handle %8.8x\n", hndl);

        Esys_TR_FromTPMPublic(esys_ctx, hndl++, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, &tr_handle);
        Esys_FlushContext(esys_ctx, tr_handle);

        Esys_Free(cap_data);
    }
}

static TPM2B_SENSITIVE_CREATE primarySensitive = {
    .sensitive = {
        .userAuth = {
            .size = 0,
        },
        .data = {
            .size = 0,
        }
    }
};

#define ENGINE_HASH_ALG TPM2_ALG_SHA256

#define TPM2B_PUBLIC_PRIMARY_RSA_TEMPLATE { \
    .publicArea = { \
        .type = TPM2_ALG_RSA, \
        .nameAlg = ENGINE_HASH_ALG, \
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH | \
                             TPMA_OBJECT_RESTRICTED | \
                             TPMA_OBJECT_DECRYPT | \
                             TPMA_OBJECT_NODA | \
                             TPMA_OBJECT_FIXEDTPM | \
                             TPMA_OBJECT_FIXEDPARENT | \
                             TPMA_OBJECT_SENSITIVEDATAORIGIN), \
        .authPolicy = { \
        .size = 0, \
        }, \
        .parameters.rsaDetail = { \
            .symmetric = { \
                .algorithm = TPM2_ALG_AES, \
                .keyBits.aes = 128, \
                .mode.aes = TPM2_ALG_CFB, \
            }, \
            .scheme = { \
                .scheme = TPM2_ALG_NULL, \
            }, \
            .keyBits = 2048, \
            .exponent = 0,\
        }, \
        .unique.rsa = { \
            .size = 0, \
        } \
    } \
}

static TPM2B_PUBLIC primaryRsaTemplate = TPM2B_PUBLIC_PRIMARY_RSA_TEMPLATE;

static TPM2B_PUBLIC keyTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT |
                             TPMA_OBJECT_DECRYPT |
                             TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_NODA),
        .authPolicy.size = 0,
        .parameters.rsaDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_NULL,
                .keyBits.aes = 0,
                .mode.aes = 0,
            },
            .scheme = {
                .scheme = TPM2_ALG_NULL,
            },
            .keyBits = 2048,
            .exponent = 0,
        },
        .unique.rsa.size = 0
    }
};

TSS2_RC init_tpm_keys(void)
{
    TSS2_RC                tss_ret = TSS2_RC_SUCCESS;
    ESYS_TR                parent = ESYS_TR_NONE;
    TPM2B_PUBLIC           inPublic = keyTemplate;
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .sensitive = {
            .userAuth = {
                .size = 0,
            },
            .data = {
                .size = 0,
            }
        }
    };

    TPM2B_DATA             outsideInfo = { .size = 0, };
    TPML_PCR_SELECTION     creationPCR = { .count = 0, };
    TPM2B_DIGEST           ownerauth = { .size = 0 };
    TPMS_CAPABILITY_DATA  *capabilityData = NULL;

    /* Initialize the Esys context */

    if ((tss_ret = Tss2_TctiLdr_Initialize(NULL, &tcti_ctx)) != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Tss2_TctiLdr_Initialize\n");
        goto error;
    }

    if ((tss_ret = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_Initialize()\n");
        goto error;
    }

    tss_ret = Esys_Startup(esys_ctx, TPM2_SU_CLEAR);
    if (tss_ret != TSS2_RC_SUCCESS){
        printf("Error: Esys_Startup()\n");
        goto error;
    }

    if ((tss_ret = Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &ownerauth)) != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_TR_SetAuth()\n");
        goto error;
    }

    tss_ret = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                 TPM2_CAP_ALGS, 0, TPM2_MAX_CAP_ALGS, NULL, &capabilityData);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_GetCapability()\n");
        goto error;
    }
    Esys_Free(capabilityData);

    tss_ret = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD,
                                 ESYS_TR_NONE, ESYS_TR_NONE, &primarySensitive,
                                 &primaryRsaTemplate, &outsideInfo, &creationPCR,
                                 &parent, NULL, NULL, NULL, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_CreatePrimary()\n");
        goto error;
    }

    tss_ret = Esys_Create(esys_ctx, parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &inSensitive, &inPublic, &outsideInfo, &creationPCR,
                          &keyPrivate, &keyPublic, NULL, NULL, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_Create()\n");
        goto error;
    }

    hexdump(keyPublic, sizeof(*keyPublic));

    return TSS2_RC_SUCCESS;

error:
    if (esys_ctx != NULL) {
        flush_tpm_contexts(esys_ctx);
        Esys_Finalize(&esys_ctx);
    }

    if (tcti_ctx != NULL)
        Tss2_TctiLdr_Finalize(&tcti_ctx);

    return tss_ret;
}

/* Should not be called if init_tpm_keys() failed */
void tpm_cleanup(void)
{
    memset(keyPrivate, 0, sizeof(*keyPrivate));
    Esys_Free(keyPrivate);
    keyPrivate = NULL;
    memset(keyPublic, 0, sizeof(*keyPublic));
    Esys_Free(keyPublic);
    keyPublic = NULL;

    flush_tpm_contexts(esys_ctx);
    Esys_Finalize(&esys_ctx);

    Tss2_TctiLdr_Finalize(&tcti_ctx);
}
