#include <stdio.h>
#include <string.h>
#include <ctype.h>      // isprint, for hexdump
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

static UsefulBuf _encode_aik(UsefulBuf buf)
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
    /* TODO */
    static const uint8_t ek_cert_buf[] = {0,1,2,3,4,5,6,7,8,9};
    UsefulBufC ek_cert = {&ek_cert_buf, sizeof(ek_cert_buf)};

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
        QCBOREncode_AddBytesToMap(&ctx, "ek_cert", ek_cert /* TODO */);
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

    /* First call obtains the size of required output buffer, second call
     * actually encodes data.
     *
     * There is also QCBOREncode_FinishGetSize(), but it internally calls
     * QCBOREncode_Finish(). We need properly allocated buffer passed to
     * QCBOREncode_Init() so we would have to call it twice anyway.
     */
    ret = _encode_aik(SizeCalculateUsefulBuf);

    ret.ptr = malloc(ret.len);
    ret = _encode_aik(ret);

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
