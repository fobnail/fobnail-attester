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
#include <qcbor/qcbor_spiffy_decode.h>

static ESYS_CONTEXT         *esys_ctx;
static TSS2_TCTI_CONTEXT    *tcti_ctx;
static TPM2B_PUBLIC         *keyPublic;
static TPM2B_NAME           *name;

/* Constants used by Esys_StartAuthSession */
static const TPMT_SYM_DEF   sym_null = {.algorithm = TPM2_ALG_NULL};
static const TPM2B_NONCE    nonceCaller = {.size = 0x20};

#define AIK_NV_HANDLE       0x8100F0BA
#define EK_NV_HANDLE        0x8100F0BE
#define EK_CERT_NV_HANDLE   0x01C00002

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

/* Release any objects of type 'hndl' that may have been allocated by commands */
static void flush_tpm_contexts(ESYS_CONTEXT *esys_ctx, TPM2_HANDLE hndl)
{
    TPMI_YES_NO more_data = TPM2_YES;

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

static UsefulBuf read_ek_cert(void)
{
    UsefulBuf             ret = NULLUsefulBuf;
    TSS2_RC               tss_ret;
    ESYS_TR               handle;
    ESYS_TR               session;
    TPM2B_NV_PUBLIC      *public;
    TPM2B_MAX_NV_BUFFER  *data;
    TPM2B_AUTH            passwd = {
                            .size = 4,
                            .buffer = {
                                (EK_CERT_NV_HANDLE >> 24) & 0xFF,
                                (EK_CERT_NV_HANDLE >> 16) & 0xFF,
                                (EK_CERT_NV_HANDLE >>  8) & 0xFF,
                                (EK_CERT_NV_HANDLE >>  0) & 0xFF,
                            }};
    uint32_t              chunk_size;
    TPMS_CAPABILITY_DATA *capability_data = NULL;

    tss_ret = Esys_TR_FromTPMPublic(esys_ctx, EK_CERT_NV_HANDLE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* No idea why 'tpmKey' and 'bind' aren't ESYS_TR_RH_NULL, but they must be
     * ESYS_TR_NONE or this function will fail
     */
    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_HMAC, &sym_null,
                                    TPM2_ALG_SHA256, &session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_StartAuthSession() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* To read EK cert we must use password made from NV index handle */
    tss_ret = Esys_TR_SetAuth(esys_ctx, session, &passwd);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_TR_SetAuth() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* Read size of data */
    tss_ret = Esys_NV_ReadPublic(esys_ctx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
                                 ESYS_TR_NONE, &public, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_NV_ReadPublic() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* Allocate UsefulBuf */
    ret.len = public->nvPublic.dataSize;
    Esys_Free(public);
    ret.ptr = malloc(ret.len);

    /* TPMs have a maximum supported data size for NV operations, read it */
    Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, NULL,
                       &capability_data);
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
            fprintf(stderr, "Error: Esys_NV_Read() %s\n",
                    Tss2_RC_Decode(tss_ret));
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
        fprintf(stderr,
                "EK certificate can't be read, is this simulated TPM?\n");

    return ek_cert;
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
        QCBOREncode_AddBytesToMap(&ctx, "loaded_key_name",
                                  UsefulBuf_Const(lkn));
    QCBOREncode_CloseMap(&ctx);

    /* Get the pointer and length of the encoded output. If there was
     * any encoding error, it will be returned here */
    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&ctx, &EncodedCBOR);
    if (uErr != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOR error: %d\n", uErr);
        return NULLUsefulBuf;
    } else {
        return UsefulBuf_Unconst(EncodedCBOR);
    }
}

UsefulBuf encode_aik(void)
{
    UsefulBuf       ret = NULLUsefulBuf;
    UsefulBuf       lkn;

    if (name == NULL) {
        fprintf(stderr, "Couldn't read AIK loaded key name\n");
        return NULLUsefulBuf;
    }

    lkn.ptr = name->name;
    lkn.len = name->size;

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

    Esys_Free(name);

    return ret;
}

UsefulBuf encode_aik_marshaled(void)
{
    UsefulBuf   marshaled;
    size_t      offset = 0;
    TSS2_RC     tss_ret;

    /* Marshaled data will never be larger than unmarshaled */
    marshaled.ptr = malloc(sizeof(*keyPublic));
    marshaled.len = sizeof(*keyPublic);

    tss_ret = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublic, marshaled.ptr,
                                           marshaled.len, &offset);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Tss2_MU_TPM2B_PUBLIC_Marshal() %s\n",
                Tss2_RC_Decode(tss_ret));
        return NULLUsefulBuf;
    }

    marshaled.len = offset;

    return marshaled;
}

UsefulBuf do_challenge(UsefulBuf in)
{
    UsefulBuf               ret = NULLUsefulBuf;
    UsefulBufC              id_object, enc_secret;
    QCBORError              uErr;
    QCBORDecodeContext      ctx;
    ESYS_TR                 aik_handle, ek_handle;
    ESYS_TR                 aik_session = TPM2_RH_NULL, ek_session = TPM2_RH_NULL;
    TPM2B_DIGEST           *cert_info = NULL;
    TPM2B_ID_OBJECT         tpm_id_object;
    TPM2B_ENCRYPTED_SECRET  tpm_enc_secret;
    TSS2_RC                 tss_ret;

    /* Let QCBORDecode internal error tracking do its work. */
    QCBORDecode_Init(&ctx, UsefulBuf_Const(in), QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&ctx, NULL);
        QCBORDecode_GetByteStringInMapSZ(&ctx, "idObject", &id_object);
        QCBORDecode_GetByteStringInMapSZ(&ctx, "encSecret", &enc_secret);
    QCBORDecode_ExitMap(&ctx);

    /* Catch further decoding error here */
    uErr = QCBORDecode_Finish(&ctx);
    if (uErr != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOR error: %d\n", uErr);
        return ret;
    }

    flush_tpm_contexts(esys_ctx, TPM2_HMAC_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_LOADED_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_POLICY_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_TRANSIENT_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_ACTIVE_SESSION_FIRST);

    tss_ret = Esys_TR_FromTPMPublic(esys_ctx, AIK_NV_HANDLE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &aik_handle);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_TR_FromTPMPublic(esys_ctx, EK_NV_HANDLE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &ek_handle);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(id_object.ptr, id_object.len,
                                                NULL, &tpm_id_object);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Tss2_MU_TPM2B_ID_OBJECT_Unmarshal() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(enc_secret.ptr,
                                                       enc_secret.len, NULL,
                                                       &tpm_enc_secret);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_POLICY, &sym_null,
                                    TPM2_ALG_SHA256, &ek_session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        printf("Error: Esys_StartAuthSession() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_PolicySecret(esys_ctx, ESYS_TR_RH_ENDORSEMENT, ek_session,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                NULL, NULL, NULL, 0, NULL, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        printf("Error: Esys_PolicySecret() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_HMAC, &sym_null,
                                    TPM2_ALG_SHA256, &aik_session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        printf("Error: Esys_StartAuthSession() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_ActivateCredential(esys_ctx, aik_handle, ek_handle,
                                      aik_session, ek_session,
                                      ESYS_TR_NONE, &tpm_id_object,
                                      &tpm_enc_secret, &cert_info);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_ActivateCredential() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    ret.ptr = malloc(cert_info->size);
    ret.len = cert_info->size;
    memcpy(ret.ptr, cert_info->buffer, ret.len);

error:
    if(ek_session != TPM2_RH_NULL)
        Esys_FlushContext(esys_ctx, ek_session);
    if(aik_session != TPM2_RH_NULL)
        Esys_FlushContext(esys_ctx, aik_session);

    Esys_Free(cert_info);
    return ret;
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

/* From https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p3_r2_pub.pdf */
static TPM2B_PUBLIC primaryRsaTemplate = {
    .publicArea = {
        .type = TPM2_ALG_RSA,
        .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = (TPMA_OBJECT_FIXEDTPM |
                             TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_ADMINWITHPOLICY |
                             TPMA_OBJECT_RESTRICTED |
                             TPMA_OBJECT_DECRYPT),
        .authPolicy = {
            .size = 32,
            .buffer = { 0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
                        0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
                        0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
                        0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA },
        },
        .parameters.rsaDetail = {
            .symmetric = {
                .algorithm = TPM2_ALG_AES,
                .keyBits.aes = 128,
                .mode.aes = TPM2_ALG_CFB,
            },
            .scheme = {
                .scheme = TPM2_ALG_NULL,
            },
            .keyBits = 2048,
            .exponent = 0,
        },
        .unique.rsa = {
            .size = 256,
        }
    }
};

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
    ESYS_TR                aik = ESYS_TR_NONE;
    ESYS_TR                tmp_new, session;
    TPM2B_TEMPLATE         inPublic;
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
    TPM2B_PRIVATE         *keyPrivate;

    size_t out_size = 0;

    tss_ret = Tss2_MU_TPMT_PUBLIC_Marshal(&keyTemplate.publicArea,
                                          inPublic.buffer, sizeof(TPMT_PUBLIC),
                                          &out_size);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Tss2_MU_TPMT_PUBLIC_Marshal() %s\n",
               Tss2_RC_Decode(tss_ret));
        goto error;
    }
    inPublic.size = out_size;

    /* Initialize the Esys context */

    tss_ret = Tss2_TctiLdr_Initialize(NULL, &tcti_ctx);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Tss2_TctiLdr_Initialize %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_Initialize() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_Startup(esys_ctx, TPM2_SU_CLEAR);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_Startup() %s\n", Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &ownerauth);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_TR_SetAuth() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                 ESYS_TR_NONE, TPM2_CAP_HANDLES, AIK_NV_HANDLE,
                                 1, NULL, &capabilityData);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_GetCapability() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    if (capabilityData->data.handles.count == 0 ||
        capabilityData->data.handles.handle[0] != AIK_NV_HANDLE) {
        printf("AIK not found, generating one now. This may take a while...\n");
        tss_ret = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_ENDORSEMENT,
                                     ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                     ESYS_TR_NONE, &primarySensitive,
                                     &primaryRsaTemplate, &outsideInfo,
                                     &creationPCR, &parent, NULL, NULL, NULL,
                                     NULL);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_CreatePrimary() %s\n",
            Tss2_RC_Decode(tss_ret));
            goto error;
        }

        tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                        &nonceCaller, TPM2_SE_POLICY, &sym_null,
                                        TPM2_ALG_SHA256, &session);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_StartAuthSession() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }

        tss_ret = Esys_PolicySecret(esys_ctx, ESYS_TR_RH_ENDORSEMENT, session,
                                    ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                    NULL, NULL, NULL, 0, NULL, NULL);
        if (tss_ret != TSS2_RC_SUCCESS) {
            printf("Error: Esys_PolicySecret() %s\n", Tss2_RC_Decode(tss_ret));
            goto error;
        }


        /* TODO: revert to Create + Load */
        tss_ret = Esys_CreateLoaded(esys_ctx, parent, session,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive,
                                    &inPublic, &aik, &keyPrivate, &keyPublic);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_CreateLoaded() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, session);



        memset(keyPrivate, 0, sizeof(*keyPrivate));
        Esys_Free(keyPrivate);
        keyPrivate = NULL;

        tss_ret = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, aik,
                                    ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                    ESYS_TR_NONE, AIK_NV_HANDLE, &tmp_new);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_EvictControl() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, aik);
        aik = tmp_new;

        tss_ret = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, parent,
                                    ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                    ESYS_TR_NONE, EK_NV_HANDLE, NULL);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_EvictControl() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, parent);
    } else {
        tss_ret = Esys_TR_FromTPMPublic(esys_ctx, AIK_NV_HANDLE, ESYS_TR_NONE,
                                        ESYS_TR_NONE, ESYS_TR_NONE, &aik);
        if (tss_ret != TSS2_RC_SUCCESS){
            fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }

        tss_ret = Esys_ReadPublic(esys_ctx, aik, ESYS_TR_NONE, ESYS_TR_NONE,
                                  ESYS_TR_NONE, &keyPublic, &name, NULL);
        Esys_FlushContext(esys_ctx, aik);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_ReadPublic() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
    }

    hexdump(keyPublic, sizeof(*keyPublic));

    return TSS2_RC_SUCCESS;

error:
    Esys_Free(capabilityData);

    if (esys_ctx != NULL) {
        flush_tpm_contexts(esys_ctx, TPM2_TRANSIENT_FIRST);
        Esys_Finalize(&esys_ctx);
    }

    if (tcti_ctx != NULL)
        Tss2_TctiLdr_Finalize(&tcti_ctx);

    return tss_ret;
}

/* Should not be called if init_tpm_keys() failed */
void tpm_cleanup(void)
{
    memset(keyPublic, 0, sizeof(*keyPublic));
    Esys_Free(keyPublic);
    keyPublic = NULL;

    memset(name, 0, sizeof(*name));
    Esys_Free(name);
    name = NULL;

    flush_tpm_contexts(esys_ctx, TPM2_HMAC_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_LOADED_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_POLICY_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_TRANSIENT_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_ACTIVE_SESSION_FIRST);

    Esys_Finalize(&esys_ctx);

    Tss2_TctiLdr_Finalize(&tcti_ctx);
}
