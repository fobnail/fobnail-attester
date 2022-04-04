#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/safestack.h>
#include <openssl/x509v3.h>
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

/* Constants used by Esys_StartAuthSession */
static const TPMT_SYM_DEF   sym_null = {.algorithm = TPM2_ALG_NULL};
static const TPM2B_NONCE    nonceCaller = {.size = 0x20};

/* Constants used by Esys_Create* functions */
static const TPM2B_SENSITIVE_CREATE inSensitive = {
    .sensitive = {
        .userAuth = {
            .size = 0,
        },
        .data = {
            .size = 0,
        }
    }
};

/* From TCG EK Credential Profile For TPM Family 2.0; Level 0 Version 2.3 */
static const TPM2B_PUBLIC primaryRsaTemplate = {
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

static const TPM2B_PUBLIC keyTemplate = {
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

/* Constant used by Esys_Sign() and Esys_Quote() */
static const TPMT_SIG_SCHEME    sig_scheme = {
    .scheme = TPM2_ALG_RSASSA,
    .details.rsassa.hashAlg = TPM2_ALG_SHA256
};

#define AIK_NV_HANDLE       0x8100F0BA
#define EK_NV_HANDLE        0x8100F0BE
#define EK_CERT_NV_HANDLE   0x01C00002

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

static TSS2_RC start_policy_auth(ESYS_TR *session)
{
    TSS2_RC tss_ret;

    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_POLICY, &sym_null,
                                    TPM2_ALG_SHA256, session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_StartAuthSession() %s\n",
                Tss2_RC_Decode(tss_ret));
        return tss_ret;
    }

    tss_ret = Esys_PolicySecret(esys_ctx, ESYS_TR_RH_ENDORSEMENT, *session,
                                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                NULL, NULL, NULL, 0, NULL, NULL);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_PolicySecret() %s\n",
                Tss2_RC_Decode(tss_ret));
        return tss_ret;
    }

    return TSS2_RC_SUCCESS;
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

error:
    Esys_FlushContext(esys_ctx, session);
    return ret;
}

static UsefulBuf _cbor_cert_chain(UsefulBuf buf, size_t num, UsefulBufC *certs)
{
    QCBOREncodeContext ctx;
    UsefulBufC enc;
    QCBORError err;
    QCBOREncode_Init(&ctx, buf);

    QCBOREncode_OpenMap(&ctx);
        QCBOREncode_OpenArrayInMap(&ctx, "certs");
        for (int i = num - 1; i >= 0; i--)
            QCBOREncode_AddBytes(&ctx, certs[i]);
        QCBOREncode_CloseArray(&ctx);
    QCBOREncode_CloseMap(&ctx);

    err = QCBOREncode_Finish(&ctx, &enc);

    if(err != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOR error: %d\n", err);
        return NULLUsefulBuf;
    } else {
        return UsefulBuf_Unconst(enc);
    }
}

/*
 * Authority Info Access and CA Issuers field is required by Windows 10 and
 * newer, but not strictly required by TPM specification. This may render some
 * TPMs unusable, but I haven't seen a TPM that has EK certificate without those
 * fields.
 */
/* Based on X509_get1_ocsp() */
static unsigned char *X509_get_ca_url(X509 *x)
{
    AUTHORITY_INFO_ACCESS *info;
    unsigned char *ret = NULL;
    int i, len;

    info = X509_get_ext_d2i(x, NID_info_access, NULL, NULL);
    if (!info)
        return NULL;
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(info); i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(info, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
            if (ad->location->type == GEN_URI) {
                len = ASN1_STRING_to_UTF8(&ret, ad->location->d.uniformResourceIdentifier);
                if (len < 0)
                    ret = NULL;
                break;
            }
        }
    }
    AUTHORITY_INFO_ACCESS_free(info);
    return ret;
}

static X509 *UsefulBufC_to_X509(UsefulBufC ub)
{
    /* Pointer to buffer is modified by d2i_* functions, make a copy */
    const unsigned char *tmp_ptr = ub.ptr;
    return d2i_X509(NULL, &tmp_ptr, ub.len);
}

static size_t curl_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    UsefulBuf *mem = (UsefulBuf *)userp;

    char *ptr = realloc(mem->ptr, mem->len + realsize);
    if (!ptr) {
        /* out of memory! */
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->ptr = ptr;
    memcpy(&ptr[mem->len], contents, realsize);
    mem->len += realsize;

    return realsize;
}

/*
 * Returns:
 * - valid non-NULL, non-empty UB on success
 * - NULL, empty UB on root CA (i.e. self-issued certificate)
 * - NULL, non-empty on error
 */
static UsefulBufC get_next_cert(UsefulBufC prev)
{
    X509 *x509 = NULL;
    unsigned char *url = NULL;
    UsefulBuf ret = NULLUsefulBuf;
    CURL *curl;
    CURLcode res;

    x509 = UsefulBufC_to_X509(prev);
    url = X509_get_ca_url(x509);
    if (url == NULL) {
        /* Test if this is root CA or malformed certificate */
        ret.len = X509_check_issued(x509, x509);

        /* Print error only if certificate is not self-issued (root CA) */
        if (ret.len != X509_V_OK)
            fprintf(stderr, "CA URL not found on non-root CA\n");

        goto error;
    }

    printf("Downloading %s\n", url);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        /* Send all data to this function  */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_cb);

        /* We pass our UsefulBuf to the callback function */
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&ret);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* Always clean up */
        curl_easy_cleanup(curl);
    }

error:
    X509_free(x509);
    OPENSSL_free(url);

    return UsefulBuf_Const(ret);
}

#define MAX_EK_CERT_CHAIN       5

UsefulBuf get_ek_cert_chain(void)
{
    /*
     * Note: Fobnail expects certificates in order:
     * - intermediate immediately under root
     * - second...nth intermediate
     * - EK certificate
     *
     * We start parsing from leaf (i.e. EK certificate) and don't know in
     * advance how long the chain will be, so we're using reversed order here.
     * _cbor_cert_chain() parses this array from the end, which converts to the
     * order expected by Fobnail.
     *
     * Root CA certificate is not sent, so one is subtracted from the number of
     * certificates when root CA is found. This doesn't happen in case of
     * malformed certificate (e.g. no AIA extension) to handle chains generated
     * with tpm_manufacture.sh without need for HTTP server for hosting chains.
     */
    size_t num_certs = 0;
    UsefulBufC certs[MAX_EK_CERT_CHAIN] = {0};
    UsefulBuf ret = SizeCalculateUsefulBuf;

    /* Read EK certificate from TPM */
    certs[0] = UsefulBuf_Const(read_ek_cert());
    if (UsefulBuf_IsNULLOrEmptyC(certs[0]))
        goto error;

    num_certs++;

    for (int i = 1; i < MAX_EK_CERT_CHAIN; i++) {
        certs[i] = get_next_cert(certs[i-1]);

        if (UsefulBuf_IsNULLC(certs[i])) {
            /* If error, include current certificate, if root - skip it */
            if (UsefulBuf_IsEmptyC(certs[i]))
                num_certs--;

            break;
        }

        num_certs++;
    }

    ret = _cbor_cert_chain(ret, num_certs, certs);
    ret.ptr = malloc(ret.len);
    ret = _cbor_cert_chain(ret, num_certs, certs);

error:
    for (int i = 0; i < MAX_EK_CERT_CHAIN; i++) {
        OPENSSL_free((void *)certs[i].ptr);
    }

    return ret;
}

UsefulBuf get_aik(void)
{
    UsefulBuf   marshaled;
    size_t      offset = 0;
    TSS2_RC     tss_ret;

    /* Marshaled data will never be larger than unmarshaled */
    marshaled.ptr = malloc(sizeof(*keyPublic));
    marshaled.len = sizeof(*keyPublic);

    tss_ret = Tss2_MU_TPM2B_PUBLIC_Marshal(keyPublic, marshaled.ptr,
                                           marshaled.len, &offset);
    if (tss_ret != TSS2_RC_SUCCESS) {
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

    /* Convert TPM handles to ESYS_TR */
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

    /* Unmarshal challenge blobs */
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

    /* Start policy authorization for EK */
    tss_ret = start_policy_auth(&ek_session);
    if (tss_ret != TSS2_RC_SUCCESS)
        goto error;

    /* Start HMAC authorization for AIK */
    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_HMAC, &sym_null,
                                    TPM2_ALG_SHA256, &aik_session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_StartAuthSession() %s\n",
                Tss2_RC_Decode(tss_ret));
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

/* Return just the signature, doesn't destroy data */
static UsefulBuf get_aik_signature(UsefulBuf data)
{
    UsefulBuf               ret = NULLUsefulBuf;
    TSS2_RC                 tss_ret;
    TPM2B_MAX_BUFFER        buf = { .size = TPM2_MAX_DIGEST_BUFFER };  // 1024
    ESYS_TR                 handle, session = ESYS_TR_NONE;
    size_t                  left = data.len;
    TPMT_TK_HASHCHECK      *ticket = NULL;
    TPM2B_DIGEST           *digest = NULL;
    TPMT_SIGNATURE         *signature = NULL;
    TPM2B_AUTH              null_auth = { .size = 0 };
    static uint32_t         hierarchy = ESYS_TR_RH_OWNER;

    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_POLICY, &sym_null,
                                    TPM2_ALG_SHA256, &session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_StartAuthSession() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    /* TPM may refuse to sign unless it calculates hash value by itself */
    if (data.len <= TPM2_MAX_DIGEST_BUFFER) {
        buf.size = data.len;
        memcpy(buf.buffer, data.ptr, data.len);
        /*
         * 3rd argument from the end should be ESYS_TR_RH_OWNER, but earlier
         * versions of TSS (<3.0) erroneously used TPM2_RH_OWNER instead. Both
         * are defined as u32 integer type. To stay compatible with older
         * software, new TSS accepts both, so we could use common version here,
         * even though it is not compliant with ESAPI. This would print one
         * error and one warning for each operation.
         *
         * https://github.com/tpm2-software/tpm2-tss/issues/1522
         * https://github.com/tpm2-software/tpm2-tss/issues/1750
         *
         * Instead, use static variable for hierarchy and change it to old
         * version on first error.
         */
        tss_ret = Esys_Hash(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &buf, TPM2_ALG_SHA256, hierarchy, &digest,
                            &ticket);
        if (tss_ret != TSS2_RC_SUCCESS && hierarchy == ESYS_TR_RH_OWNER) {
            fprintf(stderr, "Previous error might be caused by bug in TSS, "
                    "trying to work around it\n");
            hierarchy = TPM2_RH_OWNER;
            tss_ret = Esys_Hash(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, &buf, TPM2_ALG_SHA256, hierarchy,
                                &digest, &ticket);
        }
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_Hash() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
    } else {
        tss_ret = Esys_HashSequenceStart(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                         ESYS_TR_NONE, &null_auth,
                                         TPM2_ALG_SHA256, &handle);
        if (tss_ret != TSS2_RC_SUCCESS){
            fprintf(stderr, "Error: Esys_HashSequenceStart() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }

        tss_ret = Esys_TR_SetAuth(esys_ctx, handle, &null_auth);
        if (tss_ret != TSS2_RC_SUCCESS){
            fprintf(stderr, "Error: Esys_TR_SetAuth() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }

        while (left > TPM2_MAX_DIGEST_BUFFER) {
            memcpy(buf.buffer, (uint8_t *) data.ptr + (data.len - left),
                   TPM2_MAX_DIGEST_BUFFER);
            tss_ret = Esys_SequenceUpdate(esys_ctx, handle, ESYS_TR_PASSWORD,
                                          ESYS_TR_NONE, ESYS_TR_NONE, &buf);
            if (tss_ret != TSS2_RC_SUCCESS){
                fprintf(stderr, "Error: Esys_SequenceUpdate() %s\n",
                        Tss2_RC_Decode(tss_ret));
                /*
                 * Can't just 'goto error;', handle must be released and the
                 * only way to do so for sequence handles is through
                 * Esys_SequenceComplete(). Call this function with empty buffer
                 * and don't bother checking its result, this is already failed
                 * case.
                 */
                buf.size = 0;
                Esys_SequenceComplete(esys_ctx, handle, ESYS_TR_PASSWORD,
                                      ESYS_TR_NONE, ESYS_TR_NONE, &buf,
                                      ESYS_TR_RH_OWNER, &digest, &ticket);
                goto error;
            }
            left -= TPM2_MAX_DIGEST_BUFFER;
        }

        memcpy(buf.buffer, (uint8_t *) data.ptr + (data.len - left), left);
        buf.size = left;

        /* 'handle' is flushed by this function */
        tss_ret = Esys_SequenceComplete(esys_ctx, handle, ESYS_TR_PASSWORD,
                                        ESYS_TR_NONE, ESYS_TR_NONE, &buf,
                                        hierarchy, &digest, &ticket);
        if (tss_ret != TSS2_RC_SUCCESS && hierarchy == ESYS_TR_RH_OWNER) {
            fprintf(stderr, "Previous error might be caused by bug in TSS, "
                    "trying to work around it\n");
            hierarchy = TPM2_RH_OWNER;
            tss_ret = Esys_SequenceComplete(esys_ctx, handle, ESYS_TR_PASSWORD,
                                            ESYS_TR_NONE, ESYS_TR_NONE, &buf,
                                            hierarchy, &digest, &ticket);
        }
        if (tss_ret != TSS2_RC_SUCCESS){
            fprintf(stderr, "Error: Esys_SequenceComplete() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
    }

    tss_ret = Esys_TR_FromTPMPublic(esys_ctx, AIK_NV_HANDLE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &handle);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_Sign(esys_ctx, handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                        ESYS_TR_NONE, digest, &sig_scheme, ticket, &signature);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_Sign() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    ret.ptr = malloc(signature->signature.rsassa.sig.size);
    ret.len = signature->signature.rsassa.sig.size;
    memcpy(ret.ptr, signature->signature.rsassa.sig.buffer, ret.len);

error:
    if(session != TPM2_RH_NULL)
        Esys_FlushContext(esys_ctx, session);

    Esys_Free(ticket);
    Esys_Free(digest);
    Esys_Free(signature);

    return ret;
}

static UsefulBuf concat_data_sign(UsefulBuf data, UsefulBuf sign, UsefulBuf buf)
{
    QCBOREncodeContext ctx;
    UsefulBufC EncodedCBOR;
    QCBORError uErr;

    QCBOREncode_Init(&ctx, buf);

    QCBOREncode_OpenMap(&ctx);
        QCBOREncode_AddBytesToMap(&ctx, "data", UsefulBuf_Const(data));
        QCBOREncode_AddBytesToMap(&ctx, "signature", UsefulBuf_Const(sign));
    QCBOREncode_CloseMap(&ctx);

    uErr = QCBOREncode_Finish(&ctx, &EncodedCBOR);
    if(uErr != QCBOR_SUCCESS) {
        printf("QCBOR error: %d\n", uErr);
        return NULLUsefulBuf;
    } else {
        return UsefulBuf_Unconst(EncodedCBOR);
    }
}

UsefulBuf sign_with_aik(UsefulBuf data, UsefulBufC nonce)
{
    UsefulBuf   ret = NULLUsefulBuf;
    UsefulBuf   signature = NULLUsefulBuf;

    if (!UsefulBuf_IsNULLOrEmptyC(nonce)) {
        UsefulBuf data_and_nonce;

        data_and_nonce.len = data.len + nonce.len;
        data_and_nonce.ptr = malloc(data_and_nonce.len);
        memcpy(data_and_nonce.ptr, data.ptr, data.len);
        memcpy((uint8_t*)data_and_nonce.ptr + data.len, nonce.ptr, nonce.len);

        signature = get_aik_signature(data_and_nonce);
        free(data_and_nonce.ptr);
    } else {
        signature = get_aik_signature(data);
    }
    if (UsefulBuf_IsNULLOrEmpty(signature)) {
        fprintf(stderr, "Couldn't create signature with AIK\n");
        goto error;
    }

    ret = concat_data_sign(data, signature, SizeCalculateUsefulBuf);
    ret.ptr = malloc(ret.len);
    ret = concat_data_sign(data, signature, ret);

error:
    if (signature.ptr)
        free(signature.ptr);

    return ret;
}

static unsigned get_num_of_digests(TPML_PCR_SELECTION const *sel)
{
    unsigned num = 0;

    for (unsigned i = 0; i < sel->count; i++) {
        uint32_t pcrs = (sel->pcrSelections[i].pcrSelect[0] <<  0) |
                        (sel->pcrSelections[i].pcrSelect[1] <<  8) |
                        (sel->pcrSelections[i].pcrSelect[2] << 16);
        num += __builtin_popcount(pcrs);
    }

    return num;
}

static void update_pcr_selection(TPML_PCR_SELECTION *base,
                                 TPML_PCR_SELECTION const *done)
{
    /* Iterate over 'done', it's either smaller or same size as `base` */
    for (unsigned i = 0; i < done->count; i++) {
        TPMS_PCR_SELECTION const *it_done = &done->pcrSelections[i];
        TPMS_PCR_SELECTION *it_base = NULL;
        unsigned            smaller = 0;

        /*
         * According to TPM2 library specification, PCR_Read() should return
         * selector for the bank even when no PCRs are returned for it and
         * return PCR selections in order, so these indices should be the same.
         * In case they aren't, iterate over all selections and compare hash
         * IDs.
         */
        if (it_done->hash == base->pcrSelections[i].hash) {
            it_base = &base->pcrSelections[i];
        } else {
            fprintf(stderr, "Warning: different order of PCR selections."
                    " This does not comply with specification.\n");
            for (unsigned j = 0; j < base->count; j++) {
                if (it_done->hash == base->pcrSelections[j].hash) {
                    it_base = &base->pcrSelections[j];
                    break;
                }
            }

            if (it_base == NULL) {
                fprintf(stderr, "Error: Cannot remove PCRs for hash ID = %04x,"
                        " no such ID found in base selection\n", it_done->hash);
                /*
                 * Skip this and try other selections. If there were any PCRs
                 * for this algorithm, total number of returned digests won't
                 * match expected value and an error will be returned later.
                 */
                continue;
            }
        }

        /* Not sure if they are always equal, doing it safely */
        smaller = it_done->sizeofSelect > it_base->sizeofSelect ?
                  it_base->sizeofSelect : it_done->sizeofSelect;

        /*
         * Doing XOR instead of masking so bad values returned by TPM are
         * caught when checking number of hashes left after final PCR_Read().
         */
        for (unsigned j = 0; j < smaller; j++)
            it_base->pcrSelect[j] ^= it_done->pcrSelect[j];
    }
}

static UsefulBuf cbor_pcr_assertions(UsefulBuf buf, uint32_t pcr_update_ctr,
                                     TPML_DIGEST const *vals_unb,
                                     TPML_PCR_SELECTION const *sel)
{
    unsigned cursor = 0;
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, buf);

    QCBOREncode_OpenMap(&ctx);
        QCBOREncode_AddUInt64ToMap(&ctx, "update_ctr", pcr_update_ctr);
        QCBOREncode_OpenArrayInMap(&ctx, "banks");
        for (unsigned i = 0; i < sel->count; i++) {
            /*
             * Different banks may implement different sets of PCRs. Right now
             * this is not supported by attester (test in get_pcr_assertions())
             * but PCR bitmap is sent per bank anyway so format of data passed
             * to token won't have to be changed when it gets implemented.
             */
            uint32_t pcrs = 0;
            for (unsigned ii = 0; ii < sel->pcrSelections[i].sizeofSelect; ii++)
                pcrs |= sel->pcrSelections[i].pcrSelect[ii] << 8*ii;

            QCBOREncode_OpenMap(&ctx);
                QCBOREncode_AddUInt64ToMap(&ctx, "algo_id", sel->pcrSelections[i].hash);
                QCBOREncode_AddUInt64ToMap(&ctx, "pcrs", pcrs);
                QCBOREncode_OpenArrayInMap(&ctx, "pcr");
                for (unsigned ii = 0; ii < __builtin_popcount(pcrs); ii++) {
                    UsefulBufC ub = {vals_unb->digests[cursor].buffer,
                                     vals_unb->digests[cursor].size};
                    QCBOREncode_AddBytes(&ctx, ub);
                    cursor++;
                }
                QCBOREncode_CloseArray(&ctx);
            QCBOREncode_CloseMap(&ctx);
        }
        QCBOREncode_CloseArray(&ctx);
    QCBOREncode_CloseMap(&ctx);

    UsefulBufC EncodedCBOR;
    QCBORError uErr;
    uErr = QCBOREncode_Finish(&ctx, &EncodedCBOR);

    if(uErr != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOR error: %d\n", uErr);
        return NULLUsefulBuf;
    } else {
        return UsefulBuf_Unconst(EncodedCBOR);
    }
}

static UsefulBuf get_pcr_assertions(void)
{
    UsefulBuf           ret = SizeCalculateUsefulBuf;
    TSS2_RC             tss_ret;
    TPML_PCR_SELECTION *pcr_sel_out = NULL;
    UINT32              pcr_update_ctr;
    TPML_DIGEST        *pcr_vals = NULL;
    /*
     * TPML_DIGEST only has place for 8 digests. Pointer below will point to
     * modified version that will be malloc()'ed and doesn't have this limit.
     *
     * Coverage tools may still complain about out-of-bounds access. If this
     * poses an issue, new type will have to be defined just for that.
     *
     * Tss2_MU_TPML_DIGEST_Marshal() has internal check for 'count' field so it
     * can't be used on unbounded version of TPML_DIGEST.
     */
    TPML_DIGEST          *unbounded_pcr_vals = NULL;
    TPML_PCR_SELECTION    pcr_sel;
    TPMS_CAPABILITY_DATA *cap;

    tss_ret = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                 ESYS_TR_NONE, TPM2_CAP_PCRS, 0,
                                 1, NULL, &cap);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_GetCapability() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    pcr_sel = cap->data.assignedPCR;

    Esys_Free(cap);

    TPML_PCR_SELECTION  pcr_sel_orig = pcr_sel;
    unsigned            num_digests = get_num_of_digests(&pcr_sel);

    unbounded_pcr_vals = malloc(sizeof(TPML_DIGEST) - sizeof(TPM2B_DIGEST[8])
                                + num_digests * sizeof(TPM2B_DIGEST));
    unbounded_pcr_vals->count = num_digests;

    for (unsigned dgst_offset = 0; dgst_offset < num_digests;) {
        tss_ret = Esys_PCR_Read(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                ESYS_TR_NONE, &pcr_sel, &pcr_update_ctr,
                                &pcr_sel_out, &pcr_vals);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_PCR_Read() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }

        if (pcr_vals->count != get_num_of_digests(pcr_sel_out)) {
            fprintf(stderr, "Error: returned PCR selection doesn't match number"
                    " of digests (%d != %d)\n",
                    get_num_of_digests(pcr_sel_out), pcr_vals->count);
            goto error;
        }

        /* Copy returned digests to bigger buffer */
        for (unsigned i = 0; i < pcr_vals->count; i++) {
            memcpy(&unbounded_pcr_vals->digests[dgst_offset + i],
                   &pcr_vals->digests[i],
                   sizeof(TPM2B_DIGEST));
        }

        /* Remove read PCRs from PCR selection */
        update_pcr_selection(&pcr_sel, pcr_sel_out);

        dgst_offset += pcr_vals->count;

        Esys_Free(pcr_sel_out);
        pcr_sel_out = NULL;
        Esys_Free(pcr_vals);
        pcr_vals = NULL;
    }

    if (get_num_of_digests(&pcr_sel) != 0) {
        fprintf(stderr, "Error: Not all requested PCR values were read\n");
        goto error;
    }

    ret = cbor_pcr_assertions(SizeCalculateUsefulBuf, pcr_update_ctr,
                              unbounded_pcr_vals, &pcr_sel_orig);
    ret.ptr = malloc(ret.len);
    ret = cbor_pcr_assertions(ret, pcr_update_ctr, unbounded_pcr_vals,
                              &pcr_sel_orig);

error:
    Esys_Free(pcr_sel_out);
    Esys_Free(pcr_vals);

    if (unbounded_pcr_vals != NULL)
        free(unbounded_pcr_vals);

    return ret;
}

UsefulBuf get_signed_rim(UsefulBufC nonce)
{
    UsefulBuf   ret = NULLUsefulBuf;
    UsefulBuf   data = NULLUsefulBuf;

    data = get_pcr_assertions();
    if (UsefulBuf_IsNULLOrEmpty(data)) {
        fprintf(stderr, "Empty PCR assertions\n");
        goto error;
    }

    ret = sign_with_aik(data, nonce);
    if (UsefulBuf_IsNULLOrEmpty(data)) {
        fprintf(stderr, "Couldn't sign RIM\n");
        goto error;
    }

error:
    if (data.ptr)
        free(data.ptr);

    return ret;
}

static void parse_quote_input(UsefulBuf in, TPM2B_DATA *nonce,
                              TPML_PCR_SELECTION *sel)
{
    QCBORError              uErr;
    QCBORDecodeContext      ctx;
    QCBORItem               item = {0};
    static const char       label[] = "banks";
    UsefulBufC              raw_nonce = NULLUsefulBufC;
    bool                    nonce_is_first;

    memset(nonce, 0, sizeof(*nonce));
    memset(sel, 0, sizeof(*sel));

    QCBORDecode_Init(&ctx, UsefulBuf_Const(in), QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&ctx, NULL);
        /*
         * QCBORDecode_EnterArrayFromMapSZ() doesn't return QCBORItem so it
         * isn't possible to get number of items in the array that way.
         *
         * Unfortunately, this complicates decoding in multiple ways:
         * 1) We have to manually validate whether name of array is "banks".
         *    Using memcmp() and strlen() because label is not null-terminated.
         * 2) *FromMap() functions search whole map, but plain EnterArray does
         *    not. We have to ask precisely for correct type of next item.
         * 3) Order of items is not strictly specified, and Fobnail Token is
         *    free to choose the order it prefers. In this case, we don't know
         *    if first item in top-level map is "nonce" or "banks".
         *
         * Current implementation can handle different order of items. In
         * comparison to fully spiffy solution, it can't parse CBOR with
         * additional fields in top-level map, undefined in code below (unless
         * "banks" is second label/data pair in that map).
         */

        /* Check type of first element - does not advance cursor */
        uErr = QCBORDecode_PeekNext(&ctx, &item);
        nonce_is_first = item.uDataType != QCBOR_TYPE_ARRAY;
        if (nonce_is_first) {
            /*
             * Get nonce. This checks whole map for errors (e.g. duplicate
             * labels) and in order to do so, cursor is moved to the end of
             * current map (or array).
             */
            QCBORDecode_GetByteStringInMapSZ(&ctx, "nonce", &raw_nonce);
            /* Rewind to start of current map (array) and skip first element */
            QCBORDecode_Rewind(&ctx);
            QCBORDecode_GetNext(&ctx, &item);
        }

        /* Parse array - cursor is advanced as needed */
        QCBORDecode_EnterArray(&ctx, &item);
            if (item.uDataType != QCBOR_TYPE_ARRAY ||
                item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
                item.label.string.len != strlen(label) ||
                memcmp(&label, item.label.string.ptr, strlen(label))) {
                    fprintf(stderr, "Bad CBOR format for quote command\n");
                    return;
            }
            sel->count = item.val.uCount;
            for (unsigned i = 0; i < sel->count; i++) {
                uint64_t tmp;
                TPMS_PCR_SELECTION *cursel = &sel->pcrSelections[i];
                QCBORDecode_EnterMap(&ctx, NULL);
                    QCBORDecode_GetUInt64InMapSZ(&ctx, "algo_id", &tmp);
                    cursel->hash = tmp;
                    QCBORDecode_GetUInt64InMapSZ(&ctx, "pcrs", &tmp);
                    cursel->sizeofSelect = 3;
                    cursel->pcrSelect[0] = tmp >>  0 & 0xff;
                    cursel->pcrSelect[1] = tmp >>  8 & 0xff;
                    cursel->pcrSelect[2] = tmp >> 16 & 0xff;
                QCBORDecode_ExitMap(&ctx);
            }
        QCBORDecode_ExitArray(&ctx);

        if (!nonce_is_first) {
            /*
             * Get nonce from current nesting level - searches whole map (array)
             * and cursor is moved to the end of it, but it won't be necessary
             * anymore so don't bother rewinding.
             */
            QCBORDecode_GetByteStringInMapSZ(&ctx, "nonce", &raw_nonce);
        }

        nonce->size = raw_nonce.len;
        memcpy((uint8_t *)nonce + 2, raw_nonce.ptr, raw_nonce.len);
    QCBORDecode_ExitMap(&ctx);

    /* Catch decoding error here */
    uErr = QCBORDecode_Finish(&ctx);
    if (uErr != QCBOR_SUCCESS) {
        fprintf(stderr, "QCBOR error3: %d\n", uErr);
        nonce->size = 0;
        sel->count = 0;
    }
}

UsefulBuf do_quote(UsefulBuf in)
{
    TSS2_RC                tss_ret;
    ESYS_TR                session, aik;
    UsefulBuf              ret = NULLUsefulBuf;
    TPML_PCR_SELECTION     selection;
    TPM2B_DATA             nonce;

    TPM2B_ATTEST          *attest = NULL;
    UsefulBuf              attest_ub;

    TPMT_SIGNATURE        *tpm_sign = NULL;
    UsefulBuf              raw_sign = NULLUsefulBuf;

    parse_quote_input(in, &nonce, &selection);

    tss_ret = Esys_StartAuthSession(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                    &nonceCaller, TPM2_SE_HMAC, &sym_null,
                                    TPM2_ALG_SHA256, &session);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_StartAuthSession() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_TR_FromTPMPublic(esys_ctx, AIK_NV_HANDLE, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &aik);
    if (tss_ret != TSS2_RC_SUCCESS){
        fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_Quote(esys_ctx, aik, session, ESYS_TR_NONE, ESYS_TR_NONE,
                         &nonce, &sig_scheme, &selection,
                         &attest, &tpm_sign);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_Quote() %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    raw_sign.len = tpm_sign->signature.rsassa.sig.size;
    raw_sign.ptr = tpm_sign->signature.rsassa.sig.buffer;

    attest_ub.ptr = &attest->attestationData[0];
    attest_ub.len = attest->size;
    ret = concat_data_sign(attest_ub, raw_sign, SizeCalculateUsefulBuf);
    ret.ptr = malloc(ret.len);
    ret = concat_data_sign(attest_ub, raw_sign, ret);

error:
    Esys_FlushContext(esys_ctx, session);
    Esys_Free(tpm_sign);
    Esys_Free(attest);

    return ret;
}

TSS2_RC init_tpm_keys(void)
{
    TSS2_RC                tss_ret = TSS2_RC_SUCCESS;
    ESYS_TR                parent = ESYS_TR_NONE;
    ESYS_TR                aik = ESYS_TR_NONE;
    ESYS_TR                tmp_new, session;
    TPML_PCR_SELECTION     creationPCR = { .count = 0, };
    TPMS_CAPABILITY_DATA  *capabilityData = NULL;
    TPM2B_PRIVATE         *keyPrivate;
    TSS2_ABI_VERSION       curVersion = TSS2_ABI_VERSION_CURRENT;

    /* Initialize the Esys context */

    tss_ret = Tss2_TctiLdr_Initialize(NULL, &tcti_ctx);
    if (tss_ret != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Tss2_TctiLdr_Initialize %s\n",
                Tss2_RC_Decode(tss_ret));
        goto error;
    }

    tss_ret = Esys_Initialize(&esys_ctx, tcti_ctx, &curVersion);
    if (tss_ret == TSS2_SYS_RC_ABI_MISMATCH) {
        fprintf(stderr, "Warning: Esys_Initialize() mismatch of API version "
                        "between TSS headers and library. Some things may not "
                        "work as expected.\n");
        tss_ret = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    }
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
        /* Create and load EK */
        tss_ret = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_ENDORSEMENT,
                                     ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                     ESYS_TR_NONE, &inSensitive,
                                     &primaryRsaTemplate, NULL, &creationPCR,
                                     &parent, NULL, NULL, NULL, NULL);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_CreatePrimary() %s\n",
            Tss2_RC_Decode(tss_ret));
            goto error;
        }

        /* Start authorization session and create AIK */
        tss_ret = start_policy_auth(&session);
        if (tss_ret != TSS2_RC_SUCCESS)
            goto error;

        tss_ret = Esys_Create(esys_ctx, parent, session, ESYS_TR_NONE,
                              ESYS_TR_NONE, &inSensitive, &keyTemplate, NULL,
                              &creationPCR, &keyPrivate, &keyPublic, NULL, NULL,
                              NULL);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_Create() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, session);

        /* Restart identical authorization session and load AIK */
        tss_ret = start_policy_auth(&session);
        if (tss_ret != TSS2_RC_SUCCESS)
            goto error;

        tss_ret = Esys_Load(esys_ctx, parent, session, ESYS_TR_NONE,
                            ESYS_TR_NONE, keyPrivate, keyPublic, &aik);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_Load() %s\n", Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, session);

        /* Clear private AIK, it won't be needed */
        memset(keyPrivate, 0, sizeof(*keyPrivate));
        Esys_Free(keyPrivate);
        keyPrivate = NULL;

        /* Make AIK persistent */
        tss_ret = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, aik,
                                    ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                    ESYS_TR_NONE, AIK_NV_HANDLE, &tmp_new);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_EvictControl() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, aik);

        /* Make EK persistent */
        tss_ret = Esys_EvictControl(esys_ctx, ESYS_TR_RH_OWNER, parent,
                                    ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                    ESYS_TR_NONE, EK_NV_HANDLE, &tmp_new);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_EvictControl() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
        Esys_FlushContext(esys_ctx, parent);
    } else {
        /* Read public AIK from NV handle */
        tss_ret = Esys_TR_FromTPMPublic(esys_ctx, AIK_NV_HANDLE, ESYS_TR_NONE,
                                        ESYS_TR_NONE, ESYS_TR_NONE, &aik);
        if (tss_ret != TSS2_RC_SUCCESS){
            fprintf(stderr, "Error: Esys_TR_FromTPMPublic() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }

        tss_ret = Esys_ReadPublic(esys_ctx, aik, ESYS_TR_NONE, ESYS_TR_NONE,
                                  ESYS_TR_NONE, &keyPublic, NULL, NULL);
        if (tss_ret != TSS2_RC_SUCCESS) {
            fprintf(stderr, "Error: Esys_ReadPublic() %s\n",
                    Tss2_RC_Decode(tss_ret));
            goto error;
        }
    }

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

    /* All handles should be already flushed, this will print all missed ones */
    flush_tpm_contexts(esys_ctx, TPM2_HMAC_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_LOADED_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_POLICY_SESSION_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_TRANSIENT_FIRST);
    flush_tpm_contexts(esys_ctx, TPM2_ACTIVE_SESSION_FIRST);

    Esys_Finalize(&esys_ctx);

    Tss2_TctiLdr_Finalize(&tcti_ctx);
}
