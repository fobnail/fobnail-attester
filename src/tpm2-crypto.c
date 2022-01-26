#include <stdio.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

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

TSS2_RC att_generate_id_key(void)
{
    TSS2_RC 	   tss_ret = TSS2_RC_SUCCESS;
    ESYS_CONTEXT	   *esys_ctx = NULL;
    TSS2_TCTI_CONTEXT  *tcti_ctx = NULL;
    ESYS_TR 	   parent = ESYS_TR_NONE;
    TPM2B_PUBLIC 	   *keyPublic = NULL;
    TPM2B_PRIVATE	   *keyPrivate = NULL;
    TPM2B_PUBLIC	   inPublic = keyTemplate;
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

    TPM2B_DATA outsideInfo = { .size = 0, };
    TPML_PCR_SELECTION creationPCR = { .count = 0, };
    TPM2B_DIGEST ownerauth = { .size = 0 };
    TPMS_CAPABILITY_DATA *capabilityData = NULL;

    /* Initialize the Esys context */

    if ((tss_ret = Tss2_TctiLdr_Initialize(NULL, &tcti_ctx)) != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Tss2_TctiLdr_Initialize\n");
        goto error;
    }

    if ((tss_ret = Esys_Initialize(&esys_ctx, tcti_ctx, NULL)) != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Esys_Initialize()\n");
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

    tss_ret = Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
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

error:
    if (esys_ctx != NULL)
        Esys_Finalize(&esys_ctx);

    if (tcti_ctx != NULL)
        Tss2_TctiLdr_Finalize(&tcti_ctx);

    return tss_ret;
}
