/**
 * Some LICENSE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <stdbool.h>
#include <tss2/tss2_rc.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>

#include <fobnail-attester/meta.h>
#include <fobnail-attester/tpm2-crypto.h>

static volatile sig_atomic_t quit = 0;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; /* default port 5683 */

static void signal_handler(int signum)
{
    quit = signum;
}

static void coap_free_wrapper(coap_session_t *session, void *app_ptr)
{
    (void)session; /* unused */
    if (app_ptr != NULL)
        free(app_ptr);
}

static void coap_attest_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                const struct coap_pdu_t* in, const struct coap_string_t* query,
                struct coap_pdu_t* out)
{
    int ret;
    char *res_buf = "Response from server.\n";
    size_t res_buf_len = strlen(res_buf);

    printf("Received message: %s\n", coap_get_uri_path(in)->s);

    /* prepare and send response */
    coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
    ret = coap_add_data_large_response(resource,
                       session,
                       in,
                       out,
                       query,
                       COAP_MEDIATYPE_APPLICATION_CBOR,
                       -1,
                       0,
                       res_buf_len,
                       (const uint8_t *)res_buf,
                       NULL,
                       res_buf);
    if (ret == 0)
        fprintf(stderr, "Err: cannot response.\n");

}

static void coap_ek_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                const struct coap_pdu_t* in, const struct coap_string_t* query,
                struct coap_pdu_t* out)
{
    int ret;

    printf("Received message: %s\n", coap_get_uri_path(in)->s);

    UsefulBuf ub = encode_ek();
    if (UsefulBuf_IsNULLOrEmpty(ub)) {
        fprintf(stderr, "Error: cannot obtain EK\n");
        /* We probably should mention the error in response */
        quit = -1;
        return;
    }

    /* prepare and send response */
    coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
    ret = coap_add_data_large_response(resource,
                       session,
                       in,
                       out,
                       query,
                       COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
                       -1,
                       0,
                       ub.len,
                       ub.ptr,
                       coap_free_wrapper,
                       ub.ptr);
    if (ret == 0)
        fprintf(stderr, "Err: cannot response.\n");

}

static void coap_aik_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                const struct coap_pdu_t* in, const struct coap_string_t* query,
                struct coap_pdu_t* out)
{
    int ret;

    printf("Received message: %s\n", coap_get_uri_path(in)->s);

    UsefulBuf ub = encode_aik();
    if (UsefulBuf_IsNULLOrEmpty(ub)) {
        fprintf(stderr, "Error: cannot encode AIK into CBOR\n");
        /* We probably should mention the error in response */
        quit = -1;
        return;
    }

    /* prepare and send response */
    coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
    ret = coap_add_data_large_response(resource,
                       session,
                       in,
                       out,
                       query,
                       COAP_MEDIATYPE_APPLICATION_CBOR,
                       -1,
                       0,
                       ub.len,
                       ub.ptr,
                       coap_free_wrapper,
                       ub.ptr);
    if (ret == 0)
        fprintf(stderr, "Err: cannot response.\n");

}

static inline void free_null_ptr(void *ptr)
{
    if (ptr != NULL) {
        free(ptr);
        ptr = NULL;
    }
}

UsefulBuf _encode_metadata(UsefulBuf Buffer, struct meta_data *meta)
{
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, Buffer);

    QCBOREncode_OpenMap(&ctx);
        QCBOREncode_AddUInt64ToMap(&ctx, "version", meta->header_version);
        UsefulBufC mac = { meta->mac, sizeof(meta->mac) };
        QCBOREncode_AddBytesToMap(&ctx, "mac", mac);

        QCBOREncode_AddSZStringToMap(&ctx, "manufacturer",
                                     meta->manufacturer ? meta->manufacturer : "");
        QCBOREncode_AddSZStringToMap(&ctx, "product_name",
                                     meta->product_name ? meta->product_name : "");
        QCBOREncode_AddSZStringToMap(&ctx, "serial_number",
                                     meta->serial_number ? meta->serial_number : "");

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

UsefulBuf encode_meta(struct meta_data *meta)
{
    UsefulBuf ret = NULLUsefulBuf;

    //TODO: Error handling?
    ret = _encode_metadata(SizeCalculateUsefulBuf, meta);
    ret.ptr = malloc(ret.len);
    ret = _encode_metadata(ret, meta);

    return ret;
}

UsefulBuf _encode_signed_object(UsefulBuf Buffer, UsefulBuf object) {
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, Buffer);

    // TODO: sign data using AIK
    UsefulBufC signature = { NULL, 0 };

    QCBOREncode_OpenMap(&ctx);
        QCBOREncode_AddBytesToMap(&ctx, "data", UsefulBuf_Const(object));
        QCBOREncode_AddBytesToMap(&ctx, "signature", signature);
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

UsefulBuf encode_signed_object(UsefulBuf ub) {
    UsefulBuf ret = NULLUsefulBuf;

    //TODO: Error handling?
    ret = _encode_signed_object(SizeCalculateUsefulBuf, ub);
    ret.ptr = malloc(ret.len);
    ret = _encode_signed_object(ret, ub);

    return ret;
}

static void coap_metadata_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                                  const struct coap_pdu_t* in, const struct coap_string_t* query,
                                  struct coap_pdu_t* out)
{
    int ret;
    UsefulBuf ub_meta;
    UsefulBuf ub;
    struct meta_data meta;
    printf("Received message: %s\n", coap_get_uri_path(in)->s);

    /* Obtain meta information */
    memset(&meta, 0, sizeof(struct meta_data));
    if (get_meta_data(&meta) < 0) {
        fprintf(stderr, "Cannot obtain full meta information\n");
        quit = -1;
        return;
    }

    ub_meta = encode_meta(&meta);

    free_null_ptr(meta.manufacturer);
    free_null_ptr(meta.product_name);
    free_null_ptr(meta.serial_number);

    if (UsefulBuf_IsNULLOrEmpty(ub_meta)) {
        fprintf(stderr, "Error: cannot encode meta information into CBOR\n");
        quit = -1;
        return;
    }

    ub = encode_signed_object(ub_meta);
    free(ub_meta.ptr);
    if (UsefulBuf_IsNULLOrEmpty(ub)) {
        fprintf(stderr, "Error: failed to sign metadata\n");
        quit = -1;
        return;
    }

    /* prepare and send response */
    coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
    ret = coap_add_data_large_response(resource,
                         session,
                         in,
                         out,
                         query,
                         COAP_MEDIATYPE_APPLICATION_CBOR,
                         -1,
                         0,
                         ub.len,
                         ub.ptr,
                         coap_free_wrapper,
                         ub.ptr);
    if (ret == 0)
        fprintf(stderr, "Err: cannot response.\n");
}

static void coap_aik_marshaled_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                const struct coap_pdu_t* in, const struct coap_string_t* query,
                struct coap_pdu_t* out)
{
    int ret;

    printf("Received message: %s\n", coap_get_uri_path(in)->s);

    UsefulBuf ub = encode_aik_marshaled();
    if (UsefulBuf_IsNULLOrEmpty(ub)) {
        fprintf(stderr, "Error: cannot obtain AIK\n");
        /* We probably should mention the error in response */
        quit = -1;
        return;
    }

    /* prepare and send response */
    coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
    ret = coap_add_data_large_response(resource,
                       session,
                       in,
                       out,
                       query,
                       COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
                       -1,
                       0,
                       ub.len,
                       ub.ptr,
                       coap_free_wrapper,
                       ub.ptr);
    if (ret == 0)
        fprintf(stderr, "Err: cannot response.\n");

}

static void coap_challenge_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                const struct coap_pdu_t* in, const struct coap_string_t* query,
                struct coap_pdu_t* out)
{
    int ret;
    size_t len, total, offset;
    static UsefulBuf ub;
    const uint8_t *data;

    printf("Received message: %s\n", coap_get_uri_path(in)->s);

    coap_get_data_large(in, &len, &data, &offset, &total);

    /* First PDU */
    if (ub.ptr == NULL) {
        ub.ptr = malloc(total);
        ub.len = total;
    }

    memcpy((uint8_t *)ub.ptr + offset, data, len);

    /* Last PDU */
    if (total == offset + len) {
        /* prepare and send response */
        UsefulBuf ub2 = do_challenge(ub);

        coap_pdu_set_code(out, COAP_RESPONSE_CODE_CREATED);
        ret = coap_add_data_large_response(resource,
                           session,
                           in,
                           out,
                           query,
                           COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
                           -1,
                           0,
                           ub2.len,
                           ub2.ptr,
                           coap_free_wrapper,
                           ub2.ptr);
        free(ub.ptr);
        ub = NULLUsefulBuf;
        if (ret == 0)
            fprintf(stderr, "Err: cannot response.\n");
    }
}

void att_coap_add_resource(struct coap_context_t* coap_context,
               coap_request_t method, const char* resource_name,
               coap_method_handler_t handler)
{
    coap_str_const_t* resource_uri = coap_new_str_const((uint8_t const*)resource_name, strlen(resource_name));
    coap_resource_t* resource = coap_resource_init(resource_uri, COAP_RESOURCE_FLAGS_RELEASE_URI);
    coap_register_handler(resource, method, handler);
    coap_add_resource(coap_context, resource);
}

coap_endpoint_t* att_coap_new_endpoint(coap_context_t* coap_context,
                           const char* listen_address, const uint16_t port,
                           const coap_proto_t coap_protocol)
{
    /* prepare address */
    coap_address_t addr = {0};
    coap_address_init(&addr);
    addr.addr.sin.sin_family = AF_INET;
    inet_pton(AF_INET, listen_address, &addr.addr.sin.sin_addr);
    addr.addr.sin.sin_port = htons(port);

    /* create endpoint */
    return coap_new_endpoint(coap_context, &addr, coap_protocol);
}

coap_context_t* att_coap_new_context(const bool enable_coap_block_mode)
{
    /* startup */
    coap_startup();

    /* create new context */
    coap_context_t* coap_context = NULL;
    if ((coap_context = coap_new_context(NULL)) != NULL) {
        if (enable_coap_block_mode)
            /* enable block handling by libcoap */
            coap_context_set_block_mode(coap_context, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);
    }

    return coap_context;
}

/* --------------------------- main ----------------------------- */

#define UNUSED  __attribute__((unused))

int main(int UNUSED argc, char UNUSED *argv[])
{
    int result;

    /* signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* TODO: parse CLI arguments if needed */
    /*result = parse_command_line_arguments(argc, argv, ...) != 0
    if (result) {
        // 1 means help message is displayed, -1 means error
        return (result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
    }*/

    /* Generate attestation identity key */
    if (init_tpm_keys() != TSS2_RC_SUCCESS) {
        printf("Cannot generate AIK\n");
        return EXIT_FAILURE;
    }

    /* TODO: sign attestation identity key */

    coap_context_t* coap_context = NULL;
    coap_endpoint_t* coap_endpoint = NULL;

    coap_context = att_coap_new_context(true);
    if (coap_context == NULL) {
        printf("Cannot create CoAP context.\n");
        goto error;
    }

    printf("Creating CoAP server endpoint using UDP.\n");
    if ((coap_endpoint = att_coap_new_endpoint(coap_context, LISTEN_ADDRESS, port, COAP_PROTO_UDP)) == NULL) {
        printf("Cannot create CoAP server endpoint based on UDP.\n");
        goto error;
    }

    /* register CoAP resource and resource handler */
    printf("Registering CoAP resources.\n");
    att_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "attest", coap_attest_handler);
    att_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "ek", coap_ek_handler);
    att_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "aik", coap_aik_handler);
    att_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "aik_marshaled", coap_aik_marshaled_handler);
    att_coap_add_resource(coap_context, COAP_REQUEST_FETCH, "metadata", coap_metadata_handler);
    att_coap_add_resource(coap_context, COAP_REQUEST_POST, "challenge", coap_challenge_handler);

    /* enter main loop */
    printf("Entering main loop.\n");
    while (!quit) {
        /* process CoAP I/O */
        if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
            printf("Error during CoAP I/O processing.\n");
            goto error;
        }
    }

    result = EXIT_SUCCESS;
    goto finish;

error:
    result = EXIT_FAILURE;

finish:
    /* free CoAP memory */
    coap_free_endpoint(coap_endpoint);
    coap_endpoint = NULL;
    coap_free_context(coap_context);
    coap_context = NULL;

    coap_cleanup();

    tpm_cleanup();

    return result;
}


