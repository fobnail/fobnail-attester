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

#include <fobnail-attester/meta.h>
#include <fobnail-attester/tpm2-crypto.h>

static volatile sig_atomic_t quit = 0;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; /* default port 5683 */

static void signal_handler(int signum)
{
    quit = signum;
}

static void coap_attest_handler(struct coap_resource_t* resource, struct coap_session_t* session,
                const struct coap_pdu_t* in, const struct coap_string_t* query,
                struct coap_pdu_t* out)
{
    int ret;
    char *res_buf = "Response from server.\n";
    size_t res_buf_len = strlen(res_buf);

    printf("Received message.\n");

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

    /* TODO: generate attestation identity key */
    att_generate_id_key();

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

    return result;
}


