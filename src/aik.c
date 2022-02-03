#include <coap3/coap.h>
#include <stdio.h>

static uint8_t message[] = {
    0x00
};

void coap_aik_fetch_handler(
    struct coap_resource_t* resource,
    struct coap_session_t* session,
    const struct coap_pdu_t* in,
    const struct coap_string_t* query,
    struct coap_pdu_t* out
) {
    printf("sending AIK");
    coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(
        resource,
        session,
        in,
        out,
        query,
        COAP_MEDIATYPE_APPLICATION_CBOR,
        -1,
        0,
        sizeof(message),
        message,
        NULL,
        NULL
    );
}
