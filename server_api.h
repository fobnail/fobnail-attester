#pragma once

void coap_metadata_fetch_handler(
    struct coap_resource_t* resource,
    struct coap_session_t* session,
    const struct coap_pdu_t* in,
    const struct coap_string_t* query,
    struct coap_pdu_t* out
);
