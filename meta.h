#ifndef _H_META
#define _H_META

#include <stdint.h>

/* Structure for serial number */
#define SN_SIZE 64
struct serial_number {
	uint8_t size;
	uint8_t number[SN_SIZE];
};

/* Enum for hash id */
enum {
	SHA1,
	SHA256,
	SHA512
};

/* Structure for EK cert hash */
struct EKcert_hash {
	uint8_t id; /* specify what hash algo is currently used, could be equal SHA1, SHA256... */
	union {
		uint8_t sha1_hash[20];
		uint8_t sha256_hash[32];
		uint8_t sha512_hash[64];
	} hash;
};

/* Structure for meta data for provisioning and attestation */
struct meta_data {
	// SHA-256 hash signed with AIK key
	uint8_t signature[32];
	uint8_t              mac[6];         /* MAC address */
	struct serial_number sn;       /* Serial number */
	struct EKcert_hash  EK_hash;  /* EKcert hash */       
} __attribute__((packed));

#endif /* _H_META */

