#ifndef _H_META
#define _H_META

#include <stdint.h>

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
    uint8_t              header_version;
    uint8_t              mac[6];         /* MAC address */
    char           *serial_number;       /* Serial number */
    char           *manufacturer;
    char           *product_name;
    struct EKcert_hash  EK_hash;  /* EKcert hash */
} __attribute__((packed));

#define META_H_VERSION  1

#define SYS_FIRMWARE_DIR "/sys/firmware/dmi/tables"
#define SYS_ENTRY_FILE SYS_FIRMWARE_DIR "/smbios_entry_point"
#define SYS_TABLE_FILE SYS_FIRMWARE_DIR "/DMI"

int get_meta_data(struct meta_data *meta);
int get_dmi_system_info(struct meta_data *meta);

#endif /* _H_META */

