#ifndef _H_META
#define _H_META

#include <stdint.h>

/* Structure for meta data for provisioning and attestation */
struct meta_data {
    uint8_t     header_version;
    uint8_t     mac[6];               /* MAC address */
    char        *serial_number;       /* Serial number */
    char        *manufacturer;
    char        *product_name;
};

#define META_H_VERSION  1

#define SYS_FIRMWARE_DIR "/sys/firmware/dmi/tables"
#define SYS_ENTRY_FILE SYS_FIRMWARE_DIR "/smbios_entry_point"
#define SYS_TABLE_FILE SYS_FIRMWARE_DIR "/DMI"

struct dmi_header {
    uint8_t  type;
    uint8_t  length;
    uint16_t handle;
    uint8_t  data[];
};

struct sm2_t {
    char        anchor[4];
    uint8_t     eps_csum;
    uint8_t     eps_len;
    uint8_t     ver_maj;
    uint8_t     ver_min;
    uint16_t    max_struct_size;
    uint8_t     eps_rev;
    uint8_t     fa[5];
    char        dmi_anchor[5];
    uint8_t     inter_csum;
    uint16_t    len;
    uint32_t    addr;
    uint16_t    num;
    uint8_t     bcd_rev;
} __attribute__((packed));

struct sm3_t {
    char        anchor[5];
    uint8_t     eps_csum;
    uint8_t     eps_len;
    uint8_t     ver_maj;
    uint8_t     ver_min;
    uint8_t     docrev;
    uint8_t     eps_rev;
    uint8_t     reserved;
    uint32_t    len;
    uint64_t    addr;
} __attribute__((packed));

union sm_t {
    struct sm2_t sm2;
    struct sm3_t sm3;
};

#define SYS_INFO_TYPE       1
#define MRF_OFFSET          0
#define PN_OFFSET           1
#define SN_OFFSET           3

int get_meta_data(struct meta_data *meta);
int get_dmi_system_info(struct meta_data *meta);

#endif /* _H_META */

