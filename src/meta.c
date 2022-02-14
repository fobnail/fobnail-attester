#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

#include <meta.h>

int fill_meta_mac_addr(const struct meta_data *meta)
{
    int sock;
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        fprintf(stderr, "Cannot perform ioctl(): %s\n", strerror(errno));
        close(sock);
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));



    return 0;
}
