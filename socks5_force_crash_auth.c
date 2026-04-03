#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef int (*connect_func_t)(int, const struct sockaddr *, socklen_t);
static connect_func_t real_connect = NULL;

#define PROXY_IP   "192.204.3.153"
#define PROXY_PORT 12324
#define PROXY_USER "zwezabnw"
#define PROXY_PASS "fo8t7t"

static void hard_fail() {
    abort();
}

static int socks5_auth(int sock) {
    unsigned char buf[513];
    size_t ulen = strlen(PROXY_USER);
    size_t plen = strlen(PROXY_PASS);

    buf[0] = 0x01;
    buf[1] = (unsigned char)ulen;
    memcpy(&buf[2], PROXY_USER, ulen);
    buf[2 + ulen] = (unsigned char)plen;
    memcpy(&buf[3 + ulen], PROXY_PASS, plen);

    size_t total = 3 + ulen + plen;

    if (write(sock, buf, total) != total) return -1;
    if (read(sock, buf, 2) != 2) return -1;
    if (buf[1] != 0x00) return -1;

    return 0;
}

static int socks5_handshake(int sock, const struct sockaddr_in *target) {
    unsigned char buf[262];

    buf[0] = 0x05;
    buf[1] = 0x01;
    buf[2] = 0x02;
    if (write(sock, buf, 3) != 3) return -1;

    if (read(sock, buf, 2) != 2) return -1;
    if (buf[1] != 0x02) return -1;

    if (socks5_auth(sock) != 0) return -1;

    buf[0] = 0x05;
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 0x01;

    memcpy(&buf[4], &target->sin_addr, 4);
    memcpy(&buf[8], &target->sin_port, 2);

    if (write(sock, buf, 10) != 10) return -1;
    if (read(sock, buf, 10) < 2) return -1;
    if (buf[1] != 0x00) return -1;

    return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        real_connect = (connect_func_t)dlsym(RTLD_NEXT, "connect");
        if (!real_connect) return -1;
    }

    if (addr->sa_family != AF_INET) {
        return real_connect(sockfd, addr, addrlen);
    }

    struct sockaddr_in proxy;
    proxy.sin_family = AF_INET;
    proxy.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP, &proxy.sin_addr);

    if (real_connect(sockfd, (struct sockaddr *)&proxy, sizeof(proxy)) != 0) {
        hard_fail();
    }

    if (socks5_handshake(sockfd, (struct sockaddr_in *)addr) != 0) {
        hard_fail();
    }

    return 0;
}
