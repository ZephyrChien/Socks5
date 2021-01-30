#include "utils.h"
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BACKLOG 1024
#define BUFFERSIZE 2048

#define RSV 0x00
#define VERSION 0x05

#define METHOD_NOAUTH 0x00
#define METHOD_USERNAME_PASSWORD 0x02
#define AUTH_SUCCEED 0x00
#define AUTH_FAILED 0x01

#define CMD_CONNECT 0x01
#define CMD_BIND 0x02
#define CMD_UDP_ASSOCIATE 0x03

#define ATYP_IPV4 0x01
#define ATYP_DOMAIN 0x03
#define ATYP_IPV6 0x04

#define REP_SUCCEEDED 0x00
#define REP_GENERAL_FAILED 0x01
#define REP_CONNECTION_NOT_ALLOWED 0x02
#define REP_NETWORK_UNREACHABLE 0x03
#define REP_HOST_UNREACHABLE 0x04
#define REP_CONNECTION_REFUSED 0x05
#define REP_TTL_EXPIRED 0x06
#define REP_COMMAND_NOT_SUPPORTED 0x07
#define REP_ADDRESS_NOT_SUPPORTED 0x08

typedef struct proxy_d
{
    int srcfd;
    int dstfd;
} proxy_d;

typedef struct handle_d
{
    int connfd;
    s5_auth *auth;
} handle_d;

typedef struct auth_method
{
    uint8_t nmethods;
    uint8_t methods[7];
} auth_method;

typedef struct request
{
    uint8_t cmd;
    uint8_t atyp;
    uint16_t port;
    char*   addr;
} request;

// basic func
int dial(const char *addr, int port);

int dial6(const char *addr, int port);

int lstn(const char *addr, int port);

int readn(int fd, void *vbuf, int n);

int readmax(int fd, void *vbuf, int n);

int writen(int fd, const void *vbuf, int n);

// socks5 func
int recv_auth_method(int fd, auth_method *method);

int send_auth_method(int fd, const uint8_t method);

int recv_auth(int fd, s5_auth *auth);

int send_auth_stat(int fd, const uint8_t stat);

int recv_request(int fd, request *r);

int send_response(int fd, const uint8_t resp_code);

void *proxy(void *proxy_data);

// handlers
int handle_auth(int fd, const s5_auth *auth);

int handle_request(int fd, request *r);

void *handle(void *handle_data);

void *socks5_serve(void *vconfig);