#include "socks5.h"

// basic func
int dial(const char *addr, int port)
{
    int fd = socket(AF_INET,SOCK_STREAM,0);
    if (fd < 0 ) return -1;
    struct sockaddr_in raddr;
    memset(&raddr,0,sizeof(raddr));
    raddr.sin_family = AF_INET;
    raddr.sin_port = htons(port);
    if (inet_pton(AF_INET,addr,&raddr.sin_addr) < 0)
        return -1;
    if(connect(fd,(struct sockaddr*)&raddr,sizeof(raddr)) < 0)
        return -1;
    return fd;
}

int dial6(const char *addr, int port)
{
    int fd = socket(AF_INET6,SOCK_STREAM,0);
    if (fd < 0 ) return -1;
    struct sockaddr_in6 raddr;
    memset(&raddr,0,sizeof(raddr));
    raddr.sin6_family = AF_INET;
    raddr.sin6_port = htons(port);
    if (inet_pton(AF_INET6,addr,&raddr.sin6_addr) < 0)
        return -1;
    if(connect(fd,(struct sockaddr*)&raddr,sizeof(raddr)) < 0)
        return -1;
    return fd;
}

int lstn(const char *addr, int port)
{
    int fd = socket(AF_INET,SOCK_STREAM,0);
    if (fd < 0 ) return -1;
    struct sockaddr_in laddr;
    memset(&laddr,0,sizeof(laddr));
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons(port);
    if (inet_pton(AF_INET,addr,&laddr.sin_addr) < 0 )
        return -1;
    if (bind(fd,(struct sockaddr*)&laddr,sizeof(laddr)) < 0)
        return -1;
    if (listen(fd,BACKLOG) < 0)
        return -1;
    return fd;
}

int readn(int fd, void *vbuf, int n)
{
    int nread, nleft = n;
    int8_t *ptr = (int8_t *)vbuf;
    while (nleft > 0)
    {
        if ((nread = recv(fd, ptr, nleft,0)) < 0)
        {
            if (errno == EINTR)
                nread = 0;
            else
                return -1;
        }
        else if (nread == 0) break;
        ptr += nread;
        nleft -= nread;
    }
    return n - nleft;
}

int readmax(int fd, void *vbuf, int n)
{
    int nread;
    uint8_t *buf = (uint8_t *)vbuf;
    if ((nread = recv(fd,buf,n,0)) < 0 && errno == EINTR)
        return readmax(fd,vbuf,n);
    return nread;
}

int writen(int fd, const void *vbuf, int n)
{
    int nwrite, nleft = n;
    const int8_t *ptr = (int8_t *)vbuf;
    while (nleft > 0)
    {
        if ((nwrite = send(fd, ptr, nleft, 0)) <= 0)
        {
            if (nwrite < 0 && errno == EINTR)
                nwrite = 0;
            else
                return -1;
        }
        ptr += nwrite;
        nleft -= nwrite;
    }
    return n - nleft;
}


// socks5 func
int recv_auth_method(int fd, auth_method *method)
{
    uint8_t buf[8] = {0};
    if (readmax(fd,buf,8) < 3 || buf[0] != VERSION || buf[1] < 1 || buf[1] > 6)
        return -1;
    method-> nmethods = buf[1];
    int i, n = buf[1];
    for (i=0; i<n; i++)
        method-> methods[i] = buf[2+i];
    return 0;
}

int send_auth_method(int fd, const uint8_t method)
{
    uint8_t buf[2] = {0};
    buf[0] = VERSION;
    buf[1] = method;
    return writen(fd,buf,2);
}

int recv_auth(int fd, s5_auth *auth)
{
    uint8_t buf[MAX_ARG_LEN*2 + 3] = {0};
    if (readmax(fd,buf,MAX_ARG_LEN*2+3) < 3)
        return -1;
    int ulen = buf[1];
    int plen = buf[ulen+2];
    if (ulen < 1 || plen < 1 || ulen > MAX_ARG_LEN || plen > MAX_ARG_LEN)
        return -1;
    memcpy(auth-> username,buf+2,ulen);
    memcpy(auth-> password,buf+ulen+3,plen);
    return 0;
}

int send_auth_stat(int fd, const uint8_t stat)
{
    uint8_t buf[2] = {0};
    buf[0] = VERSION;
    buf[1] = stat;
    return writen(fd,buf,2);
}

int recv_request(int fd, request *r)
{
    int n;
    uint8_t buf[256] = {0}; // max domain length: 253
    if ((n = readmax(fd,buf,256)) < 6 || buf[0] != VERSION || buf[2] != 0)
        return -1;
    r-> cmd = buf[1];
    r-> atyp = buf[3];
    r-> port = buf[n-2] << 8|buf[n-1];
    switch (buf[3])
    {
        case ATYP_IPV4:
            sprintf(r-> addr,"%d.%d.%d.%d",buf[4],buf[5],buf[6],buf[7]);
            break;
        case ATYP_IPV6:
            sprintf(r-> addr,"%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
            buf[4],buf[5],buf[6],buf[7],buf[8],buf[9],buf[10],buf[11],
            buf[12],buf[13],buf[14],buf[15],buf[16],buf[17],buf[18],buf[19]);
            break;
        case ATYP_DOMAIN:
        {
            int len = buf[4];
            memcpy(r-> addr,buf,len);
            r-> addr[len] = 0;
            break;
        }
        default:
            return -1;
    }
    return 0;
}

int send_response(int fd, const uint8_t resp_code)
{
    uint8_t buf[10] = {0};
    buf[0] = VERSION;
    buf[1] = resp_code;
    buf[2] = RSV;
    buf[3] = ATYP_IPV4;
    return writen(fd,buf,10); 
}

void *proxy(void *proxy_data)
{
    proxy_d *pd = (proxy_d *)proxy_data;
    int srcfd = pd-> srcfd;
    int dstfd = pd-> dstfd;
    int n;
    uint8_t *buf = (uint8_t *)malloc(BUFFERSIZE);
    memset(buf,0,BUFFERSIZE);
    for (;;)
    {
        if ((n = readmax(srcfd,buf,BUFFERSIZE)) <= 0)
            break;
        if (writen(dstfd,buf,n) < 0)
            break;
    }
    close(srcfd);
    free(buf); buf = NULL;
    pthread_exit(NULL);
}

// handlers
int handle_auth(int fd, const s5_auth *auth)
{
    auth_method method;
    if (recv_auth_method(fd,&method) < 0)
        return -1;
    int nmethods = method.nmethods;
    int support_basic_auth = 0;
    int support_noauth = 0;
    while (nmethods--)
    {
        if (method.methods[nmethods] == METHOD_NOAUTH) support_noauth = 1;
        if (method.methods[nmethods] == METHOD_USERNAME_PASSWORD) support_basic_auth = 1;
    }
    if ((auth != NULL && !support_basic_auth) || (auth == NULL && !support_noauth))
        return -1;
    if (auth == NULL)
        return send_auth_method(fd,METHOD_NOAUTH);
    if (send_auth_method(fd,METHOD_USERNAME_PASSWORD) < 0)
        return -1;
    char username[MAX_ARG_LEN] = {0};
    char password[MAX_ARG_LEN] = {0};
    s5_auth client = {username,password};
    if (recv_auth(fd,&client) < 0)
        return -1;
    if (strcmp(client.username,auth-> username) || strcmp(client.password,auth-> password))
    {
        send_auth_stat(fd,AUTH_FAILED);
        return -1;
    }
    return send_auth_method(fd,AUTH_SUCCEED);
}

int handle_request(int fd, request *r)
{
    if (recv_request(fd,r) < 0 || r-> cmd != CMD_CONNECT)
    {
        send_response(fd,REP_GENERAL_FAILED);
        return -1;
    }
    return send_response(fd,REP_SUCCEEDED);
}

void *handle(void *handle_data)
{
    handle_d *hd = (handle_d *)handle_data;
    int connfd = hd-> connfd;
    s5_auth *auth = hd-> auth;

    // select auth method
    if (handle_auth(connfd,auth) < 0)
    {
        close(connfd);
        return NULL;
    }
    // handle request
    request r;
    char *addr = (char *)malloc(256);
    memset(addr,0,256);
    r.addr = addr;
    if (handle_request(connfd, &r) < 0)
    {
        free(addr);
        close(connfd);
        return NULL;
    }
    int dstfd;
    switch (r.atyp)
    {
        case ATYP_IPV4:
            dstfd = dial(r.addr,r.port);
            break;
        case ATYP_IPV6:
            dstfd = dial6(r.addr,r.port);
            break;
        default:
            break;
    }
    free(addr); addr = NULL;
    if (dstfd < 0)
    {
        close(connfd);
        return NULL;
    }
    pthread_t fwd, rev;
    proxy_d fwd_pd, rev_pd;
    fwd_pd.srcfd = rev_pd.dstfd = connfd;
    fwd_pd.dstfd = rev_pd.srcfd = dstfd;
    pthread_create(&fwd,NULL,proxy,&fwd_pd);
    pthread_create(&rev,NULL,proxy,&rev_pd);
    pthread_join(fwd,NULL);
    pthread_join(rev,NULL);
}

void *socks5_serve(void *vconfig)
{
    s5_config *config = (s5_config *)vconfig;
    int listenfd = lstn(config-> addr,config-> port);
    if (listenfd < 0)
        return NULL;
    for (;;)
    {
        int connfd = accept(listenfd,NULL,NULL);
        if (connfd < 0) continue;
        pthread_t handler;
        handle_d data;
        data.connfd = connfd;
        data.auth = config-> auth;
        pthread_create(&handler,NULL,handle,&data);
        pthread_detach(handler);
    }
    close(listenfd);
}