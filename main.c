#include "socks5.h"


int main(int argc, char **argv)
{
    char addr[MAX_ARG_LEN] = {0};
    char username[MAX_ARG_LEN] = {0};
    char password[MAX_ARG_LEN] = {0};
    char addr_str[MAX_ARG_LEN*2 + 1] = {0};
    char auth_str[MAX_ARG_LEN*2 + 1] = {0};
    //
    cli_args args = {addr_str, auth_str};
    get_args(argc, argv, &args);
    //
    s5_auth auth = {username, password};
    s5_config config;
    config.auth = &auth;
    config.addr = addr;
    load_config(&args, &config);
    //
    printf("start to serve on %s:%d\n",config.addr,config.port);
    socks5_serve(&config);
    return 0;
}