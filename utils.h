#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_S5ADDR 1
#define FLAG_S5AUTH 2
#define MAX_ARG_LEN 16

typedef struct cli_args
{
    char* addr_str;
    char* auth_str;
} cli_args;

typedef struct s5_auth
{
    char *username;
    char *password;
} s5_auth;

typedef struct s5_config
{
    int port;
    char *addr;
    s5_auth *auth;
} s5_config;

int str_split(const char *str, const char sep, char strs[][MAX_ARG_LEN]);
void get_args(int agrc, char **agrv, cli_args *args);
void load_config(const cli_args *args, s5_config *config);