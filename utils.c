#include "utils.h"

int str_split(const char *str, const char sep, char strs[][MAX_ARG_LEN])
{
	char buf[MAX_ARG_LEN*2] = {0};
	strcpy(buf,str);
	int len = strlen(buf);
	int i, count, last = 0;
	for (i=count=0; i<len; i++)
	{
		if (*(buf+i) == sep)
		{
			*(buf+i) = 0;
			strcpy(strs[count], buf+last);
			count++;
			last = i+1;
		}
	}
	strcpy(strs[count], buf+last);
	return count+1;
}

void get_args(int argc, char **argv, cli_args *args)
{
    int flag = 0;
	char *ptr = NULL;
    if (argc < 1)
    {
        printf("error");
        exit(1);
    }
    while (--argc)
    {
        ptr = *++argv;
		if (*ptr == '-' && *++ptr == '-')
		{
			ptr++;
			if(strcmp(ptr,"host") == 0)
			{
				flag = FLAG_S5ADDR;
				continue;
			}
			if(strcmp(ptr,"auth") == 0)
			{
				flag = FLAG_S5AUTH;
				continue;
			}
		}
		switch (flag)
		{
			case 0:
				break;
			case 1:
				flag = 0;
				strcpy(args-> addr_str,ptr);
				break;
			case 2:
				flag = 0;
				strcpy(args-> auth_str,ptr);
				break;
		}
    }
	if (strlen(args-> addr_str) == 0)
	{
		printf("invalid addr\n");
		exit(0);
	}
	if (strlen(args-> auth_str) == 0)
		args-> auth_str = NULL;
}

void load_config(const cli_args *args, s5_config *config)
{
    char addr_strs[2][MAX_ARG_LEN] = {0};
    str_split(args-> addr_str,':',addr_strs);
    config-> port = atoi(addr_strs[1]);
    strcpy(config-> addr,addr_strs[0]);

	if (args-> auth_str == NULL)
	{
		config-> auth = NULL;
		return;
	}
	char auth_strs[2][MAX_ARG_LEN] = {0};
	str_split(args-> auth_str,':',auth_strs);
    strcpy(config-> auth-> username,auth_strs[0]);
    strcpy(config-> auth-> password,auth_strs[1]);
}
