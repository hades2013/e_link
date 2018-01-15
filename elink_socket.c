#include "elink_public.h"

int create_socket(unsigned long ip, int port)
{
	struct ifreq interface;
	int fd;
	struct sockaddr_in addr;
	int n = 1;
	
	if((fd = socket(AF_INET, SOCK_STREAM , IPPROTO_TCP)) == -1)	
	{	
		printf("socket errpor\n");
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;
	
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) 
	{
		close(fd);
		return -1;
	}
 
	if(-1 == connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) )
	{
		close(fd);
		return -1;
	}
	
	return fd;
}

