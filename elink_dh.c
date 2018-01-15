
#include "elink_public.h"

/*
ʹ�ò���:
1��gen_DH_key ����client DH˽Կ����Կ
2��set_DH_server_pubkey ���� server��pub_key
3��get_client_sharekey	(1)����compute_client_sharekey���ɹ�����Կ;(2)���������Ĺ�����Կ
*/

static DH	*g_DH_client = NULL;
static DH	*g_DH_server = NULL;
static int n_server_pubkey_init = 0;
static char g_sz_sharekey[16] = {0};

static int free_DH_struct()
{
	if(g_DH_client != NULL)
	{
		DH_free(g_DH_client);

		g_DH_client = NULL;
	}

	if(g_DH_server != NULL)
	{
		DH_free(g_DH_server);

		g_DH_server = NULL;
	}

	n_server_pubkey_init = 0;

	return 0;
}

static int new_DH_struct()
{
	if((g_DH_client != NULL) || (g_DH_server != NULL))
	{
		free_DH_struct();
	}
	
	g_DH_client=DH_new();

	g_DH_server=DH_new();

	return 0;
}

int compute_client_sharekey()
{
	int n_len = 0;	
	char sz_sharekey[16] = {0};

	if(0 == n_server_pubkey_init)
	{
		printf("compute_client_sharekey fail\n");
		
		return -1;
	}
	
	n_len = DH_compute_key(sz_sharekey, g_DH_server->pub_key, g_DH_client);
	int i = 0;
	printf("=====> sharekey:=====");
	for(i = 0; i < n_len; i++)
	{
		if(0 == i%8)
		{
			printf("\n");
		}
		printf("%02x:",sz_sharekey[i]&0xFF);
		g_sz_sharekey[i] = sz_sharekey[i]&0xFF ;
	}
	printf("\n ====>sharekey sucess=====\n");
	
	return 0;
}


int get_sharekey(char *buff ,int length)
{
	int i;
	for(i=0;i<length;++i)
	{
		buff[i] = g_sz_sharekey[i];
	}
	return 1;
}


DH  *get_DH_client()
{
	return g_DH_client;	
}

int gen_DH_key()
{
	int	n_ret, n_size, n_len;
	int	i;

	int itmp = 0, len = 0;

	/* ����DH���ݽṹ */
	new_DH_struct();

	/* ����g_DH_client����Կ����������Կ�����ǿ��Թ����� */
	n_ret = DH_generate_parameters_ex(g_DH_client, KEY_BITS, DH_GENERATOR_2, NULL);

	if(n_ret != 1)
	{
		printf("DH_generate_parameters_ex err!\n");

		return -1;
	}

	/* �����Կ���� */
	n_ret=DH_check(g_DH_client, &i);

	if(n_ret != 1)
	{
		return -1;
	}

	/* ���ɹ�˽Կ */
	n_ret = DH_generate_key(g_DH_client);

	if(n_ret != 1)
	{
		printf("DH_generate_key err!\n");

		return -1;
	}

	/* ��鹫Կ */
	n_ret = DH_check_pub_key(g_DH_client, g_DH_client->pub_key, &i);

	if(n_ret != 1)
	{
		return -1;
	}
	return 0;
}

int set_DH_server_pubkey(BIGNUM *p_key)
{
	if(p_key != NULL)
	{
		g_DH_server->pub_key = BN_dup(p_key);
		if( NULL != g_DH_server->pub_key)
		{
			TRACE_DEBUG("==>client get service p_key success\n");	
		}
		
		n_server_pubkey_init = 1;
	}
	return 0;
}

