#include "elink_public.h"

static int g_n_status = ELINK_INIT;

const char * g_base64_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


int set_status(ELINK_STATUS_E_T e_status)
{
	g_n_status = e_status;

	return 1;
}

int get_status()
{
	return g_n_status;
}

/*
*   利用json 的key  返回 string 类型的value
*/
int get_json_value(char *out_buff ,cJSON * json_root ,char *json_key)
{
	strcpy(out_buff,(cJSON_GetObjectItem(json_root, json_key)->valuestring) ) ;
	return 0;
}

/*
*   利用json 的key  返回 int  类型的value
*/
int get_json_value_num( cJSON * json_root ,char *json_key)
{
	return (cJSON_GetObjectItem(json_root, json_key)->valueint);
}


int encrypt(unsigned char *sz_in_buff, int sz_in_len, unsigned char *key,unsigned char *iv, unsigned char *sz_out_buff)
{
	EVP_CIPHER_CTX ctx;
	
  	int len=0,isSuccess = 0;
	unsigned char in[BLOCK_SIZE];  
	int outl = 0;   
    	int outl_total = 0; 
	
  	EVP_CIPHER_CTX_init(&ctx);  
   
 	EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv);

	while(sz_in_len >=BLOCK_SIZE)
	{
		memcpy(in, sz_in_buff, BLOCK_SIZE);  
        	sz_in_len -= BLOCK_SIZE;  
        	sz_in_buff += BLOCK_SIZE;  
		isSuccess = EVP_EncryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);  
        	if(!isSuccess)  
        	{  
            		printf("EVP_EncryptUpdate() failed");  
            		EVP_CIPHER_CTX_cleanup(&ctx);  
            		return 0;  
        	}  
        	outl_total += outl;  
	}
	
	 if(sz_in_len > 0)  
    	{  
        	memcpy(in, sz_in_buff, sz_in_len); 
        	isSuccess = EVP_EncryptUpdate(&ctx,sz_out_buff + outl_total, &outl, in, sz_in_len);  
        	outl_total += outl;  
	
		isSuccess = EVP_EncryptFinal_ex(&ctx,sz_out_buff + outl_total,&outl);  
    		if(!isSuccess)  
    		{  
        		printf("EVP_EncryptFinal_ex() failed");  
        		EVP_CIPHER_CTX_cleanup(&ctx);  
        		return 0;  
    		}  
    		outl_total += outl;  
    	}     
        
    	EVP_CIPHER_CTX_cleanup(&ctx); 
  	return outl_total;
}


int decrypt(unsigned char *sz_in_buff, int sz_in_length, unsigned char *key,unsigned char *iv, unsigned char *sz_out_buff)
{
	unsigned char in[BLOCK_SIZE];  
    	int outl = 0;  
    	int outl_total = 0;  
    	int isSuccess;  
  
    	EVP_CIPHER_CTX ctx;   	

	//初始化ctx，加密算法初始化  
    	EVP_CIPHER_CTX_init(&ctx);  
    	isSuccess = EVP_DecryptInit_ex(&ctx,EVP_aes_128_cbc(),NULL,key,iv);  
   	if(!isSuccess)  
    	{  
        	printf("EVP_DecryptInit_ex() failed");  
        	EVP_CIPHER_CTX_cleanup(&ctx);  
        	return 0;  
    	}  

	//解密数据  
    	while(sz_in_length >BLOCK_SIZE)  
    	{  
        	memcpy(in, sz_in_buff, BLOCK_SIZE);  
        	sz_in_length -= BLOCK_SIZE;  
        	sz_in_buff += BLOCK_SIZE;  
  
        	isSuccess = EVP_DecryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, BLOCK_SIZE);  
        	if(!isSuccess)  
        	{  
            		printf("EVP_DecryptUpdate() failed");  
            		EVP_CIPHER_CTX_cleanup(&ctx);  
            		return 0;  
        	}  
        	outl_total += outl;  
    	}

	
	if(sz_in_length > 0)  
    	{  
        	memcpy(in, sz_in_buff, sz_in_length);  
        	isSuccess = EVP_DecryptUpdate(&ctx, sz_out_buff + outl_total, &outl, in, sz_in_length);  
        	outl_total += outl;  
    	} 
    	
	/*解密数据块不为16整数倍时执行 */
	 if(sz_in_length % BLOCK_SIZE != 0)  
    	{  
        	isSuccess = EVP_DecryptFinal_ex(&ctx, sz_out_buff + outl_total, &outl);  
        	if(!isSuccess)  
        	{  
           	 	printf("EVP_DecryptFinal_ex() failed\n");  
            		EVP_CIPHER_CTX_cleanup(&ctx);  
            		return 0;  
        	}  
        	outl_total += outl;  
    	}  
      
    	EVP_CIPHER_CTX_cleanup(&ctx);  
    	return outl_total;  
}


int encrypted_json_packet(char *json_buff , char *encrypt_out_buff)
{
	unsigned char ivec[16] = {0};
	unsigned char sz_sharekey[16]={0};
	int len=0;
	char encrypt_in_buff[BUF_LEN]={0};
	
	get_sharekey(sz_sharekey ,16); 
	//一定要把json 字符串结束符也加密,不然解密出来不足16字节的填充会乱码
	len =encrypt(json_buff,strlen(json_buff)+1, sz_sharekey, ivec, encrypt_out_buff);
	return len;
}

/*
*     description :  利用AES_CBC 解密出json数据包 
*/

int decode_json_packet(char *json_buff , char *decrypt_out_buf,int length)
{
	unsigned char ivec[16] = {0};
	unsigned char sz_sharekey[16]={0};
	get_sharekey(sz_sharekey ,16);
	
	int len = 0;
	len=decrypt(json_buff , length, sz_sharekey, ivec,decrypt_out_buf);
	return 1;	
}

/*
*	description : 心跳包文件同步
*/
int keepaliveCheckRunning(void)
{
	int n_ret = 0;	
	if(access(KEEPALIVE_PID_FILE, F_OK ) >= 0) //file exist
	{
		n_ret = 1;
	}
	else
	{
		n_ret = 0;
	}	
	return n_ret;
}

/*
*   参数 days 格式  1-7   ，1开始时间7结束时间
*/
int get_wifischedule_day(char *days)
{
	int  wifischedule_day = 0;
	int i = 0;
	int begin=0,end=0;
	char *tok=NULL;

	if(3 != strlen(days))
		return 127;
	
	tok=strtok(days,"-");
	begin = atoi(tok)-1;
	
	tok = strtok(NULL,"-");
	end =  atoi(tok)-1;

	for(i=begin;i<= end;i++)
	{
		wifischedule_day |= (1 << i);	
	}
	return wifischedule_day;
}

/*
*  去掉 mac 中间的: 
*/
void get_mac_address(char *mac)
{
	char mac_back[18];
	int i = 0 ,j = 0;
	memset(mac_back, 0,sizeof(mac_back));
	strcpy(mac_back,mac);
	memset(mac,0,sizeof(mac));
	for(i = 0;i<=strlen(mac_back); ++i)
	{
		if(mac_back[i] != ':')
		{
			mac[j] = mac_back[i] ;
			j++;
		}
	}
	return ;	
}

/*
*  
*/
void  get_wan_mac_address(char *mac)
{
	char wan_fac_mac[18] ={0};
	int i = 0;
	int j = 0;
	//getNvramValue("wan_fac_mac_addr",wan_fac_mac);
	getNvramValue("lan_mac_addr",wan_fac_mac);
	for(i = 0;i<=strlen(wan_fac_mac); ++i)
	{
		if(wan_fac_mac[i] != ':')
		{
			mac[j] = 	wan_fac_mac[i] ;
			j++;
		}
	}
	return ;
}

/*
*  字符串 小写转大写
*/
void   low_to_upper(char *str)
{
	int i = 0;
	for(i = 0; i < strlen(str); i++)  
	{
        	str[i] = toupper(str[i]);
	}	
    	return 0;  
}

/*
*  字符串大写转小写
*/
void  upper_to_low(char *str)
{
	int i = 0;
	for(i = 0; i < strlen(str); i++)
	{
        	str[i] = tolower(str[i]);
	}
    	return 0;  
}

/*
*    日期转换成 1-7 格式
*/
void date_change(char *WiFitimer_weekday)
{
	int n_days_tmp = 0;
	int n_wdays[7] = {0};
	int i = 0,day_begin =-1 ,day_end= -1;
	
	getNvramValue("elink_wifi_schedule_days",WiFitimer_weekday);//5g 2.4g通用
	n_days_tmp = atoi(WiFitimer_weekday);
	n_wdays[0] = (n_days_tmp>>0) & 1;
	n_wdays[1] = (n_days_tmp>>1) & 1;
	n_wdays[2] = (n_days_tmp>>2) & 1;
	n_wdays[3] = (n_days_tmp>>3) & 1;
	n_wdays[4] = (n_days_tmp>>4) & 1;
	n_wdays[5] = (n_days_tmp>>5) & 1;
	n_wdays[6] = (n_days_tmp>>6) & 1;

	for(i=0;i<7;i++)
	{	
		if(n_wdays[i] == 1)
		{
			day_begin = i;
			break;
		}
	}
	for(i =6; i>=0 ; i--)
	{
		if(n_wdays[i] == 1)
		{
			day_end = i;
			break;
		}
	}
		
	memset(WiFitimer_weekday, 0, sizeof(WiFitimer_weekday));
	//错误返回1-7
	if(day_begin == -1 ||day_end == -1 )
	{
			
		strcpy(WiFitimer_weekday,"1-7");
	}
	else
	{
		sprintf(WiFitimer_weekday,"%d-%d",day_begin+1,day_end+1);	
	}
}


