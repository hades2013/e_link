#include "elink_public.h"
#include "cJSON.h"
#include "arpping.h"

static int  sequencenum = 0;


#define	SYS_ARP_FILE	"/proc/net/arp"
#define   STA_SEC_TYPE_NUM  3

#define MAX_NUMBER_OF_MAC				64
char g_wl_cnn_mac_lists_24G[MAX_NUMBER_OF_MAC][18] = {0};
char g_wl_cnn_mac_lists_5G[MAX_NUMBER_OF_MAC][18] = {0};
static pthread_t tid_keepalive;

void (*f_getNvramValue)(const char *name, const char *value);
void (*f_setNvramValue)(const char *name, const char *value);
void (*f_commitNvram)(void);
void (*STFs)(int index, char *flash_key, char *value);
void (*LFF)(char *result, char *flash_key, int index);


typedef struct 
{
	uint32_t server_message;
	char server_message_type[32];
}ST_SERVER_MESSAGE;

static ST_SERVER_MESSAGE packet_type_str[]=
{
	{ELINK_TYPE_KEYNGREQ_ACK,"keyngack"},
	{ELINK_TYPE_RCV_SERVER_DH,"dh"},
	{ELINK_TYPE_DEV_REG_ACK,"dev_reg"},
	{ELINK_TYPE_RCV_GET_STATUS,"get_status"},
};


pthread_t get_keepalive_pid()
{
	return tid_keepalive ;
}

void set_keepalive_pid(int pid)
{
	tid_keepalive = pid ;	
	return ;
}


/*
*   构造发送数据数据send_buff
*/
int makeup_send_buff(char *send_buff,char *packet,int length)
{	
	//0x3f721fb5
	ST_ELINK_MESSAGE client_message;
	int send_buff_length= 0;
	client_message.head_flag = htonl(ELINK_HEADER_FLAG);
	client_message.n_date_len =htonl(length);  
	
	//包长度转换成大端,收到包要用ntohl 转换回来
	memcpy(send_buff,&client_message,sizeof(ST_ELINK_MESSAGE));
	memcpy(send_buff+sizeof(ST_ELINK_MESSAGE),packet,length);
	
	send_buff_length = length + sizeof(ST_ELINK_MESSAGE) ;
	return send_buff_length ;
}


int get_packet(int fd)
{
	int bytes;
	int pack_length = 0;
	char read_buff[BUF_LEN]={0};
	ST_ELINK_MESSAGE buff_head ;
	memset(&buff_head, 0, sizeof(ST_ELINK_MESSAGE));
	
	memset(read_buff, 0, BUF_LEN);

	bytes = read(fd, read_buff,BUF_LEN);
	
	if( bytes ==  0) 
	{
		doSystem("killall -SIGUSR1 MTC_e_link"); 
		return -1;
	}
	else if(bytes < 8)  
	{
		return -1;
	}
	else
	{
		memcpy(&buff_head, read_buff, sizeof(ST_ELINK_MESSAGE));
	 	//数据包不全,丢弃不处理
		if(ntohl(buff_head.n_date_len) != bytes -sizeof(ST_ELINK_MESSAGE))   
		{
			return -1;
		}
		else if(ntohl(buff_head.head_flag) != ELINK_HEADER_FLAG)
		{
			return -1;
		}
		else
		{
			pack_length = bytes - sizeof(ST_ELINK_MESSAGE) ;
			dealwith_rcv_packet(read_buff+sizeof(ST_ELINK_MESSAGE), fd,pack_length);		
		}
	}
	return bytes;
}


int get_packet_type(char*packet,int length)
{
	int n_type,n_status;
	cJSON *root;
	char reply_type[32] = {0};
	char server_reply_buff[1500] = {0};
	int i=0 ;
	n_status = get_status();
	
	//dh 协商未完成之前不需要对数据包进行 aes_cdc解密
	if(n_status == ELINK_WAITTING_KEYNGREQ_ACK || n_status == ELINK_WAITTING_DH_PUBKEY_REPLY)
	{
		root = cJSON_Parse(packet);
		if(!root)
		{
			TRACE_DEBUG("=>Parse json faild !\n");     			
			return -1;
		}
		get_json_value(reply_type,root,"type");
	}
	else
	{
		decode_json_packet(packet , server_reply_buff,length);

		root = cJSON_Parse(server_reply_buff);
		if(!root)
		{
			TRACE_DEBUG("=>Parse json faild !\n");     			
			return -1;
		}
		get_json_value(reply_type,root,"type");
		memset(packet,0,strlen(packet)+1);
		strcpy(packet,server_reply_buff);
	}
	
	if(0 == strcmp(reply_type,"ack"))
	{
		if(n_status == ELINK_WAITTING_DEV_REGISTER_ACK)
		{
			n_type= ELINK_TYPE_DEV_REG_ACK ; 		
		}
		else if(n_status ==  ELINK_WAITTING_DEV_REPORT_ACK)
		{
			n_type= ELINK_TYPE_DEV_REPORT_ACK ; 		
		}
		else
		{
			//心跳 ack 
			n_type = 	ELINK_TYPE_KEEPALIVE_ACK ;
		}
	}
	else if(0 == strcmp(reply_type,"cfg"))
	{
		//cfg 如果是cfg 需要找到具体哪个cfg 配置
		n_type=parse_cfg_type(packet);	
	}
	else
	{
		for(i = 0;i < sizeof(packet_type_str)/sizeof(ST_SERVER_MESSAGE);++i)
		{
			if(!strcmp(reply_type,packet_type_str[i].server_message_type))	
			{
				n_type = 	packet_type_str[i].server_message ;
			}
		}
	}
	
	if(NULL != root)
		cJSON_Delete(root);
	return n_type;
}


int generate_the_key(char *packet)
{
	
	cJSON *root = cJSON_Parse(packet);
	if(NULL == root)
		return 0;
	
	DH *g_DH_client = get_DH_client();
	int n_ret =0;
	n_ret=BN_num_bytes(g_DH_client->pub_key);

	char  service_public_key[128] = {0};
	char  service_public_key_decode[128]={0};
	
	cJSON *data_root = cJSON_GetObjectItem(root,"data") ;
	get_json_value(service_public_key ,data_root ,"dh_key");
	base64_decode(service_public_key ,128,service_public_key_decode);
	
	BIGNUM *new_pubkey;
	new_pubkey = BN_new();
	BN_bin2bn(service_public_key_decode,n_ret,new_pubkey);
	
	char *p =NULL;
	p = BN_bn2dec(new_pubkey);
	OPENSSL_free(p);

	set_DH_server_pubkey(new_pubkey);
	//生成密钥
	compute_client_sharekey();

	if(NULL != root)
		cJSON_Delete(root);
	
	if(new_pubkey != NULL)
		BN_free(new_pubkey);	

	set_status(ELINK_RCV_DH_PUBKEY_REPLY);
	return 1;
}

int dealwith_rcv_packet(char *packet, int fd,int length)
{
	int n_type = -1;
	n_type = get_packet_type(packet,length);
	if(n_type == -1)
	{
		//json 解析失败重新初始化
		doSystem("killall -SIGUSR1 MTC_e_link"); 	
	}
	TRACE_DEBUG("=>elink n_type[%d]\n",n_type);
	switch (n_type) 
	{
		case ELINK_TYPE_KEYNGREQ_ACK:	/*类型为keyngreq ack*/
			send_client_dh_pubkey(fd);
			break;
			
		case ELINK_TYPE_RCV_SERVER_DH:	/*类型为dh reply*/
			generate_the_key(packet);           //生成密钥
			send_dev_register_req(fd);
			break;

		case ELINK_TYPE_DEV_REG_ACK:	/*类型为dev_reg ack*/
			set_status(ELINK_RCV_DEV_REGISTER_ACK);
			start_keepalive_thread(fd);//创建心跳线程
			break;
		case ELINK_TYPE_RCV_CONFIG_CFG:	/*类型为cfg*/
			parse_server_cfg_info(packet, fd);  
			break;
		case ELINK_TYPE_RCV_SET_CFG: /* 类型为cfg   表9*/
			parse_server_set_cfg(packet, fd);  
			break;
		case ELINK_TYPE_RCV_GET_STATUS:	/*类型为get status*/
			parse_server_get_status(packet,fd);
			break;

		case ELINK_TYPE_RCV_WPS_CFG:  /*类型为cfg ,网关wps 打开或者关闭*/ 
			parse_server_wps_cfg(packet, fd);
			break;

		case ELINK_TYPE_RCV_UPGRADE_CFG:  /*类型为cfg ,url 升级*/ 
			patse_server_upgrade_cfg(packet, fd);
			break;
			
		case ELINK_TYPE_DEV_REPORT_ACK:	/*类型为cfg ,主动上报下挂信息*/
			set_status(ELINK_RCV_DEV_REPORT_ACK);
			break;

		case ELINK_TYPE_KEEPALIVE_ACK:	/*类型为keepalive*/
			keepalive_send_message();		/*  通知心跳线程发送心跳包 */
			break;		
		default:
			break;
	}
}

int patse_server_upgrade_cfg(char *packet, int fd)
{
	TRACE_DEBUG("==>patse_server_upgrade_cfg \n");
	int server_sequence = 0;
	char upgrade_url[64] ={0};
	char isreboot[8] ={0};
	cJSON *root =cJSON_Parse(packet);

	server_sequence =get_json_value_num(root,"sequence"); 
	cJSON *set_root = cJSON_GetObjectItem(root,"set") ;
	cJSON *upgrade_root = cJSON_GetObjectItem(root,"set") ;
	get_json_value(upgrade_url,upgrade_root,"downurl");
	get_json_value(isreboot,upgrade_root,"isreboot");

	reply_ack_to_server(fd,server_sequence);
	
	if(root)
		cJSON_Delete(root);
	return -1;
}

int parse_server_wps_cfg(char *packet, int fd)
{
	TRACE_DEBUG("==>parse_server_wps_cfg \n");
	char wpsswitch[32] ={0};
	int server_sequence = 0;
	char elink_mode[8]={0};
	int mbssid = 0;
	
	cJSON *root =cJSON_Parse(packet);
	if(NULL == root)
		return 0;
	
	server_sequence =get_json_value_num(root,"sequence"); 
	
	//解析 set->wpsswitch 参数
	cJSON *set_root = cJSON_GetObjectItem(root,"set") ;
	cJSON *wpsswitch_root = cJSON_GetObjectItem(set_root,"wpsswitch");

	get_json_value(wpsswitch ,wpsswitch_root ,"status");

	//默认开启2.4G  wps
	if(0 == strcasecmp(wpsswitch,"ON"))
	{
		setNvramValue("wps_cur_band",BAND_24G);
		sendMessage(WIRELESS_PBC_WPS,"ra0");
		
	}
	else if(0 == strcasecmp(wpsswitch,"OFF"))
	{
		STFs_24G(mbssid,"AuthMode", "OPEN");
		STFs_24G(mbssid,"EncrypType", "NONE");
		STFs_24G(mbssid,"WscConfStatus","0");
		commitNvram();
		sendMessage(WIRELESS_CFG_CHANGED,NULL);
	}

	reply_ack_to_server(fd,server_sequence);
	
	if(root)
		cJSON_Delete(root);
	
	return 1;
}

/*
*   收到keelalive 回复
*/
int keepalive_send_message()
{
	if(1 == keepaliveCheckRunning() )
	{
		unlink(KEEPALIVE_PID_FILE);			
		return 1;	
	}
	return 0;
}


int send_keyngreq(int fd)
{
	TRACE_DEBUG("==>send_keyngreq \n");
	char  send_buff[BUF_LEN] = {0};
	char mac[18] = {0};
	int datelength = 0;
	int length= 0;

	get_wan_mac_address(mac);
	//生成最外层 root
	cJSON *root =cJSON_CreateObject();
	//添加 type , sequence ,mac 
	cJSON_AddStringToObject(root, "type", "keyngreq");
	cJSON_AddNumberToObject(root, "sequence", ++sequencenum);
	cJSON_AddStringToObject(root, "mac", mac);
	cJSON_AddStringToObject(root, "version", "V2016.1.0");
	
	cJSON *keymodelist_array = NULL;
	cJSON *keymodelist_array_root = cJSON_CreateObject();
	cJSON_AddStringToObject(keymodelist_array_root, "keymode", "dh");
	cJSON_AddItemToObject(root, "keymodelist", keymodelist_array = cJSON_CreateArray());
	cJSON_AddItemToArray(keymodelist_array, keymodelist_array_root);
	
	char * pJson = cJSON_Print(root);
	length= strlen(pJson);
	
	datelength = makeup_send_buff(send_buff,pJson,length);
	
	if(NULL != root)
	{	
		cJSON_Delete(root);
		free(pJson);
	}

	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		printf("send error\n"); 	 	
		return -1;    	
	}
	
	set_status(ELINK_WAITTING_KEYNGREQ_ACK);
	return 0;
}

int send_client_dh_pubkey(int fd)
{
	char dh_client_p[128] = {0},dh_client_g[128] = {0},dh_client_key[128] = {0};
	char  send_buff[BUF_LEN] = {0};
	char sz_encode_dh_p[128] = {0}, sz_encode_dh_g[128] = {0},sz_encode_dh_key[128] = {0};
	int datelength = 0;
	int length = 0;
	char mac[18]={0};

	DH *g_DH_client = get_DH_client();
	int n_ret =0;
	
	BN_bn2bin(g_DH_client->g,dh_client_g);
	n_ret=BN_num_bytes(g_DH_client->g);
	base64_encode(dh_client_g, n_ret,sz_encode_dh_g);

	BN_bn2bin(g_DH_client->p,dh_client_p);
	n_ret=BN_num_bytes(g_DH_client->p);
	base64_encode(dh_client_p, n_ret,sz_encode_dh_p);
	
	BN_bn2bin(g_DH_client->pub_key,dh_client_key);
	n_ret=BN_num_bytes(g_DH_client->pub_key);
	base64_encode(dh_client_key, n_ret,sz_encode_dh_key);

	
	get_wan_mac_address(mac);

	cJSON *root = cJSON_CreateObject();
	cJSON *data_root = cJSON_CreateObject();
	if(NULL ==root ||NULL == data_root )
	{
		return -1;
	}
	
	cJSON_AddStringToObject(root, "type", "dh");
	cJSON_AddNumberToObject(root, "sequence", ++sequencenum);
	cJSON_AddStringToObject(root, "mac", mac);

	//添加 data 
	cJSON_AddStringToObject(data_root, "dh_key", sz_encode_dh_key);
	cJSON_AddStringToObject(data_root, "dh_p", sz_encode_dh_p);
	cJSON_AddStringToObject(data_root, "dh_g", sz_encode_dh_g);
	//把data添加到最外层 root
	cJSON_AddItemToObject(root, "data", data_root);

	char * pJson = cJSON_Print(root);
	length = strlen(pJson);

	datelength=makeup_send_buff(send_buff,pJson,length);

	if(NULL != root)
	{	
		cJSON_Delete(root);
		free(pJson);
	}
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		printf("send error\n"); 	 	
		return -1;    	
	}
	
	set_status(ELINK_WAITTING_DH_PUBKEY_REPLY);
	return 0;
}

/*
*	description: 设备注册
*
*/
int send_dev_register_req(int fd)
{
	char  sz_encrypt_out_buf[BUF_LEN] = {0};
	char  send_buff[BUF_LEN] = {0};
	int  datelength = 0;
	char mac[18]={0};
	int length =0;

	char soft_ver[64] = {0};
	getSofeVer(soft_ver,sizeof(soft_ver));
	
	get_wan_mac_address(mac);
	
	cJSON *root = cJSON_CreateObject();  // 创建根  
	cJSON *data_root = cJSON_CreateObject();
	if(NULL==root || NULL==data_root  )
	{
		return -1;
	}
	
	//添加 type , sequence ,mac 
	cJSON_AddStringToObject(root, "type", "dev_reg");
	cJSON_AddNumberToObject(root, "sequence", ++sequencenum);
	cJSON_AddStringToObject(root, "mac", mac);
	
	//拼data
	cJSON_AddStringToObject(data_root, "vendor", "MTC");
	cJSON_AddStringToObject(data_root, "model", "WR1203_Neutral");
	cJSON_AddStringToObject(data_root, "swversion", soft_ver);
	cJSON_AddStringToObject(data_root, "hdversion", "hadr_v1.0");
	
	cJSON_AddStringToObject(data_root, "url", "http://szmtc.com.cn");
	cJSON_AddStringToObject(data_root, "wireless", "yes");
	
	//把 data 加入到 root
	cJSON_AddItemToObject(root, "data", data_root);
	
	char * pJson = cJSON_Print(root);
	
	//利用 aes_cbc加密数据包 
	length=encrypted_json_packet(pJson,sz_encrypt_out_buf);

	datelength=makeup_send_buff(send_buff,sz_encrypt_out_buf,length);

	if(NULL != root)
	{	
		cJSON_Delete(root);
		free(pJson);
	}
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		TRACE_DEBUG("=>dev_reg send error\n"); 	 	
		return -1;    	
	}
	
	set_status(ELINK_WAITTING_DEV_REGISTER_ACK);
	return 0;
}

/*
*  向服务端回复 ack 
*/

int reply_ack_to_server(int fd,int number)
{
	
	char  sz_encrypt_out_buf[BUF_LEN] = {0};
	char  send_buff[BUF_LEN] = {0};
	int datelength = 0;
	int length = 0;
	char mac[18]={0};

	get_wan_mac_address(mac);
	cJSON *root = cJSON_CreateObject(); 
	//添加 type , sequence ,mac 
	cJSON_AddStringToObject(root, "type", "ack");
	cJSON_AddNumberToObject(root, "sequence", number);
	cJSON_AddStringToObject(root, "mac", mac);

	char * pJson = cJSON_Print(root);
	length=encrypted_json_packet(pJson,sz_encrypt_out_buf);

	if(NULL != root)
	{	
		cJSON_Delete(root);
		free(pJson);
	}

	datelength=makeup_send_buff(send_buff,sz_encrypt_out_buf,length);
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		printf("send error\n"); 	 	
		return -1;    	
	}
	
	return 0;	
}

int send_keepalive(int fd)
{
	char  sz_encrypt_out_buf[BUF_LEN] = {0};
	char  send_buff[BUF_LEN] = {0};
	char mac[18] ={0};
	int datelength = 0;
	int length = 0;

	get_wan_mac_address(mac);
	cJSON *root =cJSON_CreateObject();
	if(NULL == root)
		return 0;
	//添加 type , sequence ,mac 
	cJSON_AddStringToObject(root, "type", "keepalive");
	cJSON_AddNumberToObject(root, "sequence", ++sequencenum);
	cJSON_AddStringToObject(root, "mac", mac);
	char * pJson = cJSON_Print(root);

	length=encrypted_json_packet(pJson,sz_encrypt_out_buf);

	if(NULL != root)
	{
		cJSON_Delete(root);
		free(pJson);	
	}

	datelength=makeup_send_buff(send_buff,sz_encrypt_out_buf,length);
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     			
		return 0;    	
	}
		
	return 1;
}

/*  
*   keepalive   与devreport .
*/
void *keepaliveThread(void *arg)
{
	int fd= *(int *)arg;
	static int time_out_count=0;
	static int dev_check_count =0;
	
	pthread_detach(pthread_self()); 
	
	if(1 == keepaliveCheckRunning())
	{
		unlink(KEEPALIVE_PID_FILE);		
	}
	
	for(;;)
	{
		
		if(1 == keepaliveCheckRunning())
		{
			time_out_count++;	
			
			if(time_out_count >=3){
				//退出线程
				printf("==>keepalive time out");
				goto EXIT_KEEPALIVE;
			}
		}
		else
		{
			time_out_count= 0 ;
			if(send_keepalive(fd))
			{	
				setRuntimeFileTag(KEEPALIVE_PID_FILE);		
			}	
		}

		if(dev_check_count>=50)  /*  设备检测  */
		{
			sleep(2);
			dev_check_count = 0;
			check_dev_report(fd);	
		}
	
		dev_check_count++;
		pthread_testcancel(); 
		sleep(6);	
	}
	
EXIT_KEEPALIVE:
	doSystem("killall -SIGUSR1 MTC_e_link");
	printf("=>time out and exit\n");
	pthread_exit(NULL);	
}

void start_keepalive_thread(int fd)
{
	int ret =0 ;
	
	ret = pthread_create(&tid_keepalive, NULL, keepaliveThread, &fd);

	if(ret < 0)
	{
		TRACE_DEBUG("==>keepaliveThread start error!\n");
	}
}


int reply_client_status(int fd,int number,int type)
{
	char  sz_encrypt_out_buf[BUF_LEN] = {0};
	char  send_buff[BUF_LEN] = {0};
	int datelength = 0,length = 0;
	char mac[18]={0};
	char elink_mode[8]={0},wifi_enable[8]={0};
	int i = 0;
	char sz_wifi_enable[8] ={0},sz_wifi_schedule_en[8] = {0},sz_wifi_schedule_time[8] ={0},sz_wifi_schedule_day[8]={0};
	
	
	ST_SERVER_CFG_SET  wifi_cfg;
	
	get_wan_mac_address(mac);
	
	cJSON *root =cJSON_CreateObject();
	//添加 type , sequence ,mac 
	cJSON_AddStringToObject(root, "type", "status");
	cJSON_AddNumberToObject(root, "sequence", number);
	cJSON_AddStringToObject(root, "mac", mac);

	cJSON *status_root = cJSON_CreateObject();
	//start WiFi
	//WiFi  radio
	if(type & (1<<0))
	{	
		printf("=>recv get wifi\n");
		//创建status 里面的wifi数组
		cJSON *WiFi_array= cJSON_CreateArray();	
		
		//拼接 WiFi_ap_array_root
		cJSON *WiFi_radio = cJSON_CreateObject();
		cJSON *WiFi_ap_array = cJSON_CreateArray();	
		cJSON *WiFi_ap_array_root  = cJSON_CreateObject();  
		cJSON *WiFi_array_root= cJSON_CreateObject();

		/*
		cJSON *WiFi_radio_5g = cJSON_CreateObject();
		cJSON *WiFi_ap_array_5g = cJSON_CreateArray();	
		cJSON *WiFi_ap_array_root_5g  = cJSON_CreateObject();  
		cJSON *WiFi_array_root_5g= cJSON_CreateObject();
		*/
	
		/* 获取wifi basic 参数 */
		for(i = 0;i <1; i++)
		{
			if(0 == i)
			{
				f_getNvramValue = &getNvramValue ;
				LFF = &LFF_24G ;
			}
			else
			{
				f_getNvramValue = &getNvramValue_5G ;	
				LFF = &LFF_5G ;
			}
			
			memset(&wifi_cfg,0,sizeof(ST_SERVER_CFG_SET));
			wifi_cfg.apidx =0;
			f_getNvramValue("Channel",wifi_cfg.channel);
			f_getNvramValue("WirelessEnable",wifi_enable);
			strcpy(wifi_cfg.enable,"yes");
			if(0 == strcmp(wifi_enable,"0"))
			{
				strcpy(wifi_cfg.enable,"no");
			}
			f_getNvramValue("WPAPSK1",wifi_cfg.key);
			f_getNvramValue("SSID1",wifi_cfg.ssid);
			LFF(wifi_cfg.auth, "AuthMode",0);
			LFF(wifi_cfg.encrypt, "EncrypType",0);
			if(0 == strcasecmp(wifi_cfg.encrypt,"TKIPAES"))
			{
				printf("==>TKIPAES\n");
				memset(wifi_cfg.encrypt,0,24);
				strcpy(wifi_cfg.encrypt,"aestkip");
			}
			upper_to_low(wifi_cfg.auth);
			upper_to_low(wifi_cfg.encrypt);
			
			if(0 == i)
			{
				cJSON_AddStringToObject(WiFi_radio, "mode", "2.4G");
				cJSON_AddNumberToObject(WiFi_radio, "channel", atoi(wifi_cfg.channel));
	
				cJSON_AddNumberToObject(WiFi_ap_array_root, "apidx", wifi_cfg.apidx);
				cJSON_AddStringToObject(WiFi_ap_array_root, "enable", wifi_cfg.enable);
				cJSON_AddStringToObject(WiFi_ap_array_root, "ssid", wifi_cfg.ssid);
				cJSON_AddStringToObject(WiFi_ap_array_root, "key", wifi_cfg.key);
				cJSON_AddStringToObject(WiFi_ap_array_root, "auth", wifi_cfg.auth);
				cJSON_AddStringToObject(WiFi_ap_array_root, "encrypt", wifi_cfg.encrypt);
				cJSON_AddItemToArray(WiFi_ap_array ,WiFi_ap_array_root);
				cJSON_AddItemToObject(WiFi_array_root, "radio", WiFi_radio);
				cJSON_AddItemToObject(WiFi_array_root, "ap",WiFi_ap_array );
				cJSON_AddItemToArray(WiFi_array ,WiFi_array_root);
			}
			else
			{
				/*
				cJSON_AddStringToObject(WiFi_radio_5g, "mode", "5G");
				cJSON_AddNumberToObject(WiFi_radio_5g, "channel", atoi(wifi_cfg.channel));
	
				cJSON_AddNumberToObject(WiFi_ap_array_root_5g, "apidx", wifi_cfg.apidx);
				cJSON_AddStringToObject(WiFi_ap_array_root_5g, "enable", wifi_cfg.enable);
				cJSON_AddStringToObject(WiFi_ap_array_root_5g, "ssid", wifi_cfg.ssid);
				cJSON_AddStringToObject(WiFi_ap_array_root_5g, "key", wifi_cfg.key);
				cJSON_AddStringToObject(WiFi_ap_array_root_5g, "auth", wifi_cfg.auth);
				cJSON_AddStringToObject(WiFi_ap_array_root_5g, "encrypt", wifi_cfg.encrypt);
				cJSON_AddItemToArray(WiFi_ap_array_5g ,WiFi_ap_array_root_5g);
				cJSON_AddItemToObject(WiFi_array_root_5g, "radio", WiFi_radio_5g);
				cJSON_AddItemToObject(WiFi_array_root_5g, "ap",WiFi_ap_array_5g );
				cJSON_AddItemToArray(WiFi_array ,WiFi_array_root_5g);
				*/
			}
		}
		cJSON_AddItemToObject(status_root, "wifi", WiFi_array);
	}
	//end WiFi


	//WiFiswitch
	
	if(type & (1<<1))
	{
		getNvramValue("WirelessEnable",sz_wifi_enable);
		cJSON *WiFiswitch_root = cJSON_CreateObject();
		if(0 == strcmp(sz_wifi_enable,"0"))
		{
			//ON OFF 必须大写, 并且 wifiswitch  必须小写
			cJSON_AddStringToObject(WiFiswitch_root, "status", "OFF");
		}
		else
		{
			cJSON_AddStringToObject(WiFiswitch_root, "status", "ON");	
		}
		cJSON_AddItemToObject(status_root, "wifiswitch", WiFiswitch_root);
	}
	
	//ledswitch   没有接口 返回无线led 状态
	
	if(type & (1<<2))
	{
		getNvramValue("WirelessEnable",sz_wifi_enable);
		cJSON *ledswitch_root = cJSON_CreateObject();
		
		//ON OFF 必须大写, 并且 wifiswitch  必须小写
		
		if(0 == strcmp(sz_wifi_enable,"0"))
		{
			cJSON_AddStringToObject(ledswitch_root, "status", "OFF");
		}
		else
		{
			cJSON_AddStringToObject(ledswitch_root, "status", "ON");	
		}
		cJSON_AddItemToObject(status_root, "ledswitch", ledswitch_root);
	}
	
	//wifitimer
	if(type & (1<<3))
	{
		getNvramValue("elink_wifi_schedule_enable",sz_wifi_schedule_en);
		getNvramValue("elink_wifi_schedule_time",sz_wifi_schedule_time);
		
		date_change(sz_wifi_schedule_day);
		printf("==>sz_wifi_schedule_day[%s]\n",sz_wifi_schedule_day);
		printf("==>sz_wifi_schedule_time[%s]\n",sz_wifi_schedule_time);
		
		cJSON *WiFitimer_array =NULL;
		cJSON *WiFitimer_array_root = cJSON_CreateObject();
		cJSON_AddStringToObject(WiFitimer_array_root, "weekday", sz_wifi_schedule_day);
		cJSON_AddStringToObject(WiFitimer_array_root, "time", sz_wifi_schedule_time);
		cJSON_AddStringToObject(WiFitimer_array_root, "enable", sz_wifi_schedule_en);
		cJSON_AddItemToObject(status_root, "wifitimer", WiFitimer_array = cJSON_CreateArray()) ;
		cJSON_AddItemToArray(WiFitimer_array, WiFitimer_array_root) ;
	}

	//把 status_root 添加到最外部root
	cJSON_AddItemToObject(root, "status", status_root);
	
	char * pJson = cJSON_Print(root);

	printf("=>get status=%s\n",pJson);

	
	length=encrypted_json_packet(pJson,sz_encrypt_out_buf);
	
	datelength=makeup_send_buff(send_buff,sz_encrypt_out_buf,length);
	
	if(NULL != root)
	{	
		cJSON_Delete(root);
		free(pJson);
	}
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		printf("send error\n"); 	 	
		return -1;    	
	}
	
	return 1;
}

/*
*      解析表9数据
*/
int parse_server_set_cfg(char *packet, int fd)
{
	int server_sequence = 0; 
	char WiFiswitch_status[8] ={0},ledswitch_status[8] ={0};
	char WiFitimer_weekday[32] ={0},WiFitimer_time[32] ={0},WiFitimer_enable[16] = {0};
	char wireless_enable[8]={0}, led_enable[8]={0};
	int  wifi_schedule_en = 0;
	int wifi_schedule_time = 0;
	int schedule_enable = -1;
	int i = 0;
	int wifi_reboot_flag =0;
	char old_wireless_enable[8]={0};

	getNvramValue("WirelessEnable", old_wireless_enable);
	
	//网关发送的ON /OFF 需要转换成"0" ,"1"
	ST_LED_WIFI_STATUS  enable[2]=
	{
		{"0","OFF"},
		{"1","ON"},
	};
	
	cJSON *root =cJSON_Parse(packet);
	if(NULL == root)
		return  0;
	
	server_sequence=get_json_value_num(root,"sequence");

	//提取出set      
	cJSON *set_root = cJSON_GetObjectItem(root, "set");

	//从set 中提取出WiFiswitch , 
	if(cJSON_HasObjectItem(set_root, "wifiswitch"))
	{
		cJSON *WiFiswitch_root =  cJSON_GetObjectItem(set_root, "wifiswitch");
		get_json_value(WiFiswitch_status ,WiFiswitch_root ,"status");
	}

	//从set 中提取出ledswitch_status
	if(cJSON_HasObjectItem(set_root, "ledswitch"))
	{
		cJSON *ledswitch_root =  cJSON_GetObjectItem(set_root, "ledswitch");
		get_json_value(ledswitch_status ,ledswitch_root ,"status");
	}

	
	if(cJSON_HasObjectItem(set_root, "wifitimer"))
	{
		wifi_schedule_en = 1;
		cJSON *WiFitimer_array = cJSON_GetArrayItem(cJSON_GetObjectItem(set_root, "wifitimer"), 0);
		cJSON *WiFitimer_root = cJSON_Parse(cJSON_PrintUnformatted(WiFitimer_array));

		get_json_value(WiFitimer_weekday ,WiFitimer_root ,"weekday");   
		get_json_value(WiFitimer_time ,WiFitimer_root ,"time");    
		get_json_value(WiFitimer_enable ,WiFitimer_root ,"enable");


		//转换日期
		wifi_schedule_time = get_wifischedule_day(WiFitimer_weekday);
		printf("=>wifi_schedule_time[%d]\n",wifi_schedule_time);
		memset(WiFitimer_weekday,0,sizeof(WiFitimer_weekday));
		sprintf(WiFitimer_weekday,"%d",wifi_schedule_time);
		
		setNvramValue("elink_wifi_schedule_time",WiFitimer_time);
		setNvramValue_5G("elink_wifi_schedule_time",WiFitimer_time);
		setNvramValue("elink_wifi_schedule_days",WiFitimer_weekday);
		setNvramValue_5G("elink_wifi_schedule_days",WiFitimer_weekday);	
	}
	
	
	//设置路由器的参数
	for(i=0 ; i<2;i++)
	{
		if(0 == strcasecmp(WiFiswitch_status,enable[i].set_status))
		{
			strcpy(wireless_enable,enable[i].router_cfg);
		}
		if(0 ==strcasecmp(ledswitch_status,enable[i].set_status))
		{
			strcpy(led_enable,enable[i].router_cfg);		
		}
	}
	
	if(0 != strcmp(old_wireless_enable,wireless_enable))
	{
		wifi_reboot_flag = 1;	
	}
	

	//led 开关

	//无线调度
	if(wifi_schedule_en)
	{
		setNvramValue("elink_wifi_schedule_en","1");
		setNvramValue_5G("elink_wifi_schedule_en","1");				
	}
	else
	{
		setNvramValue("elink_wifi_schedule_en","0");
		setNvramValue_5G("elink_wifi_schedule_en","0");	
	}
	
	commitNvram();
	commitNvram_5G();

	//设置无线开关
	if(wifi_reboot_flag)
	{
		setNvramValue("WirelessEnable",wireless_enable);
		setNvramValue_5G("WirelessEnable",wireless_enable);
		sendMessage(WIRELESS_CFG_CHANGED,NULL); 
	}
	else
	{
		printf("==>no need reboot\n");
	}

	//调度线程
	if(wifi_schedule_en)
	{	
		if(0 == strcmp(WiFitimer_enable,"1") || 0 == strcmp(WiFitimer_enable,"enable") )
		{
			doSystem("killall -9 elink_wifi_schedule");
			restartProgram("elink_wifi_schedule", "1");	
		}
		else
		{
			doSystem("killall -9 elink_wifi_schedule");
			restartProgram("elink_wifi_schedule", "0");	
		}
	}
	else
	{
		doSystem("killall -9 elink_wifi_schedule");
	}
	
	reply_ack_to_server(fd,server_sequence);

	if(root)
		cJSON_Delete(root);
	return 1;
}


/*
 *  设置无线配置参数
*/
int set_wifi_config(ST_SERVER_CFG_SET *cfg,int size)
{
	int n_mbssid = 0;
	int i = 0;
	
	for(i = 0 ; i< size; i++)
	{
		if(0 == strcmp(cfg[i].mode,"2.4G"))
		{
			/*2.4G*/
			f_setNvramValue = &setNvramValue;
			f_commitNvram  = &commitNvram ;
			STFs			    =  &STFs_24G;
		}
		else if(0 == strcmp(cfg[i].mode,"5G"))
		{
			/*5G*/
			f_setNvramValue = &setNvramValue_5G;
			f_commitNvram  = &commitNvram_5G ;
			STFs			    =  &STFs_5G;
		}
		else
		{
			return 0;
		}

	
		f_setNvramValue("SSID1",cfg[i].ssid);
	
		if(!strncmp(cfg[i].channel, "0", 2))
		{
			f_setNvramValue("AutoChannelSelect", "1");
			f_setNvramValue("Channel", "0");			
		}
		else
		{
			f_setNvramValue("AutoChannelSelect", "0");
			f_setNvramValue("Channel", cfg[i].channel);	
		}

		if (0 == strcasecmp(cfg[i].auth, "open") || 0 ==  strcasecmp(cfg[i].auth, "share") )
		{
			printf("=>NONE\n");
			STFs	(n_mbssid,"AuthMode", "OPEN");
			STFs	(n_mbssid,"EncrypType", "NONE");
		}
		else if (0 == strcasecmp(cfg[i].auth, "wpapsk") ||0 == strcasecmp(cfg[i].auth, "wpa2psk")  || 0 == strcasecmp(cfg[i].auth, "wpa") || 0 == strcasecmp(cfg[i].auth, "wpa2"))	     
		{
			printf("=>AES\n");
			//AES
			low_to_upper(cfg[i].auth);
			low_to_upper(cfg[i].encrypt);
			STFs	(n_mbssid,"AuthMode", cfg[i].auth);
			if(0 == strcasecmp(cfg[i].encrypt,"TKIPAES"))
			{
				STFs	(n_mbssid,"EncrypType", "AES");		
			}
			else
			{
				STFs	(n_mbssid,"EncrypType", cfg[i].encrypt);	
			}
			f_setNvramValue("WPAPSK1", cfg[i].key);
		}
		else if (0 == strcasecmp(cfg[i].auth, "wpapskwpa2psk")) 
		{  
			printf("=>wpapskwpa2psk\n");
			//TKIPAES
			low_to_upper(cfg[i].auth);
			low_to_upper(cfg[i].encrypt);
			STFs	(n_mbssid,"AuthMode",cfg[i].auth);
			STFs	(n_mbssid,"EncrypType", cfg[i].encrypt);
			f_setNvramValue("WPAPSK1", cfg[i].key);
		}
		
		f_commitNvram();		
	}
	
	sendMessage(WIRELESS_CFG_CHANGED,NULL);
	
	return 1;
}

int reply_cfg_ack_to_server(int fd,int number)
{
	char  sz_encrypt_out_buf[BUF_LEN] = {0};
	char  send_buff[BUF_LEN] = {0};
	int datelength = 0;
	int length = 0;
	char mac[18]={0};

	get_wan_mac_address(mac);
	cJSON *root = cJSON_CreateObject(); 
	
	cJSON_AddStringToObject(root, "type", "ack");
	cJSON_AddNumberToObject(root, "sequence", number);
	cJSON_AddStringToObject(root, "mac", mac);

	char * pJson = cJSON_Print(root);
	length=encrypted_json_packet(pJson,sz_encrypt_out_buf);

	if(NULL != root)
	{	
		cJSON_Delete(root);
		free(pJson);
	}

	datelength=makeup_send_buff(send_buff,sz_encrypt_out_buf,length);
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		printf("send error\n"); 	 	
		return -1;    	
	}
	
	return 0;	
}

int parse_server_cfg_info(char *packet, int fd)
{
	/*解析成功再回应ack给服务器*/
	ST_SERVER_CFG_SET server_set_cfg[2]={0} ;
	char gtway_mac[24]={0},wan_mac[24] ={0},wan_ip[32]={0},wan_mask[32]={0},wan_gateway[32]={0};
	int server_sequence = 0;
	char status_radio_mode[8] ={0};
	char server_channel[8]={0};
	int  status_radio_channel = 0;
	int channel = 0;
	int array_size =0,i=0,j = 0,ap_array_size = 0;
	cJSON *arrayItem = NULL;
	char work_mode[32]={0};
	
	cJSON *root =cJSON_Parse(packet);
	
	if(NULL == root)
		return  0;
	
	server_sequence=get_json_value_num(root,"sequence");
	
	get_json_value(gtway_mac,root,"mac");
	get_wan_mac_address(wan_mac);

	getNvramValue("wan_ipaddr",wan_ip);
	getNvramValue("wan_mask",wan_mask);
	getNvramValue("wan_gateway",wan_gateway);
	getNvramValue("system_work_mode",work_mode);

	if(cJSON_HasObjectItem(root, "status"))
	{
		cJSON *status_root = cJSON_GetObjectItem(root, "status");
		cJSON *status_WiFi_array = cJSON_GetObjectItem(status_root, "wifi");
		array_size = cJSON_GetArraySize(status_WiFi_array);

		//  "status":{"wifi":[{"radio":{"channel":0,"mode":"2.4G"}},{"radio":{"channel":0,"mode":"5G"}}]}
		//遍历 wifi 数组
		for(i=0;i<array_size;++i)
		{
			arrayItem = cJSON_GetArrayItem(status_WiFi_array,i);  
			cJSON *radio_root = cJSON_GetObjectItem(arrayItem, "radio");  
			status_radio_channel = get_json_value_num(radio_root,"channel"); 
			get_json_value(status_radio_mode,radio_root,"mode"); 
		}	
	}
	
	if(cJSON_HasObjectItem(root, "set"))
	{
		cJSON *set_radio_root =NULL;
		cJSON *set_ap_root =NULL;
		cJSON *set_array_item =NULL;
		cJSON *set_ap_item =NULL;
		cJSON *set_root =NULL;
		cJSON *set_WiFi_array=NULL;
		char wifi_encrypt[24]={0};
		
		//   解包  set ->  WiFi  
		set_root = cJSON_GetObjectItem(root, "set");
		set_WiFi_array= cJSON_GetObjectItem(set_root, "wifi");
		array_size = cJSON_GetArraySize(set_WiFi_array);
		
		for(i=0;i<array_size;++i)
		{
			set_array_item = cJSON_GetArrayItem(set_WiFi_array,i);	
			set_radio_root =  cJSON_GetObjectItem(set_array_item, "radio"); 
			
			channel= get_json_value_num(set_radio_root,"channel");
			sprintf(server_set_cfg[i].channel,"%d", channel);
			get_json_value(server_set_cfg[i].mode,set_radio_root,"mode");

			set_ap_root = cJSON_GetObjectItem(set_array_item, "ap"); 
			ap_array_size = cJSON_GetArraySize(set_ap_root); 

			for(j=0;j<ap_array_size;++j)
			{
				set_ap_item  = cJSON_GetArrayItem(set_ap_root,j);	
				server_set_cfg[i].apidx= get_json_value_num(set_ap_item,"apidx");
				get_json_value(server_set_cfg[i].ssid,set_ap_item,"ssid");
				get_json_value(server_set_cfg[i].key,set_ap_item,"key");
				get_json_value(server_set_cfg[i].auth,set_ap_item,"auth");
				get_json_value(wifi_encrypt,set_ap_item,"encrypt");
				if(0 == strcasecmp(wifi_encrypt,"aestkip"))   //TKIPAES
				{
					strcpy(server_set_cfg[i].encrypt,"TKIPAES");
				}
				else
				{
					strcpy(server_set_cfg[i].encrypt,wifi_encrypt);	
				}
				printf("=>encrypt[%s]\n",server_set_cfg[i].encrypt);
				
				if(cJSON_HasObjectItem(set_ap_item, "enable"))
				{
					//网关下发配置无enable , 文档有
					get_json_value(server_set_cfg[i].enable,set_ap_item,"enable");		
				}
			}	
		}	
	}

	if(0 == strcmp(work_mode,"router"))
	{
		char wan_fac_mac[32]={0};
		getNvramValue("wan_fac_mac_addr",wan_fac_mac);
		printf("=>wan_fac_mac=%s\n",wan_fac_mac);
		printf("==>wan_ip[%s],wan_mask[%s],wan_gateway[%s]",wan_ip,wan_mask,wan_gateway);
		doSystem("killall -9 udhcpd"); 
		doSystem("route del default"); 
		doSystem("ifconfig eth2.2 0.0.0.0"); 
		doSystem("brctl addif br0 eth2.2"); 
		doSystem("ifconfig br0:0  %s netmask %s hw ether %s",wan_ip,wan_mask,wan_fac_mac); 
		doSystem("route add default gw %s dev br0",wan_gateway); 
		setNvramValue("system_work_mode","ap");
		setNvramValue("dhcpd_en","0");
		printf("=>turn into to brage\n");
	}
	set_wifi_config(&server_set_cfg,array_size);	
	
	reply_cfg_ack_to_server(fd,server_sequence);
	return 1;
}

/*
 *  get_status 回复包, 
*/
int parse_server_get_status(char *packet,int fd)
{
	char  get_status_name[4][16]={"wifi","wifiswitch","ledswitch","wifitimer"};
	char get_name[16]={0};
	cJSON *arrayItem = NULL;
	int array_size = 0,i =0,j=0;
	int name_type = 0;
	int sequence = 0;
	
	cJSON *root  = cJSON_Parse(packet);
	
	if(NULL == root)
		return 0;
	
	sequence = get_json_value_num(root,"sequence");
	
	cJSON *get_array = cJSON_GetObjectItem(root, "get");
	
	//获取数组大小
	array_size = cJSON_GetArraySize(get_array);
	
	//遍历 get_array 
	for(i=0;i<array_size;++i)
	{
		arrayItem = cJSON_GetArrayItem(get_array,i);
		memset(get_name,0,sizeof(get_name));
		get_json_value(get_name,arrayItem,"name");
		for( j=0 ; j<4 ; j++)
		{
			if(0 == strcasecmp(get_status_name[j],get_name))
			{
				name_type |= 1 << j  ;
				break;
			}
		}
	}
	reply_client_status(fd,sequence,name_type);
	
	return 1;
}


int parse_cfg_type(char *packet)
{
	cJSON *root =cJSON_Parse(packet);

	if(cJSON_HasObjectItem(root,"status"))
	{
		//表8
		return ELINK_TYPE_RCV_CONFIG_CFG  ;
	}
	else if(cJSON_HasObjectItem(root,"set"))
	{
		cJSON *set_root = cJSON_GetObjectItem(root, "set");	
		
	 	if(cJSON_HasObjectItem(set_root,"WiFiswitch"))
		{
			//表9
			return ELINK_TYPE_RCV_SET_CFG ;
		}
		else if(cJSON_HasObjectItem(set_root,"wpsswitch"))
		{
			//表13
			return  ELINK_TYPE_RCV_WPS_CFG;
		}
		else if(cJSON_HasObjectItem(set_root,"upgrade"))
		{
			//表14
			return  ELINK_TYPE_RCV_UPGRADE_CFG;
		}
	}
	return -1;
}

int getWirelessCnnMac_24G()
{
	int  s = 0,i;
	
	struct iwreq iwr;
	RT_802_11_MAC_TABLE table = {0};

	//2.4G
	memset(&iwr, 0x0, sizeof(iwr));
	memset(&table, 0x0, sizeof(table));
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(iwr.ifr_name, "ra0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &table;
	
	if (s <= 0) 
	{
		printf("erorr to create socket\n");
		goto FAIL_EXIT;
	}

	if (ioctl(s, RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT, &iwr) < 0) 
	{
		close(s);
		printf("erorr to ioctl socket\n");

		goto FAIL_EXIT;
	}
	close(s);
	s = 0;
	memset(g_wl_cnn_mac_lists_24G,0,sizeof(g_wl_cnn_mac_lists_24G));
	//同站点不同条目用","分开，不同站点使用";"分开
	for (i = 0; i < table.Num; i++) 
	{
		sprintf(g_wl_cnn_mac_lists_24G[i],"%02X:%02X:%02X:%02X:%02X:%02X",
				table.Entry[i].Addr[0],
				table.Entry[i].Addr[1],
				table.Entry[i].Addr[2], 
				table.Entry[i].Addr[3],
				table.Entry[i].Addr[4], 
				table.Entry[i].Addr[5]);
		if(i >= MAX_NUMBER_OF_MAC-1)
		{
			break;
		}
	}
	return 0;
	
FAIL_EXIT:
	return -1;
}

int getWirelessCnnMac_5G()
{
	int  s = 0,i;
	
	struct iwreq iwr;
	RT_802_11_MAC_TABLE table = {0};


	memset(&iwr, 0x0, sizeof(iwr));
	memset(&table, 0x0, sizeof(table));
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(iwr.ifr_name, "rai0", IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) &table;
	
	if (s <= 0) 
	{
		printf("5g erorr to create socket\n");
		goto FAIL_EXIT;
	}

	if (ioctl(s, RTPRIV_IOCTL_GET_MAC_TABLE_STRUCT, &iwr) < 0) 
	{
		close(s);
		printf("5g erorr to ioctl socket\n");

		goto FAIL_EXIT;
	}
	close(s);
	s = 0;

	memset(g_wl_cnn_mac_lists_5G,0,sizeof(g_wl_cnn_mac_lists_5G));
	
	//同站点不同条目用","分开，不同站点使用";"分开
	for (i = 0; i < table.Num; i++) 
	{
		sprintf(g_wl_cnn_mac_lists_5G[i],"%02X:%02X:%02X:%02X:%02X:%02X",
				table.Entry[i].Addr[0],
				table.Entry[i].Addr[1],
				table.Entry[i].Addr[2], 
				table.Entry[i].Addr[3],
				table.Entry[i].Addr[4], 
				table.Entry[i].Addr[5]);

		if(i >= MAX_NUMBER_OF_MAC-1)
		{
			break;
		}
	}	

	return 0;
	
FAIL_EXIT:
	return -1;
}

int checkWirelessClient_24G(char *mac_addr)
{
	int i = 0;
	
	if((NULL == mac_addr) || (strlen(mac_addr) < 17))
	{
		return 0;
	}

	for(i=0; i<MAX_NUMBER_OF_MAC; i++)
	{
		if(17 == strlen(g_wl_cnn_mac_lists_24G[i]))
		{	//忽略大小写比较字符串.
			if(0 == strcasecmp(g_wl_cnn_mac_lists_24G[i],mac_addr))
			{
				return 1;
			}
		}
	}
	
	return 0;
}

int checkWirelessClient_5G(char *mac_addr)
{
	int i = 0;
	
	if((NULL == mac_addr) || (strlen(mac_addr) < 17))
	{
		return 0;
	}

	for(i=0; i<MAX_NUMBER_OF_MAC; i++)
	{
		if(17 == strlen(g_wl_cnn_mac_lists_5G[i]))
		{
			if(0 == strcasecmp(g_wl_cnn_mac_lists_5G[i],mac_addr))
			{
				return 1;
			}
		}
	}

	return 0;
}

int check_dev_report(int fd)
{	
	static ST_DEV_REPORT_MESSAGE dev_report_prov[128]={0}; //上一次上报信息
	static int prov_array_size =0;

	ST_DEV_REPORT_MESSAGE  dev_report_next[128]={0};
	unsigned long requested_ip,lan_ip;
	int array_size = 0,j=0;
	FILE *fp;
	char buf[128]={0},ip[16]={0},mac[18] = {0};
	char *wan_interface=NULL;
	char *p1=NULL,*p2 = NULL;
	char iptmp[16] = {0};
	unsigned char lan_mac_arp[6];
	char *lan_ifname= NULL;
	char lan_mac[18] ={0};
	char lan_ip_addr[16]={0};
	int ret = 0;

	getWirelessCnnMac_24G();
	
   	getWirelessCnnMac_5G();
	
	//arp file
	fp=fopen(SYS_ARP_FILE,"r");
	if(NULL == fp)
	{
	   return -1;
	}

	if(NULL == fgets(buf,128,fp))
	{
	   fclose(fp);
	   return -1;
	}
	
	wan_interface = getWanIfName();
	lan_ifname = getLanIfName();
	getNvramValue("lan_mac_addr",lan_mac);
	getNvramValue("lan_ipaddr",lan_ip_addr);
	lan_ip =inet_addr(lan_ip_addr);
	sscanf(lan_mac, "%02x:%02x:%02x:%02x:%02x:%02x", &lan_mac_arp[0], &lan_mac_arp[1], &lan_mac_arp[2], &lan_mac_arp[3], &lan_mac_arp[4], &lan_mac_arp[5]);   
	
	while(fgets(buf,128,fp))
	{
		//过滤掉 wan arp
		if(strstr(buf,wan_interface) != NULL)
	    	{
	        	continue;
	    	}

		p1 = strchr(buf,' ');
		 if(NULL == p1)
      	 	{
           		fclose(fp);
           		return -1;
       		}
		 
		strncpy(ip,buf,p1-buf);
		strncpy(iptmp,ip,p1-buf);
		requested_ip = inet_addr(iptmp);

		//参数1 ,2 不能用htonl 转换
		if(ret = arpping(requested_ip , lan_ip ,lan_mac_arp , lan_ifname))
		{
			//ret 返回 1 表示地址 已经释放,但是 arp 文件没有及时更新
			continue ;
		}
		
		p1=strchr(buf,':');  //mac;
	   	if(NULL == p1)
	   	{
	   		fclose(fp);
	      		return -1;
	   	}
		
		p1 -= 2;
	   	p2 = strchr(p1,' ');

		if(NULL == p2)
	   	{
	      		fclose(fp);
	      		return -1;
	   	}

		strncpy(mac,p1,p2-p1);
		
		upMacAddr(mac, dev_report_next[array_size].mac);
		
		if((checkWirelessClient_24G( dev_report_next[array_size].mac)) || (checkWirelessClient_5G( dev_report_next[array_size].mac)))
		{
			dev_report_next[array_size].connecttype = 1;
		}
		else
		{
			 dev_report_next[array_size].connecttype = 0;
		}
		/* 去掉mac 中间的 : */
		get_mac_address(dev_report_next[array_size].mac);  
		strcpy( dev_report_next[array_size].vmac, dev_report_next[array_size].mac);
		array_size++;
	}

	if(prov_array_size == array_size)
	{
		if(0 == memcmp(dev_report_prov,dev_report_next,sizeof(ST_DEV_REPORT_MESSAGE)*array_size))
		{
			TRACE_DEBUG("==>no new dev connect\n");	
		}
		else
		{
			TRACE_DEBUG("==>new device report\n");
			memset(dev_report_prov,0,sizeof(dev_report_prov)*prov_array_size);
			memcpy(dev_report_prov,dev_report_next,sizeof(ST_DEV_REPORT_MESSAGE)*array_size);
			prov_array_size = array_size;
			if(0 == send_dev_report(dev_report_next,array_size,fd))
			{
				set_status(ELINK_WAITTING_DEV_REPORT_ACK);
				/*必须发送成功才能设置状态，否则会跟keepalive 冲突 */
			}
		}
	}
	else
	{
		TRACE_DEBUG("==>new device report\n");
		memset(dev_report_prov,0,sizeof(dev_report_prov)*prov_array_size);
		memcpy(dev_report_prov,dev_report_next,sizeof(ST_DEV_REPORT_MESSAGE)*array_size);
		prov_array_size = array_size;
		if(0 == send_dev_report(dev_report_next,array_size,fd))
		{
			set_status(ELINK_WAITTING_DEV_REPORT_ACK);
			/*必须发送成功才能设置状态，否则会跟keepalive 冲突 */
		}
	}
	return 1;
}


int send_dev_report(ST_DEV_REPORT_MESSAGE *buff,int array_size,int fd)
{	
	int i = 0;
	char mac[18] = {0};
	char  sz_encrypt_out_buf[BUF_LEN] = {0};
	char send_buff[BUF_LEN] = {0};
	int length = 0,datelength = 0;

	get_wan_mac_address(mac);
	cJSON *root =	cJSON_CreateObject();
	//添加 type , sequence ,mac 
	cJSON_AddStringToObject(root, "type", "dev_report");
	cJSON_AddNumberToObject(root, "sequence", ++sequencenum);
	cJSON_AddStringToObject(root, "mac", mac);

	cJSON *dev_array = NULL;
	cJSON *dev_array_root[array_size] ;
	cJSON_AddItemToObject(root, "dev", dev_array = cJSON_CreateArray());
	
	for(i=0 ; i < array_size ; i++)
	{
		dev_array_root[i] =  cJSON_CreateObject();	
		cJSON_AddStringToObject(dev_array_root[i], "mac", buff[i].mac);
		cJSON_AddStringToObject(dev_array_root[i], "vmac", buff[i].vmac);
		cJSON_AddNumberToObject(dev_array_root[i], "connecttype", buff[i].connecttype);
		cJSON_AddItemToArray(dev_array, dev_array_root[i]);
	}
	char *pJson = cJSON_Print(root);
	
	length=encrypted_json_packet(pJson,sz_encrypt_out_buf);

	if(NULL != root)
	{
		cJSON_Delete(root);
		free(pJson);	
	}

	datelength=makeup_send_buff(send_buff,sz_encrypt_out_buf,length);
	
	if( send(fd,send_buff, datelength, 0) != datelength)     	
	{     		
		TRACE_DEBUG("=>dev_report send error\n"); 	 	
		return -1;    	
	}	
	return 0;						
}

