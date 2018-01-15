#ifndef __ELINK_PUBLIC_H__
#define __ELINK_PUBLIC_H__

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <errno.h>
#include <string.h>
#include <linux/filter.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>


#include <openssl/ssl.h>  
#include <openssl/err.h> 

#include <openssl/dh.h>
#include <openssl/aes.h>
#include <linux/wireless.h>

#include "common.h"
#include "ipc_msg.h"
#include "sys_log.h"
#include "oid.h"

#include "cJSON.h"

#define	BUF_LEN		1500
#define	KEY_BITS	128		/*16 bytes*/

/*the string len must be 16(include the ending character '/0')*/
#define	IVEC_STRING	"0123456789abcdef" 

#define	ELINK_HEADER_FLAG	0x3f721fb5

#define	ELINK_SERVER_LISTEN_PORT	32768
#define	ELINK_CLIENT_BIND_PORT		32769

#define	SELECT_WAIT_TIMEOUT	1

#define  T1  10
#define  T2  20
#define  T3  30 
#define  T4  20
#define  T5  5
#define  T6  5
#define  T7  5
#define  T8  2
#define  T9  5
#define KEEPALIVE_PID_FILE   "/var/run/elink.pid"
#define BLOCK_SIZE 16




/*
数据头部总共8个字节，包含两部分，标示Flag 4个字节，长度Len 4个字节。
数据头部的低4个字节为Flag，采用big endian方式，值为0x3f721fb5。
数据头部的高4个字节为Len，采用big endian方式，用于标识后续密文长度。
*/
typedef struct elink_message_st
{
	unsigned long head_flag;
	unsigned long n_date_len;
}ST_ELINK_MESSAGE;

typedef struct elink_message_st_st
{
	char head_flag[4];
	unsigned long n_date_len;
}ST_ST_ELINK_MESSAGE;


typedef struct dev_report_message_st
{
	char  mac[18];
	char vmac[18];
	int  connecttype;
	unsigned long ip ;
}ST_DEV_REPORT_MESSAGE;

typedef struct elink_cfg
{
	int init_flag;
	int socket_fd;
	int max_fd;
}ST_ELINK_CFG;

typedef struct led_wifi_status_st
{
	char  router_cfg[8];
	char  set_status[8];
}ST_LED_WIFI_STATUS;

typedef struct server_cfg_set_st
{
	int  apidx;
	char  mode[8] ;
	char channel[8] ;
	char enable[8];
	char ssid[64];
	char key[64];
	char auth[24];
	char encrypt[24];
}ST_SERVER_CFG_SET;

typedef enum elink_status_e
{
	ELINK_INIT = 0,
	ELINK_WAITTING_KEYNGREQ_ACK,
	ELINK_RCV_KEYNGREQ_ACK,
	ELINK_WAITTING_DH_PUBKEY_REPLY,
	ELINK_RCV_DH_PUBKEY_REPLY,
	ELINK_WAITTING_DEV_REGISTER_ACK,
	ELINK_RCV_DEV_REGISTER_ACK,
	ELINK_DEV_REGISTER_SUCESS,
	ELINK_WAITTING_DEV_REPORT_ACK,
	ELINK_RCV_DEV_REPORT_ACK,
	ELINK_WAITTING_KEEPALIVE_ACK,
	ELINK_RCV_KEEPALIVE_ACK,
}ELINK_STATUS_E_T;

typedef enum elink_packet_type_e
{
	ELINK_TYPE_KEYNGREQ = 0,
	ELINK_TYPE_KEYNGREQ_ACK,
	ELINK_TYPE_SEND_CLIENT_DH,
	ELINK_TYPE_RCV_SERVER_DH,
	ELINK_TYPE_DEV_REG,
	ELINK_TYPE_DEV_REG_ACK,
	ELINK_TYPE_KEEPALIVE,
	ELINK_TYPE_KEEPALIVE_ACK,
	ELINK_TYPE_RCV_CONFIG_CFG,
	ELINK_TYPE_RCV_SET_CFG,
	ELINK_TYPE_RCV_WPS_CFG,
	ELINK_TYPE_RCV_UPGRADE_CFG,
	ELINK_TYPE_SEND_CFG_ACK,
	ELINK_TYPE_RCV_GET_STATUS,
	ELINK_TYPE_RETURN_STATUS,
	ELINK_TYPE_DEV_REPORT,
	ELINK_TYPE_DEV_REPORT_ACK,
}ELINK_PACKET_TYPE_E_T;

typedef enum elink_init_status
{
	ELINK_INIT_SUCCESS = 0,
	ELINK_INIT_GATEWAY_FAILED,
	ELINK_INIT_SOCKET_FAILED,	
	ELINK_INIT_OTHER_FAILED,	
}ELINK_INIT_STATUS_T;


#define	WAIT_KEEPALIVE_ACK_FAILTIME		10

/*elink_dh.c -- begin*/
int set_wifi_config(ST_SERVER_CFG_SET *cfg,int size);
int set_DH_server_pubkey(BIGNUM *p_key);
DH  *get_DH_client();
int get_sharekey(char *buff ,int length);
int gen_DH_key();
int compute_client_sharekey();
int get_client_sharekey(char *p_out_sharekey, int n_sharekey_len);
/*elink_dh.c -- end*/

/*elink_socket.c -- begin*/
int create_socket(unsigned long ip, int port);
/*elink_socket.c -- end*/

/*elink_public.c -- begin*/
int set_status(ELINK_STATUS_E_T e_status);
int get_status();
/*elink_public.c -- end*/

/*elink_public.c -- begin*/
int makeup_send_buff(char *send_buff,char *packet,int length);
int get_wifischedule_day(char *days);
int patse_server_upgrade_cfg(char *packet, int fd);
int parse_cfg_type(char *packet);
int parse_server_get_status(char *packet,int fd);
int get_packet(int fd);
int get_packet_type(char *packet,int length);
int dealwith_rcv_packet(char *packet, int fd,int length);
int send_dev_report(ST_DEV_REPORT_MESSAGE *buff,int array_size,int fd);
int send_keyngreq(int fd);
int send_client_dh_pubkey(int fd);
int send_dev_register_req(int fd);
int send_keepalive(int fd);
int reply_client_status(int fd,int number,int type);
int parse_server_cfg_info(char *packet, int fd);
int reply_ack_to_server(int fd,int number);


void  get_wan_mac_address(char *mac);
int	restore_default_config();
int check_dev_report(int fd);
/*elink_public.c -- end*/


/*cJSON*/
int get_json_value(char *out_buff ,cJSON * json_root ,char *json_key);
int get_json_value_num( cJSON * json_root ,char *json_key);


/*AES_CEC*/
int encrypted_json_packet(char *json_buff , char *encrypt_out_buff);
int decode_json_packet(char *json_buff , char *decrypt_out_buf,int length);

//字符串
void  upper_to_low(char *str);
void   low_to_upper(char *str);
/* 日期*/
void date_change(char *WiFitimer_weekday);


/*  keepalive */
void start_keepalive_thread(int fd);
pthread_t get_keepalive_pid();
void set_keepalive_pid(int pid);
int keepalive_send_message();
/*   文件同步 */
int keepaliveCheckRunning(void);
//int setRuntimeFileTag(char *file_name);  //加入公共库需要去掉

void base64_encode(unsigned char *input, unsigned input_length, unsigned char *output);

void base64_decode(unsigned char *input, unsigned input_length, unsigned char *output);

#endif
