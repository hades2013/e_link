#include "elink_public.h"


static int g_n_signal_pipe[2];
static ST_ELINK_CFG elink_info ;


/* Exit and cleanup */
static void exit_client(int retval)
{
	exit(retval);
}

/* Signal handler */
static void signal_handler(int sig)
{
	if(send(g_n_signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT) < 0)
	{
		TRACE_DEBUG("Could not send signal: %s", strerror(errno));
	}
	return;
}

int  init_elink_config()
{
	char gateway[64] ={0};
	unsigned long ip = 0;
	char work_mode[32]={0};

	if( gen_DH_key())
		return  ELINK_INIT_OTHER_FAILED;
	
	socketpair(AF_UNIX, SOCK_STREAM, 0, g_n_signal_pipe);
	
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGTERM, signal_handler);

	memset(gateway,0,sizeof(gateway));
	getNvramValue("system_work_mode",work_mode);
	if(0 == strcmp(work_mode,"router"))
	{
		getNvramValue("wan_gateway",gateway);					
	}
	else if(0 == strcmp(work_mode,"ap"))
	{
		getNvramValue("lan_gw_udhcpc",gateway);
	}
	else
	{
		return ELINK_INIT_GATEWAY_FAILED;		
	}
	
	if(!gateway)
		return ELINK_INIT_GATEWAY_FAILED;
	
	ip=inet_addr(gateway); 
	
	elink_info.socket_fd = create_socket(ip, ELINK_SERVER_LISTEN_PORT);
	
	if(elink_info.socket_fd <= 0)
		return ELINK_INIT_SOCKET_FAILED;
	
	set_status(ELINK_INIT);
	
	return ELINK_INIT_SUCCESS;
}

int  restore_default_config()
{
	TRACE_DEBUG("=>default_config\n ");
	pthread_t keepalive_pid = 0;
	keepalive_pid=get_keepalive_pid();
	pthread_cancel(keepalive_pid);
	
	elink_info.init_flag = 0;
	elink_info.socket_fd = 0;
	elink_info.max_fd = 0;
	
	if(g_n_signal_pipe[0] >0 || g_n_signal_pipe[1] >0)
	{
		close(g_n_signal_pipe[0]);
		close(g_n_signal_pipe[1]);
		g_n_signal_pipe[0] = 0;
		g_n_signal_pipe[1] = 0;
	}
	
	sleep(T1);
	return 1;
}

void init_elink()
{
	int init_ret = 0;
	init_ret=init_elink_config();
	
	switch(init_ret)
	{
	case ELINK_INIT_GATEWAY_FAILED:	
		sleep(T8);
		break;
	case ELINK_INIT_SOCKET_FAILED:
		sleep(T1);
		break;
	case ELINK_INIT_SUCCESS:
		elink_info.init_flag= 1 ;
		break;
	default:
		break;  
	}
	return ;
}

int main()
{	
	int init_ret =0;
	struct timeval tv;
	fd_set fdset_rfds;
	int n_select_ret;
	int n_sig;
	int n_status = ELINK_INIT;
	int n_wait_keyngreq_time_count = 0, n_wait_dhpubkey_reply_time_count = 0, n_wait_devregister_time_count = 0, n_wait_dev_report_time_count = 0;
	int n_exit_flag = 0;
	
	memset(&elink_info,0,sizeof(ST_ELINK_CFG));
	
	for(;;) 
	{
		/* begin for loop */
		if(1 != elink_info.init_flag)
		{
			init_elink();	
			continue ;
		}
		else
		{
			tv.tv_sec = SELECT_WAIT_TIMEOUT;
			tv.tv_usec = 0;

			FD_ZERO(&fdset_rfds);
			FD_SET(elink_info.socket_fd, &fdset_rfds);
			FD_SET(g_n_signal_pipe[0], &fdset_rfds);

			elink_info.max_fd = elink_info.socket_fd > g_n_signal_pipe[0] ? elink_info.socket_fd  : g_n_signal_pipe[0];
			
			n_select_ret = select((elink_info.max_fd+ 1), &fdset_rfds, NULL, NULL, &tv);
			
			if(n_exit_flag)
			{
				/*ÍË³öÄ£¿é*/
				exit_client(0);
			}
		
			if(0 == n_select_ret) 
			{
				/* timeout */
				n_status = get_status();
				switch (n_status) 
				{
					case ELINK_INIT:
						send_keyngreq(elink_info.socket_fd);
						n_wait_keyngreq_time_count = 0;
						break;
					case ELINK_WAITTING_KEYNGREQ_ACK:
						n_wait_keyngreq_time_count++;
						if(n_wait_keyngreq_time_count > T9)
						{	
							doSystem("killall -SIGUSR1 MTC_e_link"); 
							n_wait_keyngreq_time_count = 0;
						}
						break;
					case ELINK_WAITTING_DH_PUBKEY_REPLY:
						n_wait_dhpubkey_reply_time_count++;
						if(n_wait_dhpubkey_reply_time_count > T2)
						{	
							doSystem("killall -SIGUSR1 MTC_e_link"); 
							n_wait_dhpubkey_reply_time_count = 0;
						}
						break;
					case ELINK_WAITTING_DEV_REGISTER_ACK:
						n_wait_devregister_time_count++;
						if(n_wait_devregister_time_count > T3)
						{
							doSystem("killall -SIGUSR1 MTC_e_link"); 
							n_wait_devregister_time_count = 0;
						}
						break;
					case ELINK_WAITTING_DEV_REPORT_ACK:
						n_wait_dev_report_time_count++;
						if(n_wait_dev_report_time_count > T2)
						{
							doSystem("killall -SIGUSR1 MTC_e_link"); 
							n_wait_dev_report_time_count = 0;
						}
						break;
					default:
						break;
				}
				continue ;
			}
			else if((n_select_ret < 0) && (errno != EINTR)) 
			{
				/* error on select */
				exit_client(0);
			}
			
			if(FD_ISSET(g_n_signal_pipe[0], &fdset_rfds)) 
			{
				if(read(g_n_signal_pipe[0], &n_sig, sizeof(n_sig)) < 0)
				{
					continue; 
				}	
				switch(n_sig) 
				{
					case SIGUSR1:
						restore_default_config();
						continue;
					case SIGUSR2:
						restore_default_config();
						continue;
					case SIGTERM:
						n_exit_flag = 1;
						exit_client(0);
				}
			}
			
			if(FD_ISSET(elink_info.socket_fd, &fdset_rfds)) 
			{
				/* packet is ready, read it */
				get_packet(elink_info.socket_fd);
			}

		}
	}

	return 0;
}

