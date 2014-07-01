/*
 * uac.c
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */

//#include "csenn_eXosip2.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "dispatch.h"
#include <string.h>
#include "uac.h"
#include "time.h"

int g_register_id  ;//= 0;/*注册ID/用来更新注册或取消注册*/
int g_call_id      ;//= 0;/*INVITE连接ID/用来分辨不同的INVITE连接，每个时刻只允许有一个INVITE连接*/
int g_did_realPlay ;//= 0;/*会话ID/用来分辨不同的会话：实时视音频点播*/
int g_did_backPlay ;//= 0;/*会话ID/用来分辨不同的会话：历史视音频回放*/
int g_did_fileDown ;//= 0;/*会话ID/用来分辨不同的会话：视音频文件下载*/

/*GB28181主函数*/
void csenn_eXosip_launch(void)
{
/*
	char eXosip_server_id[30]           = "34020000002000000001";
	char eXosip_server_ip[20]           = "192.168.1.178";
	char eXosip_server_port[10]         = "5060";
	char eXosip_ipc_id[30]              = "34020000001320000001";
	char eXosip_ipc_pwd[20]             = "12345678";
	char eXosip_ipc_ip[20]              = "192.168.1.144";
	char eXosip_ipc_port[10]            = "6000";
*/
	static  char eXosip_device_name[30]         = "IPC";
	static  char eXosip_device_manufacturer[30] = "CSENN";
	static  char eXosip_device_model[30]        = "GB28181";
	static  char eXosip_device_firmware[30]     = "V1.0";
	static  char eXosip_device_encode[10]       = "ON";
	static  char eXosip_device_record[10]       = "OFF";

	static  char eXosip_status_on[10]           = "ON";
	static  char eXosip_status_ok[10]           = "OK";
	static  char eXosip_status_online[10]       = "ONLINE";
	static  char eXosip_status_guard[10]        = "OFFDUTY";
	static char eXosip_status_time[30]         = "2012-12-20T12:12:20";
/*
	device_info.server_id           = eXosip_server_id;
	device_info.server_ip           = eXosip_server_ip;
	device_info.server_port         = eXosip_server_port;
	device_info.ipc_id              = eXosip_ipc_id;
	device_info.ipc_pwd             = eXosip_ipc_pwd;
	device_info.ipc_ip              = eXosip_ipc_ip;
	device_info.ipc_port            = eXosip_ipc_port;
*/
	device_info.device_name         = eXosip_device_name;
	device_info.device_manufacturer = eXosip_device_manufacturer;
	device_info.device_model        = eXosip_device_model;
	device_info.device_firmware     = eXosip_device_firmware;
	device_info.device_encode       = eXosip_device_encode;
	device_info.device_record       = eXosip_device_record;

	device_status.status_on         = eXosip_status_on;
	device_status.status_ok         = eXosip_status_ok;
	device_status.status_online     = eXosip_status_online;
	device_status.status_guard      = eXosip_status_guard;
	device_status.status_time       = eXosip_status_time;
/*
	csenn_eXosip_callback.csenn_eXosip_getDeviceInfo(&device_info);
	while (csenn_eXosip_init());
	while (csenn_eXosip_register(3600));
	csenn_eXosip_processEvent();
*/
}

int csenn_eXosip_init(void)
{
	g_register_id  = 0;/*注册ID/用来更新注册或取消注册*/
	g_call_id      = 0;/*INVITE连接ID/用来分辨不同的INVITE连接，每个时刻只允许有一个INVITE连接*/
	g_did_realPlay = 0;/*会话ID/用来分辨不同的会话：实时视音频点播*/
	g_did_backPlay = 0;/*会话ID/用来分辨不同的会话：历史视音频回放*/
	g_did_fileDown = 0;/*会话ID/用来分辨不同的会话：视音频文件下载*/

	int ret = 0;

	ret = eXosip_init();/*初始化osip和eXosip协议栈*/
	if (0 != ret)
	{
		printf("Couldn't initialize eXosip!\r\n");
		return -1;
	}
	printf("eXosip_init success!\r\n");

	ret = eXosip_listen_addr(IPPROTO_UDP, NULL, atoi(device_info.ipc_port), AF_INET, 0);
	if (0 != ret)/*传输层初始化失败*/
	{
		eXosip_quit();
		printf("eXosip_listen_addr error!\r\n");
		return -1;
	}
	printf("eXosip_listen_addr success!\r\n");

	return 0;
}

int csenn_eXosip_invit(sessionId * id, char * to, char * sdpMessage, char * responseSdp)
{
	osip_message_t *invite;
	int i;// optionnal route header
	char to_[100];
	snprintf (to_, 100,"sip:%s", to);
	char from_[100];
		snprintf (from_, 100,
			"sip:%s:%s", device_info.ipc_ip ,device_info.ipc_port );
		//snprintf (tmp, 4096, "");
	/*i = eXosip_call_build_initial_invite (&invite,
			"sip:34020000001180000002@192.168.17.1:5060",
			"sip:34020000001320000001@192.168.17.1:5060",
			NULL,
			"34020000001320000001:1,34020000001180000002:1" );*/
		i = eXosip_call_build_initial_invite (&invite,
					to_,
					from_,
					NULL,
					"This is a call for a conversation" );
	//i = eXosip_call_build_initial_invite (&invite,"<sip:user2@192.168.17.128>",	"<sip:user1@192.168.17.128>",NULL,	"This is a call for a conversation" );
	if (i != 0)
	{
	return -1;
	}
	//osip_message_set_supported (invite, "100rel");
	{
	char tmp[4096];
	char localip[128];
	eXosip_guess_localip (AF_INET, localip, 128);
	localip[128]=device_info.ipc_ip;

	i=osip_message_set_body (invite, sdpMessage, strlen (sdpMessage));
	i=osip_message_set_content_type (invite, "APPLICATION/SDP");
	}
	eXosip_lock ();
	i = eXosip_call_send_initial_invite (invite);

	if (i > 0)
	{
	//eXosip_call_set_reference (i, "ssss");
	}
	eXosip_unlock ();
	int flag1 = 1;
	      while (flag1)
	        {
	    	  eXosip_event_t *je;
	          je = eXosip_event_wait (0, 1000);

	       if (je == NULL)
	        {
	          printf ("No response or the time is over!\n");
	          break;
	        }

	       switch (je->type)
	        {
	        case EXOSIP_CALL_INVITE:
	          printf ("a new invite reveived!\n");
	          break;
	        case EXOSIP_CALL_PROCEEDING:
	          printf ("proceeding!\n");
	          break;
	        case EXOSIP_CALL_RINGING:
	          printf ("ringing!\n");
	          //printf ("call_id is %d, dialog_id is %d \n", je->cid, je->did);
	          break;
	        case EXOSIP_CALL_ANSWERED:
	          printf ("ok! connected!\n");
	          printf ("call_id is %d, dialog_id is %d \n", je->cid, je->did);
	          id->cid=je->cid;
	          id->did=je->did;
	          osip_body_t *body;
	          osip_message_get_body (je->response, 0, &body);
	          //printf ("I get the msg is: %s\n", body->body);
	          //(*responseSdp)=(char *)malloc (body->length*sizeof(char));
	          if(body!=NULL)
	          snprintf (responseSdp, body->length,"%s", body->body);

	           //response a ack
	          osip_message_t *ack = NULL;
	          eXosip_call_build_ack (je->did, &ack);
	          eXosip_call_send_ack (je->did, ack);
	          flag1 = 0;
	          break;
	        case EXOSIP_CALL_CLOSED:
	          printf ("the other sid closed!\n");
	          break;
	        case EXOSIP_CALL_ACK:
	          printf ("ACK received!\n");
	          break;
	        default:
	          printf ("other response!\n");
	          break;
	        }
	       eXosip_event_free (je);

	        }
	return 0;

}

int check_conf(const char * file)
{
	int fd=open(file,O_RDONLY);
	    if(fd>2){   //确保文件存在
	    	static  char * cfgFile;
	    	cfgFile=(char *)malloc(sizeof(char)*30);
	    	strcpy(cfgFile,file);
	    	device_info.cfgFile=cfgFile;
	        close(fd);
	        //printf("open config file:%s success\n",file);
	    }
	    else{
	       printf("can not open config file:%s\n",file);
	       return 0;
	       //exit(1);
	    }
	return 1;
	}

int uac_init(const char *conf)
{
	if(conf==NULL)
		conf=DEFAULT_CFG;
	if(check_conf(conf)<1)
	{
		printf("check_conf error\n");
		return 0;
	}
	user_type=0;
	call_type=0;

	invite_user_type=0;
	invite_type=0;

	init_Contextconf(device_info.cfgFile);		//对注册上下文结构的初始化，在opensips中它同样存在

	csenn_eXosip_launch();
	static  char eXosip_server_id[CHARLEN];//           = "34020000001180000002";
	static  char eXosip_server_ip[CHARLEN];//           = "192.168.17.127";//"123456";//
	static  char eXosip_server_port[CHARLEN];//         = "5060";
	static  char eXosip_ipc_id[CHARLEN];//              = "11111";//"34020000001180000002";//
	static  char eXosip_ipc_pwd[CHARLEN];//             = "123456";//"12345678";//
	static  char eXosip_ipc_ip[CHARLEN];//              = "192.168.171.128";
	static  char eXosip_ipc_port[CHARLEN];//            = "5060";

	static  char radius_id[CHARLEN];//            = "5060";
	//static  char sipserver_id[50];//            = "5060";

	get_conf_value( "radius_id" , radius_id , device_info.cfgFile);

	get_conf_value( "server_id" , eXosip_server_id , device_info.cfgFile);
	get_conf_value( "server_ip" , eXosip_server_ip , device_info.cfgFile);
	get_conf_value( "server_port" , eXosip_server_port , device_info.cfgFile);
	get_conf_value( "self_id" , eXosip_ipc_id , device_info.cfgFile);
	get_conf_value( "self_password" , eXosip_ipc_pwd , device_info.cfgFile);
	getNetInfo( eXosip_ipc_ip , NULL );
	get_conf_value( "self_port" , eXosip_ipc_port , device_info.cfgFile);

	char user_type_temp[CHARLEN];
	get_conf_value("self_type",user_type_temp,device_info.cfgFile);

	if(strcmp(user_type_temp,"IPC")==0)
	{
		user_type=USER_TYPE_IPC;
	}
	else if(strcmp(user_type_temp,"CLIENT")==0)
	{
		user_type=USER_TYPE_CLIENT;
	}
	else if(strcmp(user_type_temp,"NVR")==0)
	{
		user_type=USER_TYPE_NVR;
	}

	device_info.server_id           = eXosip_server_id;
	device_info.server_ip           = eXosip_server_ip;
	device_info.server_port         = eXosip_server_port;
	device_info.ipc_id              = eXosip_ipc_id;
	device_info.ipc_pwd             = eXosip_ipc_pwd;
	device_info.ipc_ip              = eXosip_ipc_ip;
	device_info.ipc_port            = eXosip_ipc_port;
	device_info.radius_id           = radius_id;


	//auth_request_packet_data=NULL;

	//csenn_eXosip_callback.csenn_eXosip_getDeviceInfo(&device_info);
	while (csenn_eXosip_init());
	return 1;
}

int uac_register()
{
		int expires=3600;		/* 注册存活时间 */
		int ret = 0;			/* 注册返回值 */
		eXosip_event_t *je  = NULL;	/* 监听到的消息指针 */
		osip_message_t *reg = NULL;	/* 注册的消息体指针 */
		char from[100];/*sip:主叫用户名@被叫IP地址*/
		char proxy[100];/*sip:被叫IP地址:被叫IP端口*/

		memset(from, 0, 100);
		memset(proxy, 0, 100);
		sprintf(from, "sip:%s@%s", device_info.ipc_id, device_info.server_ip);
		sprintf(proxy, "sip:%s:%s", device_info.server_ip, device_info.server_port);

	/*------step 1-----------发送不带认证信息的注册请求-----------------------*/
	retry:
		eXosip_lock();
		g_register_id = eXosip_register_build_initial_register(from, proxy, NULL, expires, &reg);
		char mac[12];
		memset(mac,0,12);
		memcpy(mac,RegisterCon->self_MACaddr.macaddr,sizeof(RegisterCon->self_MACaddr.macaddr));
		//mac[12]='\n';
		//getNetInfo(NULL,mac);//printf("mac:%02x %02x %02x %02x %02x %02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

		codeToChar(mac,sizeof(mac));
		char mac_subject[20];
		sprintf(mac_subject,"MAC:%s\r\n",mac);
		osip_message_set_subject(reg,mac_subject);
		osip_message_set_authorization(reg, "Capability algorithm=\"H:MD5\"");
		if (0 > g_register_id)
		{
			eXosip_lock();
			printf("eXosip_register_build_initial_register error!\r\n");
			return -1;
		}
		printf("eXosip_register_build_initial_register success!\r\n");

		ret = eXosip_register_send_register(g_register_id, reg);
		eXosip_unlock();
		if (0 != ret)
		{
			printf("eXosip_register_send_register no authorization error!\r\n");
			return -1;
		}
		printf("eXosip_register_send_register no authorization success!\r\n");

		printf("g_register_id=%d\r\n", g_register_id);

		for (;;)
		{
			je = eXosip_event_wait(10, 500);/*侦听消息的到来*/

			if (NULL == je)/*没有接收到消息*/
			{
				continue;
			}
			if (EXOSIP_REGISTRATION_FAILURE == je->type)/*注册失败*/
			{
				printf("<EXOSIP_REGISTRATION_FAILURE>\r\n");
				printf("je->rid=%d\r\n", je->rid);
				/*-------step 2---------收到服务器返回的注册失败/401未认证状态------------*/
				if ((NULL != je->response)&&(401 == je->response->status_code))
				{
					AuthActive * auth_active_packet_data=NULL;
					osip_body_t *body;

					osip_header_t * subject;
					osip_message_get_subject(je->response,0,&subject);
					if(subject==NULL)
					{
						printf("no subject\n");
						return 0;
					}
					//printf("subject->hvalue:%s\n",subject->hvalue);
					char mac[12];
					memset(mac, 0, 12);
					memcpy(mac,subject->hvalue,4);
					if(!strcmp(mac,"MAC:"))
					{
						memcpy(mac,subject->hvalue+4,12);
						decodeFromChar(mac,12);
						memcpy(RegisterCon->peer_MACaddr.macaddr,mac,6);
					}
					else
					{
						printf("subject not match\n");
						return 0;
					}

					osip_message_get_body (je->response, 0, &body);
					if(!auth_active_packet_data)
					{
						free(auth_active_packet_data);
						auth_active_packet_data=NULL;
					}
					if((sizeof(AuthActive)*2)>(body->length))
					{
						printf("body->length is not enough");
						return 0;
					}
					auth_active_packet_data=(AuthActive *)malloc (body->length*sizeof(char));
					memcpy(auth_active_packet_data,body->body, body->length);
					decodeFromChar((char*)auth_active_packet_data,body->length);
					if(!HandleWAPIProtocolAuthActive(RegisterCon,auth_active_packet_data))
					{
						printf("HandleWAPIProtocolAuthActive error\n");
						return 0;
					}

					/*
					//printf("message:%s\n",message);
					if(0/*when receive 401Unauthorized package，send ACK and Regester/)
					{
						osip_message_t *ack = NULL;
						int call_id=atoi(reg->call_id->number);
						printf("je->did:%d\n",je->did);
						ret=eXosip_call_build_ack(je->rid,&ack);
						ret=eXosip_call_send_ack(atoi(je->rid),ack);
					}
					*/

					reg = NULL;
					/*----------step 3-------------发送携带认证信息的注册请求----------------------*/
					eXosip_lock();
					eXosip_clear_authentication_info();/*清除认证信息*/
					eXosip_add_authentication_info(device_info.ipc_id, device_info.ipc_id, device_info.ipc_pwd, "MD5", NULL);/*添加主叫用户的认证信息*/
					eXosip_register_build_register(je->rid, expires, &reg);

					if(auth_request_packet_data!=NULL)
					{

						free(auth_request_packet_data);
						auth_request_packet_data=NULL;
					}

					auth_request_packet_data=(AccessAuthRequ*)malloc(sizeof(AccessAuthRequ)*2);

					memset(auth_request_packet_data,0, sizeof(AccessAuthRequ)*2);

					if(ProcessWAPIProtocolAccessAuthRequest(RegisterCon,auth_active_packet_data,auth_request_packet_data)<1)
					{
						printf("ProcessWAPIProtocolAccessAuthRequest error\n");
						return 0;
					}
					codeToChar((char*)auth_request_packet_data,sizeof(AccessAuthRequ)*2);

					//printf("length:%d",(sizeof(AuthActive)*2));
					//printf("length:%d",(sizeof(AccessAuthRequ)*2));
					//printf("length:%d",(sizeof(CertificateAuthRequ)*2));
					//printf("length:%d",sizeof(CertificateAuthResp)*2);
					//printf("length:%d",sizeof(AccessAuthResp)*2);

					osip_message_set_body(reg,(char*)auth_request_packet_data,sizeof(AccessAuthRequ)*2);
					decodeFromChar((char *)auth_request_packet_data,sizeof(AccessAuthRequ)*2);

					ret = eXosip_register_send_register(je->rid, reg);
					eXosip_unlock();
					if (0 != ret)
					{
						printf("eXosip_register_send_register authorization error!\r\n");
						return -1;
					}
					printf("eXosip_register_send_register authorization success!\r\n");
					eXosip_event_free (je);
				}
				else/*真正的注册失败*/
				{
					printf("EXOSIP_REGISTRATION_FAILURE error!\r\n");
					return -1;
					//goto retry;/*重新注册*/
				}
			}
			else if (EXOSIP_REGISTRATION_SUCCESS == je->type)
			{
				/*---------step 6-------------收到服务器返回的注册成功--------------------------------*/

				AccessAuthResp * access_auth_resp_data;
				osip_body_t *body;
				osip_message_get_body (je->response, 0, &body);
				access_auth_resp_data=(AccessAuthResp *)malloc (body->length*sizeof(char));
				memcpy(access_auth_resp_data,body->body, body->length);
				decodeFromChar((char*)access_auth_resp_data,sizeof(AccessAuthResp)*2);

				if(HandleWAPIProtocolAccessAuthResp(RegisterCon,auth_request_packet_data,access_auth_resp_data)<1)
				{
					printf("HandleWAPIProtocolAccessAuthResp error\n");
					return 0;
				}

				g_register_id = je->rid;/*保存注册成功的注册ID*/
				printf("g_register_id=%d\r\n", g_register_id);
				printf("<EXOSIP_REGISTRATION_SUCCESS>\r\n");
				/*
				//send key agreement package  发送密钥协商包
				osip_message_t * inforequest;
				ret=eXosip_message_build_request(&inforequest,"MESSAGE",proxy,from,NULL);
				ret=osip_message_set_body(inforequest,"sssss",6);
				ret=eXosip_message_send_request(inforequest);

				*/
				eXosip_event_free (je);
				break;
			}

		}

		return 0;
}

int uac_invite(sessionId * inviteId,const char *to,const char * sdp_message,char * responseSdp)
{
	//interface 1: do something in playSdp and inviteIp, and open the video transportation
			//char playSdp[4096];
			/*snprintf (playSdp, 4096,
				"v=0\r\n"
				"o=josua  0 0 IN IP4 %s\r\n"
				"s=Play\r\n"
				"c=IN IP4 %s\r\n"
				"t=0 0\r\n"
				"m=audio 8000 RTP/AVP 0 8 101\r\n", device_info.ipc_ip,device_info.ipc_ip);
				*/
			//char inviteIp[100]="34020000001180000002@192.168.17.1:5060";
			//char inviteIp[100]="34020000001310000051@192.168.17.129:5060";
			//end interface 1:

			//char *responseSdp;
			//sessionId inviteId;
			csenn_eXosip_invit(inviteId,to,sdp_message,responseSdp);

			//interface 2: do something with responseSdp ;
			//printf("main return sdp:%s \n",responseSdp);
			//end interface 2:
	return 0;
}

int uac_bye(const sessionId Id)
{
	eXosip_lock();
	eXosip_call_terminate( Id.cid, Id.did);
	eXosip_unlock();
	eXosip_event_t *g_event  = NULL;/*消息事件*/
	uac_waitfor(&Id,EXOSIP_CALL_MESSAGE_ANSWERED,&g_event);
	if(!g_event)
	{
		printf("no bye response\n");
		return 0;
	}
	eXosip_event_free (g_event);
	return 1;
	}

int uac_send_info(const sessionId Id)
{
	osip_message_t *info;
	char info_body[1000];
	int i;
	eXosip_lock ();
	i = eXosip_call_build_info (Id.did, &info);
	if (i == 0)
	{
		snprintf (info_body, 999, "Signal=sss\r\nDuration=250\r\n");
		osip_message_set_content_type (info, "Application/MANSRTSP");
		osip_message_set_body (info, info_body, strlen (info_body));
		i = eXosip_call_send_request (Id.did, info);
	}
	else
	{
		printf("eXosip_call_build_info error\n");
		return 0;
	}
	eXosip_unlock ();

	//成功时返回的i可能是0，如果是0则需要修改，后续在测试修改
	return i;
}

int uac_send_message(const sessionId Id, const alter_message * alter_m)
{
	osip_message_t *message;
	int i;
	eXosip_lock ();
	i = eXosip_call_build_request (Id.did,alter_m->method_type/*"MESSAGE" or "INFO"*/, &message);
	if (i == 0)
	{
		if(alter_m->content_type!=NULL)
		osip_message_set_content_type (message, alter_m->content_type/*"Application/MANSRTSP"*/);
		if(alter_m->subject!=NULL)
		osip_message_set_subject(message,alter_m->subject);
		osip_message_set_body (message, alter_m->body, strlen (alter_m->body));
		i = eXosip_call_send_request (Id.did, message);
	}
	eXosip_unlock ();

	return i;
}

int uac_send_noSessionMessage(const sip_entity* to_, const alter_message * alter_m)
{//,char * to, char * from, char * route,char * content,char * subject
	osip_message_t *message;
	char from[4+CHARLEN+1+15+1+4+1];
	char to[4+CHARLEN+1+15+1+4+1];
	snprintf(from,sizeof(from),"sip:%s@%s:%s",device_info.ipc_id,device_info.ipc_ip,device_info.ipc_port);
	snprintf(to,sizeof(to),"sip:%s@%s:%d",to_->username,to_->ip,to_->port);
	eXosip_lock ();
	eXosip_message_build_request (&message, alter_m->method_type, to,from, alter_m->route);

	if(alter_m->subject!=NULL)
	osip_message_set_subject(message,alter_m->subject);
	osip_message_set_body(message,alter_m->body,strlen(alter_m->body));
	osip_message_set_content_type(message,alter_m->content_type);
	eXosip_message_send_request(message);

	eXosip_unlock ();
	return 1;
	}

int uac_waitfor(const sessionId* id, const eXosip_event_type_t t,eXosip_event_t **event)
{
	eXosip_event_t *g_event  = NULL;/*消息事件*/
	while(1)
	{
	/*等待新消息的到来*/
		g_event = eXosip_event_wait(0, 50);/*侦听消息的到来*/
		eXosip_lock();
		eXosip_default_action(g_event);
		eXosip_automatic_refresh();/*Refresh REGISTER and SUBSCRIBE before the expiration delay*/
		eXosip_unlock();
		if ( g_event == NULL)
		{
			continue;
		}
		if(g_event->request==NULL)
		{
			continue;
		}

		if(id!=NULL && strcmp(id->call_id,g_event->request->call_id->number))
		{
			printf("id->call_id:%s g_event->request->call_id->number:%s\n",
					id->call_id, g_event->request->call_id->number);
			printf("id!=NULL &&\n");
			continue;
		}
		if(g_event->type==EXOSIP_CALL_RINGING || g_event->type==EXOSIP_MESSAGE_ANSWERED)
		{
			continue;
		}
		if(g_event->type==t)
		{
			(*event)=g_event;
			return 1;
		}
		else
		{
			(*event)=g_event;
			return 0;
		}
	}

	if(event==NULL)
	{
		printf("no response\n\n");
		return 0;
	}

	return 0;
}

int uac_sendInvite(sessionId * id, const sip_entity* to, const alter_message * alter_m)
{// char * to, char * message, char *meessageType,char *subject
	osip_message_t *invite;
	int i;// optionnal route header
	char to_[100];
	snprintf (to_, 100,"sip:%s@%s", to->username,to->ip);
	char from_[100];
	snprintf (from_, 100,"sip:%s@%s:%s",device_info.ipc_id, device_info.ipc_ip ,device_info.ipc_port );

	i = eXosip_call_build_initial_invite (&invite,to_,from_,NULL,alter_m->subject );

	if (i != 0)
	{
	return -1;
	}
	//osip_message_set_supported (invite, "100rel");
	{
	char localip[128];
	eXosip_guess_localip (AF_INET, localip, 128);

	i=osip_message_set_body (invite, alter_m->body, strlen (alter_m->body));
	i=osip_message_set_content_type (invite, alter_m->content_type);
	}
	eXosip_lock ();
	i = eXosip_call_send_initial_invite (invite);
	eXosip_unlock ();
	//printf("invite->call_id->number:%s size:%d\n",invite->call_id->number,strlen(invite->call_id->number));
	//id->call_id=(char *)malloc(sizeof(char)*(strlen(invite->call_id->number)+1));
	int copynum=0;
	if(sizeof(id->call_id)>(strlen(invite->call_id->number)+1))
	{
		copynum=(strlen(invite->call_id->number)+1);
	}
	else
	{
		copynum=sizeof(id->call_id);
	}
	memcpy(id->call_id,invite->call_id->number,copynum);//strlen(invite->call_id->number)+1);
	//if (i > 0)
	//{
	//eXosip_call_set_reference (i, "ssss");
	//}

	return 0;

}


int uac_key_nego()
{
	eXosip_event_t *g_event;
	osip_header_t * subject;
	char to[100];
	char from[100];

	//key_nego 1
	snprintf(to, 50,"sip:%s@%s:%s",device_info.ipc_id,device_info.server_ip,device_info.server_port);
	snprintf(from, 50,"sip:%s@%s:%s",device_info.ipc_id,device_info.server_ip,device_info.server_port);
	//uac_send_noSessionMessage(to,from, NULL,"this is no KEY_NAGO1 message","KEY_NAGO1\n");
	sessionId id;
	sip_entity target;
	memset(&target,0,sizeof(target));
	sprintf(target.ip, "%s", device_info.server_ip);
	target.port=atoi(device_info.server_port);
	sprintf(target.username, "%s", device_info.ipc_id);
	alter_message invite_message;
	memset(&invite_message,0,sizeof(alter_message));
	invite_message.body="this is KEY_NAGO1 message";
	invite_message.content_type=CONTENT_CODE;
	invite_message.subject="KEY_NAGO1\n";
	uac_sendInvite(&id,&target,&invite_message);
	//uac_sendInvite(&id,to,"this is no KEY_NAGO1 message","text/code","KEY_NAGO1\n");
	//printf("uac_sendInvite sucess\n");
	uac_waitfor(&id,EXOSIP_CALL_ANSWERED,&g_event);
	if(g_event==NULL)
	{
		printf("no response\n\n");
		return 0;
	}
	id.cid=g_event->cid;
	id.did=g_event->did;
	if(g_event->type!= EXOSIP_CALL_ANSWERED )//&& g_event->type!=EXOSIP_CALL_MESSAGE_ANSWERED)
	{
		//if(g_event->response )
			//printf("g_event->response->message:\n");
		//if(g_event->response->call_id)
		//printf("g_event->response->call_id->number:%s\n",g_event->response->call_id->number);
		printf("g_event->type:%d\n",g_event->type);
		printf("g_event->cid:%d\n",g_event->cid);
		printf("not the right response\n");
		return 0;
	}
	osip_message_t *ack = NULL;
	eXosip_call_build_ack (id.did, &ack);
	if(eXosip_call_send_ack (id.did, ack)!=0)
	{
		printf("send_ack error\n");
		return 0;
	}

	osip_message_get_subject(g_event->response,0,&subject);
	if(subject==NULL)
	{
		printf("no subject\n");
		return 0;
	}
	//printf("subject->hvalue:%s\n",subject->hvalue);
	if(!strcmp(subject->hvalue,"KEY_NAGO2"))
	{
		//do something handle the KEY_NAGO2
		osip_body_t *body;
		osip_message_get_body (g_event->response, 0, &body);//body
		UnicastKeyNegoRequ *unicast_key_nego_requ_packet_c=(UnicastKeyNegoRequ*)malloc (sizeof(UnicastKeyNegoRequ)*2);
		if(body->length < sizeof(UnicastKeyNegoRequ)*2)
		{
			printf("not valid length");
			free(unicast_key_nego_requ_packet_c);
			return 0;
		}
		memcpy(unicast_key_nego_requ_packet_c,body->body, sizeof(UnicastKeyNegoRequ)*2);
		decodeFromChar(unicast_key_nego_requ_packet_c,sizeof(UnicastKeyNegoRequ)*2);

		if(HandleUnicastKeyNegoRequest(RegisterCon, unicast_key_nego_requ_packet_c)<1)
		{
			printf("HandleUnicastKeyNegoRequest error\n");
			free(unicast_key_nego_requ_packet_c);
			return 0;
		}

		id.cid=g_event->cid;
		id.did=g_event->did;
		osip_message_t *ack = NULL;
		printf("id.cid:%d id.did:%d",id.cid,id.did);
		//eXosip_call_build_ack (id.did, &ack);
		//eXosip_call_send_ack (id.cid, ack);
		free(unicast_key_nego_requ_packet_c);
		eXosip_event_free (g_event);
	}
	else
	{
		printf("not KEY_NAGO2\n");
		printf("g_event->cid:%d\n",g_event->cid);
		eXosip_event_free (g_event);
		return 0;

	}
	g_event=NULL;
	UnicastKeyNegoResp *unicast_key_nego_resp_packet_c=(UnicastKeyNegoResp*)malloc (sizeof(UnicastKeyNegoResp)*2);
	if(ProcessUnicastKeyNegoResponse(RegisterCon, unicast_key_nego_resp_packet_c)<1)
	{
		printf("ProcessUnicastKeyNegoResponse error\n");
		free(unicast_key_nego_resp_packet_c);
		return 0;
	}
	codeToChar(unicast_key_nego_resp_packet_c,sizeof(UnicastKeyNegoResp)*2);

	//key_nego 3
	alter_message key_nego_message;
	memset(&key_nego_message,0,sizeof(alter_message));
	key_nego_message.body=unicast_key_nego_resp_packet_c;
	key_nego_message.method_type=METHODMESSAGE;
	key_nego_message.content_type=CONTENT_CODE;
	key_nego_message.subject="KEY_NAGO3";

	if(uac_send_message(id,&key_nego_message)!=0)
	{
		printf("uac_send_message error\n");
		free(unicast_key_nego_resp_packet_c);
		return 0;
	}
	free(unicast_key_nego_resp_packet_c);
	if(!uac_waitfor(&id,EXOSIP_CALL_MESSAGE_ANSWERED,&g_event))
	{
		printf("g_event->type:%d\n",g_event->type);
		printf("g_event->cid:%d\n",g_event->cid);
		printf("not the right response\n");
		return 0;
	}
	if(g_event==NULL)
	{
		printf("no response\n\n");
		return 0;
	}
	osip_message_get_subject(g_event->response,0,&subject);
	//printf("subject->hvalue:%s",subject->hvalue);
	if(!strcmp(subject->hvalue,"KEY_NAGO4"))
	{
		//do something handle the KEY_NAGO 4
		osip_body_t *body;
		osip_message_get_body (g_event->response, 0, &body);
		UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet_c=(UnicastKeyNegoConfirm*)malloc (sizeof(UnicastKeyNegoConfirm)*2);
		if(body->length < sizeof(UnicastKeyNegoConfirm)*2)
		{
			printf("not valid length");
			free(unicast_key_nego_confirm_packet_c);
			return 0;
		}
		memcpy(unicast_key_nego_confirm_packet_c,body->body, sizeof(UnicastKeyNegoConfirm)*2);
		//free(body);
		decodeFromChar(unicast_key_nego_confirm_packet_c,sizeof(UnicastKeyNegoConfirm)*2);

		if(HandleUnicastKeyNegoConfirm(RegisterCon, unicast_key_nego_confirm_packet_c)<1)
		{
			printf("HandleUnicastKeyNegoConfirm error\n");
			free(unicast_key_nego_confirm_packet_c);
			return 0;
		}

		free(unicast_key_nego_confirm_packet_c);
		eXosip_event_free (g_event);
		uac_bye(id);

		//return 1;
	}
	else
	{
		printf("not KEY_NAGO4\n");
		//printf("g_event->cid:%d\n",g_event->cid);
		eXosip_event_free (g_event);
		uac_bye(id);
		return 0;
	}
	//if it is NVR , it will wait for IPC access
	//if(!strcmp(device_info.ipc_port,"5063"))
	//{
		//user_type=NVR;
		//printf("user_type is NVR\n");
	//}
	/*
	if(user_type==NVR)
	{
		eXosip_event_t *event;
		uac_waitfor(NULL, EXOSIP_MESSAGE_NEW,&event);
		if(event==NULL)
		{
			printf("not the right response\n");
			return 0;
		}
		if(HandleP2PKeyDistribution_request(event)<1)
		{
			printf("HandleP2PKeyDistribution_request error\n");
			return 0;
		}
	}
*/
	printf("uac_key_nego-----finished\n");
	return 1;
}

int uac_key_distribute(const char *peer_id, sip_entity *sip_target)
{


	eXosip_event_t *g_event;
	osip_header_t * subject;
	char to[100];
	char from[100];

	//key_nego 1
	//snprintf(to, 50,"sip:%s@%s:%s",device_info.server_id,device_info.server_ip,device_info.server_port);
	//char peer_id[CHARLEN]="user2";
	snprintf(to, 50,"sip:%s@%s:%s",peer_id,device_info.server_ip,device_info.server_port);
	snprintf(from, 50,"sip:%s@%s:%s",device_info.ipc_id,device_info.ipc_ip,device_info.ipc_port);
	//uac_send_noSessionMessage(to,from, NULL,"peer userid:user2\n","KEY_DISTRIBUTE1\n");

	sessionId id;
	sip_entity sip_server;
	memset(&sip_server,0,sizeof(sip_server));
	sprintf(sip_server.ip, "%s", device_info.server_ip);
	sip_server.port=atoi(device_info.server_port);
	sprintf(sip_server.username, "%s", peer_id);

	alter_message invite_message;
	memset(&invite_message,0,sizeof(alter_message));
	invite_message.body="peer userid:user2\n";
	invite_message.content_type=CONTENT_CODE;
	invite_message.subject="KEY_DISTRIBUTE1\n";
	uac_sendInvite(&id,&sip_server,&invite_message);
	/*------------------finish send the invite request----------------------*/


	//printf("uac_sendInvite sucess\n");
	uac_waitfor(&id,EXOSIP_CALL_ANSWERED,&g_event);
	if(g_event==NULL)
	{
		printf("no response\n\n");
		return 0;
	}
	id.cid=g_event->cid;
	id.did=g_event->did;
	if(g_event->type!= EXOSIP_CALL_ANSWERED )//&& g_event->type!=EXOSIP_CALL_MESSAGE_ANSWERED)
	{
		printf("g_event->type:%d\n",g_event->type);
		printf("g_event->cid:%d\n",g_event->cid);
		printf("not the right response\n");
		return 0;
	}
	/*------------------finish receive the  response----------------------*/


	osip_message_t *ack = NULL;
	eXosip_call_build_ack (id.did, &ack);
	if(eXosip_call_send_ack (id.did, ack))
	{
		printf("send_ack error\n");
		return 0;
	}
	/*------------------finish send the ack response----------------------*/
	printf("before HandleP2PKeyDistribution_request\n");
	if(HandleP2PKeyDistribution_request(g_event)<1)
	{
		printf("HandleP2PKeyDistribution_request error\n");
		id.cid=g_event->cid;
		id.did=g_event->did;
		memcpy(id.call_id,g_event->request->call_id->number,sizeof(id.call_id));
		eXosip_event_free (g_event);
		uac_bye(id);
		return 0;
	}
	id.cid=g_event->cid;
	id.did=g_event->did;
	memcpy(id.call_id,g_event->request->call_id->number,sizeof(id.call_id));
	eXosip_event_free (g_event);
	uac_bye(id);

	int LinkNum;
	LinkNum=getSecureLinkNum(&Securelinks, p2pcc->peer_id);
	if(LinkNum<0)
	{
		printf("No secure link information with %s!\n ", p2pcc->peer_id);
		return 0;
	}
	memcpy(sip_target->ip,Securelinks.links[LinkNum].partner_ip/*"192.168.17.127"*/
			,sizeof(sip_target->ip));
	sip_target->port=5063;//this will modify later
	memcpy(sip_target->username,p2pcc->peer_id,sizeof(sip_target->username));

	printf("uac_key_distribute-----finished\n");
	return 1;
}

int HandleP2PKeyDistribution_request(const eXosip_event_t *g_event)
{
	osip_header_t * subject;
	osip_message_t *message;
	if(g_event->response!=NULL)
	{
		message=g_event->response;
	}
	else if(g_event->request!=NULL)
	{
		message=g_event->request;
	}
	else
	{
		printf("no right response or request in HandleP2PKeyDistribution_request\n");
		return 0;
	}
	osip_message_get_subject(message,0,&subject);
	if(subject==NULL)
	{
		printf("no subject\n");
		return 0;
	}
	printf("subject->hvalue:%s\n",subject->hvalue);
	P2PLinkContext *lc;
	if(!strcmp(subject->hvalue,"KEY_DISTRIBUTE2"))
	{
		osip_body_t *body;
		osip_message_get_body (message, 0, &body);
		P2PKeyDistribution *p2p_key_dist_packet=(P2PKeyDistribution *)malloc(sizeof(P2PKeyDistribution)*2);
		if(body->length < sizeof(P2PKeyDistribution)*2)
		{
			printf("not valid length");
			free(p2p_key_dist_packet);
			return 0;
		}
		memcpy(p2p_key_dist_packet,body->body, sizeof(P2PKeyDistribution)*2);
		//free(body);
		decodeFromChar(p2p_key_dist_packet,sizeof(P2PKeyDistribution)*2);

		//do something handle the KEY_DISTRIBUTE2

		lc=(P2PLinkContext *)malloc(sizeof(P2PLinkContext));


		//为了避免register 的一个认证bug，该bug于radius有关，现暂时增加这条语句
		/*
		char value[CHARLEN];
		get_conf_value( "self_type", value,device_info.cfgFile);
		if(strcmp(value,"NVR")==0)
		{
			Self_type=NVR;

		}**/
		//----------------------------

		// 需要改进，因为可能是Client于NVR进行通信
		if(user_type==IPC)
		{
			P2PLinkContext_Conversion_C(RegisterCon, lc, NVR);
		}
		else if(user_type==NVR)
		{
			P2PLinkContext_Conversion_C(RegisterCon, lc, IPC);
		}
		else
			printf("user_type:%d",user_type);

		if(HandleP2PKeyDistribution(lc, p2p_key_dist_packet)<1)
		{
			printf("HandleP2PKeyDistribution error\n");
			free(lc);
			return 0;
		}
		if(p2pcc!=NULL)
		{
			free(p2pcc);
		}
		p2pcc=(P2PCommContext *)malloc(sizeof(P2PCommContext));
		P2PCommContext_Conversion(lc,p2pcc);
		free(lc);
		return 1;
	}
	else
	{
		printf("not KEY_DISTRIBUTE2\n");
		return 0;
	}


}

int uac_token_exchange(const sip_entity* to,const TokenType toketype_)
{
	eXosip_event_t *event;
	if(send_token(to,toketype_)<1)
	{
		printf("send_token error\n");
		return 0;
	}
	if(uac_waitfor(NULL,EXOSIP_MESSAGE_NEW,&event)<1)
	{
		printf("uac_waitfor error event->type:%d\n",event->type);
		return 0;
	}
	if(handle_token(event->request,toketype_)<1)
	{
		printf("handle_token error\n");
		return 0;
	}
	osip_message_t *g_answer = NULL;/*请求的确认型应答*/
	eXosip_lock();
	eXosip_message_build_answer(event->tid, 200, &g_answer);/*Build default Answer for request*/
	eXosip_message_send_answer(event->tid, 200, g_answer);/*按照规则回复200OK*/
	eXosip_unlock();

	printf("uac_token_exchange-----finished\n");
	return 1;
	}

int send_token(const sip_entity* to, const TokenType toketype_)
{
	char *token=(char *)malloc(sizeof(P2PAuthToken)*2);
	int i=0;
	char *subject;
	switch(toketype_)
	{
	case Auth:
		i=ProcessP2PAuthToken(p2pcc, token);
		subject=P2PAUTH_SUBJECT;
		break;
	case Reauth:
		i=ProcessP2PReauthToken(p2pcc, token);
		subject=P2PREAUTH_SUBJECT;
		break;
	case Byesession:
		i=ProcessP2PByeSessionToken(p2pcc, token);
		subject=P2PBYESESSION_SUBJECT;
		break;
	case Byelink:
		i=ProcessP2PByeLinkToken(p2pcc, token);
		subject=P2PBYELINK_SUBJECT;
		break;
	default:
		printf("TokenType error\n");
		return 0;
		break;
	}
	if(i<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}
	codeToChar(token,sizeof(P2PAuthToken)*2);
	alter_message p2pauth_message;
	memset(&p2pauth_message,0,sizeof(alter_message));
	p2pauth_message.body=token;
	p2pauth_message.method_type=METHODMESSAGE;
	p2pauth_message.content_type=CONTENT_CODE;
	p2pauth_message.subject=subject;
	uac_send_noSessionMessage(to, &p2pauth_message);
	return 1;
}
int handle_token(const osip_message_t *sip_message, const TokenType toketype_)
{
	osip_body_t *body;
	osip_message_get_body (sip_message, 0, &body);//body
	P2PAuthToken *token_request=(P2PAuthToken *)malloc(sizeof(P2PAuthToken)*2);
	if(body->length < sizeof(P2PAuthToken)*2)
	{
		printf("not valid length");
		free(token_request);
		return 0;
	}
	memcpy(token_request,body->body, sizeof(P2PAuthToken)*2);
	decodeFromChar(token_request,sizeof(P2PAuthToken)*2);

	int i=0;
	switch(toketype_)
	{
	case Auth:
		i=HandleP2PAuthToken(p2pcc, token_request);
		break;
	case Reauth:
		i=HandleP2PReauthToken(p2pcc, token_request);
		break;
	case Byesession:
		i=HandleP2PByeSessionToken(p2pcc, token_request);
		break;
	case Byelink:
		i=HandleP2PByeLinkToken(p2pcc, token_request);
		break;
	default:
		printf("TokenType error\n");
		return 0;
		break;
	}
	if(i<1)
	{
		printf("ProcessP2PAuthToken error\n");
		return 0;
	}

	return 1;
}

int getSipEntity(sip_entity * target_sip, const osip_message_t *sip_message)
{
	//sip_entity target_sip;
	//printf("event->request->from->url->host:%s",sip_message->from->url->host);
	memcpy(target_sip->ip,sip_message->from->url->host,sizeof(target_sip->ip));
	//printf("event->request->from->url->port:%s",sip_message->from->url->port);
	target_sip->port=atoi(sip_message->from->url->port);
	memcpy(target_sip->username,sip_message->from->url->username,sizeof(target_sip->username));
	//printf("target_sip.username:%s",target_sip->username);
	return 1;
	}

int uac_videotransmit_ipc2nvr(sip_entity * target_sip)
{
	sessionId inviteId;
	char send_sdp_data[1024];
	char recieve_sdp_data[1024];
	call_type=CALL_TYPE_PLAY;
	uac_get_Playsdp(send_sdp_data);
	char default_invite[100];
	sprintf(default_invite,"%s@%s:%d",target_sip->username,target_sip->ip,target_sip->port);
	//get_conf_value("default_invite",default_invite,device_info.cfgFile);
	//printf("default_invite:%s\n",default_invite);
	if(!1/**/)
	{
		printf("the link is not build\n");
		return 0;
	}
	uac_invite(&inviteId,default_invite,//"34020000001310000051@192.168.17.1:5060",---
			send_sdp_data,recieve_sdp_data);

	uac_handle_Playsdp(recieve_sdp_data);
	//uac_receive_Playmedia();
	//uac_start_media(target_sip->ip);

	return 1;
}
