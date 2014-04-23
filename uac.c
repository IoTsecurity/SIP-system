/*
 * uac.c
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */

#include "csenn_eXosip2.h"
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

#define CONTENT_TYPE "text/code"

int uac_init()
{
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
			return 0;
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
		getNetInfo(NULL,mac);//printf("mac:%02x %02x %02x %02x %02x %02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
		codeToChar(mac,sizeof(mac));
		char mac_subject[20];
		sprintf(mac_subject,"MAC:%s\n",mac);
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
					printf("subject->hvalue:%s\n",subject->hvalue);
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
					printf("body->length:%d\n",body->length);
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

					if(!auth_request_packet_data)
					{

						free(auth_request_packet_data);
						auth_request_packet_data=NULL;
					}

					auth_request_packet_data=(AccessAuthRequ*)malloc(sizeof(AccessAuthRequ)*2);

					memset(auth_request_packet_data,0, sizeof(AccessAuthRequ)*2);

					if(!ProcessWAPIProtocolAccessAuthRequest(RegisterCon,auth_active_packet_data,auth_request_packet_data))
					{
						printf("ProcessWAPIProtocolAccessAuthRequest error\n");
						return 0;
					}
					codeToChar((char*)auth_request_packet_data,sizeof(AccessAuthRequ)*2);

					printf("length:%d",(sizeof(AuthActive)*2));
					printf("length:%d",(sizeof(AccessAuthRequ)*2));
					printf("length:%d",(sizeof(CertificateAuthRequ)*2));
					printf("length:%d",sizeof(CertificateAuthResp)*2);
					printf("length:%d",sizeof(AccessAuthResp)*2);

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

				break;
			}

		}

		return 0;
}

int uac_invite(sessionId * inviteId,char *to,char * sdp_message,char * responseSdp)
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

int uac_bye(sessionId inviteId)
{
	eXosip_lock();
	eXosip_call_terminate( inviteId.cid, inviteId.did);
	eXosip_unlock();
	eXosip_event_t *g_event  = NULL;/*消息事件*/
	uac_waitfor(&inviteId,EXOSIP_CALL_MESSAGE_ANSWERED,&g_event);
	if(!g_event)
	{
		printf("no bye response\n");
	}

	eXosip_event_free (g_event);
	return 1;
	}

int uac_send_info(sessionId inviteId)
{
	osip_message_t *info;
	char info_body[1000];
	int i;
	eXosip_lock ();
	i = eXosip_call_build_info (inviteId.did, &info);
	if (i == 0)
	{
		snprintf (info_body, 999, "Signal=sss\r\nDuration=250\r\n");
		osip_message_set_content_type (info, "Application/MANSRTSP");
		osip_message_set_body (info, info_body, strlen (info_body));
		i = eXosip_call_send_request (inviteId.did, info);
	}
	eXosip_unlock ();
	return i;
}

int uac_send_message(sessionId inviteId,alter_message * alter_m)
{//, char * message_type ,char * context_type,char * message_str,char * subject
	osip_message_t *message;
	int i;
	eXosip_lock ();
	i = eXosip_call_build_request (inviteId.did,alter_m->method_type/*"MESSAGE" or "INFO"*/, &message);
	if (i == 0)
	{
		//snprintf (message_body, 999, message_str/*"message_info"*/);
		if(alter_m->content_type!=NULL)
		osip_message_set_content_type (message, alter_m->content_type/*"Application/MANSRTSP"*/);
		if(alter_m->subject!=NULL)
		osip_message_set_subject(message,alter_m->subject);
		osip_message_set_body (message, alter_m->body, strlen (alter_m->body));
		i = eXosip_call_send_request (inviteId.did, message);
	}
	eXosip_unlock ();

	return i;
}

int uac_send_noSessionMessage(sip_entity* to, alter_message * alter_m)
{//,char * to, char * from, char * route,char * content,char * subject
	osip_message_t *message;
	char from[4+CHARLEN+1+15+1+4+1];
	snprintf(from,"sip:%s@%s:%s",device_info.ipc_id,device_info.ipc_ip,device_info.ipc_port);
	eXosip_lock ();
	eXosip_message_build_request (&message, "MESSAGE", to,from, alter_m->route);
	printf("message->sip_version:%s \n",message->sip_version);
	printf("eXosip_message_build_request end \n");

	if(alter_m->subject!=NULL)
	osip_message_set_subject(message,alter_m->subject);

	osip_message_set_body(message,alter_m->body,strlen(alter_m->body));
	printf("osip_message_set_body end \n");
	osip_message_set_content_type(message,"text/code");
	printf("osip_message_set_content_type end \n");
	eXosip_message_send_request(message);
	printf("eXosip_message_send_request end \n");
	eXosip_unlock ();
	return 1;
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
	invite_message.body="this is KEY_NAGO1 message";
	invite_message.content_type="text/code";
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
	if(!eXosip_call_send_ack (id.did, ack))
	{
		printf("send_ack success\n");
	}

	osip_message_get_subject(g_event->response,0,&subject);
	if(subject==NULL)
	{
		printf("no subject\n");
		return 0;
	}
	printf("subject->hvalue:%s\n",subject->hvalue);
	if(!strcmp(subject->hvalue,"KEY_NAGO2"))
	{
		//do something handle the KEY_NAGO2
		osip_body_t *body;
		osip_message_get_body (g_event->response, 0, &body);
		UnicastKeyNegoRequ *unicast_key_nego_requ_packet_c=(UnicastKeyNegoRequ*)malloc (sizeof(UnicastKeyNegoRequ)*2);
		if(body->length < sizeof(UnicastKeyNegoRequ)*2)
		{
			printf("not valid length");
			free(unicast_key_nego_requ_packet_c);
			return 0;
		}
		memcpy(unicast_key_nego_requ_packet_c,body->body, body->length);
		free(body);
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
		printf("KEY_NAGO2 success\n");
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
	key_nego_message.body=unicast_key_nego_resp_packet_c;
	key_nego_message.method_type="MESSAGE";
	key_nego_message.content_type="text/code";
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
	printf("subject->hvalue:%s",subject->hvalue);
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
		memcpy(unicast_key_nego_confirm_packet_c,body->body, body->length);
		free(body);
		decodeFromChar(unicast_key_nego_confirm_packet_c,sizeof(UnicastKeyNegoConfirm)*2);

		if(HandleUnicastKeyNegoConfirm(RegisterCon, unicast_key_nego_confirm_packet_c)<1)
		{
			printf("HandleUnicastKeyNegoConfirm error\n");
			free(unicast_key_nego_confirm_packet_c);
			return 0;
		}

		printf("KEY_NAGO4 sucess\n");
		eXosip_event_free (g_event);
		uac_bye(id);
		return 0;
	}
	else
	{
		printf("not KEY_NAGO4\n");
		//printf("g_event->cid:%d\n",g_event->cid);
		eXosip_event_free (g_event);
		uac_bye(id);
		return 0;
	}

	return 1;
}

int uac_key_distribute()
{
	eXosip_event_t *g_event;
	osip_header_t * subject;
	char to[100];
	char from[100];

	//key_nego 1
	//snprintf(to, 50,"sip:%s@%s:%s",device_info.server_id,device_info.server_ip,device_info.server_port);
	char peer_id[CHARLEN]="user2";
	snprintf(to, 50,"sip:%s@%s:%s",peer_id,device_info.server_ip,device_info.server_port);
	snprintf(from, 50,"sip:%s@%s:%s",device_info.ipc_id,device_info.ipc_ip,device_info.ipc_port);
	//uac_send_noSessionMessage(to,from, NULL,"peer userid:user2\n","KEY_DISTRIBUTE1\n");

	sessionId id;
	sip_entity target;
	memset(&target,0,sizeof(target));
	sprintf(target.ip, "%s", device_info.server_ip);
	target.port=atoi(device_info.server_port);
	sprintf(target.username, "%s", peer_id);

	alter_message invite_message;
	invite_message.body="peer userid:user2\n";
	invite_message.content_type="text/code";
	invite_message.subject="KEY_DISTRIBUTE1\n";
	uac_sendInvite(&id,&target,&invite_message);

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
	if(!eXosip_call_send_ack (id.did, ack))
	{
		printf("send_ack success\n");
	}

	osip_message_get_subject(g_event->response,0,&subject);
	if(subject==NULL)
	{
		printf("no subject\n");
		return 0;
	}
	printf("subject->hvalue:%s\n",subject->hvalue);
	if(!strcmp(subject->hvalue,"KEY_DISTRIBUTE2"))
	{
		//do something handle the KEY_DISTRIBUTE2
		id.cid=g_event->cid;
		id.did=g_event->did;
		osip_message_t *ack = NULL;
		printf("id.cid:%d id.did:%d",id.cid,id.did);
		printf("KEY_DISTRIBUTE2 success\n");
		eXosip_event_free (g_event);
		uac_bye(id);
	}
	else
	{
		printf("not KEY_DISTRIBUTE2\n");
		printf("g_event->cid:%d\n",g_event->cid);
		eXosip_event_free (g_event);
		uac_bye(id);
		return 0;

	}
	return 1;
}

int uac_waitfor(sessionId* id, eXosip_event_type_t t,eXosip_event_t **event)
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
		if (NULL == g_event)
		{
			continue;
		}
		if(g_event->request==NULL)
		{
			continue;
		}
		//printf("id.call_id:%s\n",id.call_id);
		//printf("g_event->request->call_id->number:%s\n",g_event->request->call_id->number);
		if(id!=NULL && strcmp(id->call_id,g_event->request->call_id->number))
		{
			//printf("enter0\n");
			continue;
		}
		if(g_event->type==EXOSIP_CALL_RINGING)
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
	return 0;
}

int uac_sendInvite(sessionId * id, sip_entity* to, alter_message * alter_m)
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
	localip[128]=device_info.ipc_ip;//需要修改

	i=osip_message_set_body (invite, alter_m->body, strlen (alter_m->body));
	i=osip_message_set_content_type (invite, alter_m->content_type);
	}
	eXosip_lock ();
	i = eXosip_call_send_initial_invite (invite);
	eXosip_unlock ();
	//printf("invite->call_id->number:%s size:%d\n",invite->call_id->number,strlen(invite->call_id->number));
	//id->call_id=(char *)malloc(sizeof(char)*(strlen(invite->call_id->number)+1));
	memcpy(id->call_id,invite->call_id->number,strlen(invite->call_id->number)+1);

	//if (i > 0)
	//{
	//eXosip_call_set_reference (i, "ssss");
	//}

	return 0;

}

int uac_token_exchange(sip_entity * target)
{

	char to[100];
	char from[100];

	//key_nego 1
	//sprintf(to,"sip:%s@%s:%d",target->username,target->ip,target->port);
	//sprintf(from, "sip:%s@%s:%s",device_info.ipc_id,device_info.ipc_ip,device_info.ipc_port);
	//uac_send_noSessionMessage(to,from, NULL,"this is no KEY_NAGO1 message","KEY_NAGO1\n");

	alter_message token_mess;
	token_mess.body="this is no session message";
	token_mess.subject="Token Exchange1\n";
	uac_send_noSessionMessage(target,&token_mess);
	eXosip_event_t *event;
	uac_waitfor(NULL, EXOSIP_MESSAGE_NEW,&event);

	if(event==NULL)
	{
		printf("other response\n");
		return -1;
	}
	osip_body_t *message_body = NULL;
	osip_message_get_body(event->request, 0, &message_body);
	printf("message_body->body:%s\n",message_body->body);


	return 1;
}

int init_conf(char * file)
{
	int fd=open(file,O_RDONLY);
	    if(fd>2){   //确保文件存在
	    	static  char * cfgFile ;
	    	cfgFile=(char *)malloc(sizeof(char)*30);
	    	strcpy(cfgFile,file);
	    	device_info.cfgFile=cfgFile;
	        close(fd);
	        printf("open config file:%s success\n",file);
	    }
	    else{
	       printf("can not open config file:%s\n",file);
	       exit(1);
	    }
	return 0;
	}

