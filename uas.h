#include "csenn_eXosip2.h"
#include <pthread.h>
#include "interface.h"
#ifndef UAS_H
#define UAS_H

int handle_invite(eXosip_event_t * g_event)
{
	int length;
	char * message;
	//osip_message_to_str(g_event->request, &message, &length);
	osip_body_t *body;
	osip_message_get_body (g_event->request, 0, &body);
	message=(char *)malloc (body->length*sizeof(char));
	snprintf (message, body->length,"%s", body->body);

	//identify the invite_user_type and invite_type from the sdp
	invite_user_type=INVITE_USER_TYPE_CLIENT;
	invite_type=INVITE_TYPE_PLAY;


	//interface do somthing with the sdp
	//function_run(uas_handle_invite_sdp,message);
	//uas_function_run(uas_handle_invite_sdp,message);
	uas_handle_sdp(message);
	//end interface


	if(MSG_IS_INVITE(g_event->request))/*使用INVITE方法的请求*/
	{
		/*实时视音频点播*/
		/*历史视音频回放*/
		/*视音频文件下载*/
		osip_message_t *asw_msg = NULL;/*请求的确认型应答*/


		eXosip_lock();
		if(0 != eXosip_call_build_answer(g_event->tid, 200, &asw_msg))/*Build default Answer for request*/
		{
			eXosip_call_send_answer(g_event->tid, 603, NULL);
			eXosip_unlock();
			printf("eXosip_call_build_answer error!\r\n");
			return -1;
			}
		eXosip_unlock();

		char sdp_body[1024];
		//char sdp_body[4096];
		//memset(sdp_body, 0, 4096);
		//printf("<MSG_IS_INVITE>\r\n");

		//interface get sdp
		//uas_function_run(uas_get_invite_sdp,sdp_body);
		uas_get_sdp(sdp_body);
		//end interface

		eXosip_lock();
		osip_message_set_body(asw_msg, sdp_body, strlen(sdp_body));/*设置SDP消息体*/
		osip_message_set_content_type(asw_msg, "application/sdp");
		eXosip_call_send_answer(g_event->tid, 200, asw_msg);/*按照规则回复200OK with SDP*/
		printf("eXosip_call_send_answer success!\r\n");
		eXosip_unlock();


	}
	return 0;
}

int handle_message(eXosip_event_t * g_event)
{
	osip_body_t *msg_body = NULL;
	osip_message_t *g_answer = NULL;/*请求的确认型应答*/

	//printf("<MSG_IS_INFO>\r\n");
	osip_message_get_body(g_event->request, 0, &msg_body);
	if(NULL != msg_body)
	{
		eXosip_call_build_answer(g_event->tid, 200, &g_answer);/*Build default Answer for request*/
		eXosip_call_send_answer(g_event->tid, 200, g_answer);/*按照规则回复200OK*/
		printf("eXosip_call_send_answer success!\r\n");
		//csenn_eXosip_paraseInfoBody(g_event);/*解析INFO的RTSP消息体*/

		char * message;
		osip_body_t *body;
		osip_message_get_body (g_event->request, 0, &body);
		message=(char *)malloc (body->length*sizeof(char));
		snprintf (message, body->length,"%s", body->body);

		if(MSG_IS_INFO(g_event->request))
		//interface handle the message
		//uas_function_run(uas_handle_Message,message);
			uas_handle_Historyrtsp(message);
		//end interface

		else if(MSG_IS_MESSAGE(g_event->request))
		//interface handle the message
		//uas_function_run(uas_handle_Message,message);
		handle_HistoryEOFmessage(message);
		//end interface

		free(message);
	}
}

int handle_bye(eXosip_event_t * g_event)
{
	/*实时视音频点播*/
					/*历史视音频回放*/
					/*视音频文件下载*/
					printf("\r\n<EXOSIP_CALL_CLOSED>\r\n");
					if(MSG_IS_BYE(g_event->request))
					{
						printf("<MSG_IS_BYE>\r\n");
						if((0 != g_did_realPlay)&&(g_did_realPlay == g_event->did))/*实时视音频点播*/
						{
							/*关闭：实时视音频点播*/
							//printf("realPlay closed success!\r\n");

							//interface stop transport
							//uas_function_run(uas_stop_transport,NULL);
							uas_close_media();
							//end interface

							g_did_realPlay = 0;
						}
						else if((0 != g_did_backPlay)&&(g_did_backPlay == g_event->did))/*历史视音频回放*/
						{
							/*关闭：历史视音频回放*/
							//printf("backPlay closed success!\r\n");

							//interface stop transport
							//uas_function_run(uas_stop_transport,NULL);
							uas_close_media();
							//end interface

							g_did_backPlay = 0;
						}
						else if((0 != g_did_fileDown)&&(g_did_fileDown == g_event->did))/*视音频文件下载*/
						{
							/*关闭：视音频文件下载*/
							//printf("fileDown closed success!\r\n");

							//interface stop transport
							//uas_function_run(uas_stop_transport,NULL);
							uas_close_media();
							//end interface

							g_did_fileDown = 0;
						}
						if((0 != g_call_id)&&(0 == g_did_realPlay)&&(0 == g_did_backPlay)&&(0 == g_did_fileDown))/*设置全局INVITE连接ID*/
						{
							//printf("call closed success!\r\n");

							uas_close_media();
							g_call_id = 0;
						}
					}
	return 0;
}

/*解析INVITE的SDP消息体，同时保存全局INVITE连接ID和全局会话ID*/
void uas_eXosip_paraseInviteBody(eXosip_event_t *p_event)
{
	sdp_message_t *sdp_msg = NULL;
	char *media_sever_ip   = NULL;
	char *media_sever_port = NULL;

	sdp_msg = eXosip_get_remote_sdp(p_event->did);
	if (sdp_msg == NULL)
	{
		printf("eXosip_get_remote_sdp NULL!\r\n");
		return;
	}
	printf("eXosip_get_remote_sdp success!\r\n");

	/*从SIP服务器发过来的INVITE请求的o字段或c字段中获取媒体服务器的IP地址与端口*/
		media_sever_ip   = sdp_message_o_addr_get(sdp_msg);/*媒体服务器IP地址*/
		media_sever_port = sdp_message_m_port_get(sdp_msg, 0);/*媒体服务器IP端口*/
		//printf("%s->%s:%s\r\n", sdp_msg->s_name, media_sever_ip, media_sever_port);

	g_call_id = p_event->cid;/*保存全局INVITE连接ID*/
/*实时点播*/
	if (0 == strcmp(sdp_msg->s_name, "Play"))
	{
		g_did_realPlay = p_event->did;/*保存全局会话ID：实时视音频点播*/

		//interface start transport
		//uas_function_run(uas_start_transport,NULL);
		uas_start_media();
		//end interface
	}
/*回放*/
	else if (0 == strcmp(sdp_msg->s_name, "Playback"))
	{
		g_did_backPlay = p_event->did;/*保存全局会话ID：历史视音频回放*/
	}
/*下载*/
	else if (0 == strcmp(sdp_msg->s_name, "Download"))
	{
		g_did_fileDown = p_event->did;/*保存全局会话ID：视音频文件下载*/
	}

	//csenn_eXosip_callback.csenn_eXosip_mediaControl(sdp_msg->s_name, media_sever_ip, media_sever_port);
}

void uas_eXosip_processEvent(void)
{
	eXosip_event_t *g_event  = NULL;/*消息事件*/
	osip_message_t *g_answer = NULL;/*请求的确认型应答*/

	while (1)
	{
/*等待新消息的到来*/
		g_event = eXosip_event_wait(0, 200);/*侦听消息的到来*/
		eXosip_lock();
		eXosip_default_action(g_event);
		eXosip_automatic_refresh();/*Refresh REGISTER and SUBSCRIBE before the expiration delay*/
		eXosip_unlock();
		if (NULL == g_event)
		{
			continue;
		}
		//csenn_eXosip_printEvent(g_event);
/*处理感兴趣的消息*/
		switch (g_event->type)
		{
/*即时消息：通信双方无需事先建立连接*/
			case EXOSIP_MESSAGE_NEW:/*MESSAGE:MESSAGE*/
			{
				printf("\r\n<EXOSIP_MESSAGE_NEW>\r\n");
				if(MSG_IS_MESSAGE(g_event->request))/*使用MESSAGE方法的请求*/
				{
					/*设备控制*/
					/*报警事件通知和分发：报警通知响应*/
					/*网络设备信息查询*/
					/*设备视音频文件检索*/
					printf("<MSG_IS_MESSAGE>\r\n");
					eXosip_lock();
					eXosip_message_build_answer(g_event->tid, 200, &g_answer);/*Build default Answer for request*/
					eXosip_message_send_answer(g_event->tid, 200, g_answer);/*按照规则回复200OK*/
					printf("eXosip_message_send_answer success!\r\n");
					eXosip_unlock();
					csenn_eXosip_paraseMsgBody(g_event);/*解析MESSAGE的XML消息体，同时保存全局会话ID*/
				}
			}
			break;
/*即时消息回复的200OK*/
			case EXOSIP_MESSAGE_ANSWERED:/*200OK*/
			{
				/*设备控制*/
				/*报警事件通知和分发：报警通知*/
				/*网络设备信息查询*/
				/*设备视音频文件检索*/
				printf("\r\n<EXOSIP_MESSAGE_ANSWERED>\r\n");
			}
			break;
/*以下类型的消息都必须事先建立连接*/
			case EXOSIP_CALL_INVITE:/*INVITE*/
			{
				printf("\r\n<EXOSIP_CALL_INVITE>\r\n");

				handle_invite(g_event);
			}
			break;
			case EXOSIP_CALL_ACK:/*ACK*/
			{
				/*实时视音频点播*/
				/*历史视音频回放*/
				/*视音频文件下载*/
				printf("\r\n<EXOSIP_CALL_ACK>\r\n");/*收到ACK才表示成功建立连接*/
				uas_eXosip_paraseInviteBody(g_event);/*解析INVITE的SDP消息体，同时保存全局INVITE连接ID和全局会话ID*/
			}
			break;
			case EXOSIP_CALL_CLOSED:/*BEY*/
			{
				handle_bye(g_event);
			}
			break;
			case EXOSIP_CALL_MESSAGE_NEW:/*MESSAGE:INFO*/
			{
				/*历史视音频回放*/
				printf("\r\n<EXOSIP_CALL_MESSAGE_NEW>\r\n");
				if(MSG_IS_INFO(g_event->request)||MSG_IS_MESSAGE(g_event->request))//identify the info/message package
				{
					handle_message(g_event);
				}
			}
			break;
			case EXOSIP_CALL_MESSAGE_ANSWERED:/*200OK*/
			{
				/*历史视音频回放*/
				/*文件结束时发送MESSAGE(File to end)的应答*/
				printf("\r\n<EXOSIP_CALL_MESSAGE_ANSWERED>\r\n");
			}
			break;
/*其它不感兴趣的消息*/
			default:
			{
				printf("\r\n<OTHER>\r\n");
				printf("eXosip event type:%d\n", g_event->type);
			}
			break;
		}
	}
}


#endif
