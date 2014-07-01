/*
 * main.c
 *
 *  Created on: 2013年12月4日
 *      Author: jzw
 */


#include <stdio.h>
#include <stdlib.h>

//#include "csenn_eXosip2.h"
#include "uac.h"
#include "uas.h"
#include "dispatch.h"
#include "sm1.h"

int main(int argc,char *argv[])
{
		sessionId inviteId;
		char send_sdp_data[1024];
		char recieve_sdp_data[1024];
		char rtsp_data[1024];
		char EOF_message[1024];
		char to[50];
		char from[50];
		struct st_rtsptype rtsptype;

		sip_entity target;
		sip_entity p2p_target;

		FILE *media_p;

		char *conf;
		conf=NULL;
		if(argc>1)
		{
			//check_conf(argv[1]);
			conf=argv[1];
		}
		if(uac_init(conf)<1)
		{
			printf("uac_init error\n");
			return 0;
		}

		printf("1: register\n");
		/*printf("2: invite\n");
		printf("3: send info\n");
		printf("4: send EOF message\n");
		printf("5: send nosession message\n");*/
		printf("2: key_nego\n");
		printf("3: key distribute\n");

		printf("4: token exchange\n");
		printf("5: transmit the video between IPC and NVR\n");
		printf("6: bye\n");

		printf("\n");
		//printf("a: bye\n");
		printf("b: run as a uas\n");
		printf("c: exit\n");

		char command;
		while(1)
		{
			printf ("please input the comand:\n");
			scanf ("%c", &command);
			if(command=='\n')
				continue;
			getchar ();
			switch (command)
			{
				case '1':
					uac_register();
					break;
					/*
				case '2':
					call_type=CALL_TYPE_PLAY;
					uac_get_Playsdp(send_sdp_data);
					char *default_invite;
					default_invite=(char *)malloc(sizeof(char)* 100);
					get_conf_value("default_invite",default_invite,device_info.cfgFile);
					//printf("default_invite:%s\n",default_invite);
					uac_invite(&inviteId,default_invite,//"34020000001310000051@192.168.17.1:5060",---
							send_sdp_data,recieve_sdp_data);
					uac_handle_Playsdp(recieve_sdp_data);
					//uac_receive_Playmedia();
					uac_start_media(device_info.server_ip);
					break;
				case '3':
					//uas_send_info(inviteId);
					rtsptype.rtsp_datatype="PLAY";
					rtsptype.scale=1;
					uac_get_Historyrtsp(rtsp_data,&rtsptype);
					alter_message info;
					memset(&info,0,sizeof(alter_message));
					info.body=rtsp_data;
					info.method_type="INFO";
					info.content_type="Application/MANSRTSP";
					info.route=NULL;
					uac_send_message(inviteId,&info);
					break;
				case '4':
					//send "EOF" message
					get_HistoryEOFmessage(EOF_message,"EOF");
					alter_message eof_info;
					memset(&eof_info,0,sizeof(alter_message));
					eof_info.body=EOF_message;
					eof_info.method_type=METHODMESSAGE;
					eof_info.content_type="Application/MANSCDP+xml";
					eof_info.route=NULL;
					uac_send_message(inviteId,&eof_info);
					//uas_send_message(inviteId,"INFO","Application/MANSRTSP","sssss");
					break;
				case '5':
					memset(&target,0,sizeof(target));
					sprintf(target.ip, "%s", device_info.server_ip);
					target.port=atoi(device_info.server_port);
					sprintf(target.username, "%s", device_info.server_id);
					//snprintf(to, 50,"sip:%s@%s:%s",device_info.server_id,device_info.server_ip,device_info.server_port);

					alter_message mess;
					memset(&mess,0,sizeof(alter_message));
					mess.body="this is no session message";
					mess.route=NULL;
					mess.method_type=METHODMESSAGE;
					mess.subject=NULL;

					uac_send_noSessionMessage(&target,&mess);
					break;
					*/
				case '2':
					uac_key_nego();
					if(user_type==NVR)
					{
						uas_eXosip_processEvent();
					}
					break;
				case '3':
					uac_key_distribute("user2",&p2p_target);
					break;
				case '4':

					//uac_token_exchange(&p2p_target);
					uac_token_exchange(&p2p_target,Auth);
					writekey(Securelinks.links[getSecureLinkNum(&Securelinks,p2p_target.username)].CK,KEY_LEN,1);
					uac_token_exchange(&p2p_target,Reauth);
					uac_token_exchange(&p2p_target,Byesession);
					uac_token_exchange(&p2p_target,Byelink);
					//uac_token_exchange(&p2p_target,Auth);
					break;
				case '5':
					//video_invite();
					//uac_videotransmit_ipc2nvr(&p2p_target);

					uac_start_media(&media_p, p2p_target.ip);
					break;
				case '6':
					uac_bye(inviteId);
					//uac_close_Playmedia();
					uac_close_media(media_p);
					break;
				case 'b':
					uas_eXosip_processEvent();
					break;
				case 'c':
					exit(1);
					break;
				default:
					break;
			}
		}

	printf("end\n");
	return 0;
}
