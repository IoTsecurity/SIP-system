/*
 * main.c
 *
 *  Created on: 2013年12月4日
 *      Author: jzw
 */


#include <stdio.h>
#include <stdlib.h>

#include "csenn_eXosip2.h"
#include "uac.h"
#include "uas.h"
#include "dispatch.h"

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

		if(argc>1)
		init_conf(argv[1]);
		else
		init_conf("default.cfg");
		uac_init();

		printf("1: register\n");
		printf("2: invite\n");
		printf("3: send info\n");
		printf("4: send EOF message\n");
		printf("5: send nosession message\n");
		printf("6: key_nego\n");
		printf("7: key distribute\n");
		printf("\n");
		printf("a: bye\n");
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
				case '2':
					call_type=CALL_TYPE_PLAY;
					uac_get_Playsdp(send_sdp_data);
					char *default_invite;
					default_invite=(char *)malloc(sizeof(char)* 100);
					get_conf_value("default_invite",default_invite,device_info.cfgFile);
					//printf("default_invite:%s\n",default_invite);
					uac_invite(&inviteId,default_invite,//"34020000001310000051@192.168.17.1:5060",
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
					uac_send_message(inviteId,"INFO","Application/MANSRTSP",rtsp_data,NULL);
					break;
				case '4':
					//send "EOF" message
					get_HistoryEOFmessage(EOF_message,"EOF");
					uac_send_message(inviteId,"MESSAGE","Application/MANSCDP+xml",EOF_message,NULL);
					//uas_send_message(inviteId,"INFO","Application/MANSRTSP","sssss");
					break;
				case '5':
					snprintf(to, 50,"sip:%s@%s:%s",device_info.server_id,device_info.server_ip,device_info.server_port);
					snprintf(from, 50,"sip:%s@%s:%s",device_info.ipc_id,device_info.ipc_ip,device_info.ipc_port);
					uac_send_noSessionMessage(to,from, NULL,"this is no session message",NULL);
					break;
				case '6':
					uac_key_nego();
					break;
				case '7':
					uac_key_distribute();
					break;
				case 'a':
					uac_bye(inviteId);
					//uac_close_Playmedia();
					uac_close_media();
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
