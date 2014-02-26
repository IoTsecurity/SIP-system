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

/*
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>

#include <pthread.h>

#include <osip2/osip_mt.h>
#include <eXosip2/eXosip.h>
*/

int main(int argc,char *argv[])
{
		sessionId inviteId;
		char send_sdp_data[1024];
		char recieve_sdp_data[1024];
		char rtsp_data[1024];
		char EOF_message[1024];
		struct st_rtsptype rtsptype;

		if(argc>1)
		init_conf(argv[1]);
		else
		init_conf("default.cfg");
		uac_init();

		printf("r: regester\n");
		printf("i: invite\n");
		printf("n: send info\n");
		printf("m: send message\n");
		printf("b: bye\n");
		printf("s: run as a uas\n");
		printf("e: exit\n");

		char command;
		//printf ("please input the comand:\n");
		//scanf ("%c", &command);
		//getchar ();
		while(1)
		{
			printf ("please input the comand:\n");
			scanf ("%c", &command);
			if(command=='\n')
				continue;
			getchar ();
			//printf("+%c+\n",command);
			switch (command)
			{
				case 'r':
					uac_register();
					break;
				case 'i':
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
				case 'b':
					uac_bye(inviteId);
					//uac_close_Playmedia();
					uac_close_media();
					break;
				case 'n':
					//uas_send_info(inviteId);
					rtsptype.rtsp_datatype="PLAY";
					rtsptype.scale=1;
					uac_get_Historyrtsp(rtsp_data,&rtsptype);
					uac_send_message(inviteId,"INFO","Application/MANSRTSP",rtsp_data);
					break;
				case 'm':
					//send "EOF" message
					get_HistoryEOFmessage(EOF_message,"EOF");
					uac_send_message(inviteId,"MESSAGE","Application/MANSCDP+xml",EOF_message);
					//uas_send_message(inviteId,"INFO","Application/MANSRTSP","sssss");
					break;
				case 's':
					uas_eXosip_processEvent();
					break;
				case 'e':
					exit(1);
					break;
				default:
					break;
			}
		}

	printf("end\n");
	return 0;
}
