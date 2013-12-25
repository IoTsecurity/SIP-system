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
#include "interface.h"

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

int main()
{
		sessionId inviteId;
		char send_sdp_data[1024];
		char recieve_sdp_data[1024];
		char rtsp_data[1024];
		struct st_rtsptype rtsptype;
		uac_init();

		printf("r: regester\n");
		printf("i: invite\n");
		printf("n: send info\n");
		printf("m: send message\n");
		printf("b: bye\n");
		printf("s: run as a uas\n");

		char command;
		//printf ("please input the comand:\n");
		//scanf ("%c", &command);
		//getchar ();
		while(1)
		{
			printf ("please input the comand:\n");
			scanf ("%c", &command);
			getchar ();
			switch (command)
			{
				case 'r':
					uac_register();
					break;
				case 'i':
					uac_get_sdp(send_sdp_data);
					uac_invite(&inviteId,"34020000001310000054@192.168.17.1:5060",//"34020000001310000051@192.168.17.1:5060",
							send_sdp_data,recieve_sdp_data);
					uac_handle_sdp(recieve_sdp_data);
					uac_receive_media();
					break;
				case 'b':
					uac_bye(inviteId);
					uac_close_media();
					break;
				case 'n':
					//uas_send_info(inviteId);
					rtsptype.rtsp_datatype="PLAY";
					rtsptype.scale=1;
					uac_get_rtsp(rtsp_data,&rtsptype);
					uac_send_message(inviteId,"INFO","Application/MANSRTSP",rtsp_data);
					break;
				case 'm':
					//send "EOF" message
					uac_send_message(inviteId,"MESSAGE","Application/MANSCDP+xml","<?xml version=\"1.0\">\r\n<Notify></Notify>");
					//uas_send_message(inviteId,"INFO","Application/MANSRTSP","sssss");
					break;
				case 's':
					uas_eXosip_processEvent();
					break;
				default:
					break;
			}
		}

		//csenn_eXosip_processEvent();

	printf("end\n");
	return 0;
}
