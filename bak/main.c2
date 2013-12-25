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
		char * get_message;
		uac_init();

		printf("r: regester\n");
		printf("i: invite\n");
		printf("b: bye\n");

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
					uas_register();
					break;
				case 'i':
					uas_invite(&inviteId,
							"34020000001310000051@192.168.17.129:5060",
							"v=0\r\n"
							"o=josua  0 0 IN IP4 192.168.1.1\r\n"
							"s=Play\r\n"
							"c=IN IP4 192.168.1.1\r\n"
							"t=0 0\r\n"
							"m=audio 8000 RTP/AVP 0 8 101\r\n",
							&get_message);
					break;
				case 'b':
					uas_bye(inviteId);
					break;
				case '1':
					//uas_send_info(inviteId);
					uas_send_message(inviteId,"INFO","Application/MANSRTSP","sssss");
					break;
				case 'm':
					uas_send_message(inviteId,"MESSAGE","Application/MANSCDP+xml","<?xml version=\"1.0\">\r\n<Notify></Notify>");
					//uas_send_message(inviteId,"INFO","Application/MANSRTSP","sssss");
					break;
				default:
					break;
			}
		}

		//csenn_eXosip_processEvent();

	printf("end\n");
	return 0;
}
