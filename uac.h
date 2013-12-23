/*
 * uac.c
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */

#include "csenn_eXosip2.h"
#include "interface.c"

#ifndef UAC_H
#define UAC_H

int uac_init()
{
	printf("start\n");
			csenn_eXosip_launch();
			static  char eXosip_server_id[30]           = "34020000001180000002";
			static  char eXosip_server_ip[20]           = "192.168.17.1";
			static  char eXosip_server_port[10]         = "5060";
			static  char eXosip_ipc_id[30]              = "34020000001180000002";
			static  char eXosip_ipc_pwd[20]             = "12345678";
			static  char eXosip_ipc_ip[20]              = "192.168.17.128";
			static  char eXosip_ipc_port[10]            = "5060";

			device_info.server_id           = eXosip_server_id;
			device_info.server_ip           = eXosip_server_ip;
			device_info.server_port         = eXosip_server_port;
			device_info.ipc_id              = eXosip_ipc_id;
			device_info.ipc_pwd             = eXosip_ipc_pwd;
			device_info.ipc_ip              = eXosip_ipc_ip;
			device_info.ipc_port            = eXosip_ipc_port;


			//csenn_eXosip_callback.csenn_eXosip_getDeviceInfo(&device_info);
			while (csenn_eXosip_init());
			return 0;
}

int uas_register()
{
	csenn_eXosip_register(3600);
	return 0;
}

int uas_invite(sessionId * inviteId,char *to,char * sdp_message,char * responseSdp)
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
			csenn_eXosip_invit(inviteId,to,sdp_message,&responseSdp);

			//interface 2: do something with responseSdp ;
			//printf("main return sdp:%s \n",responseSdp);
			//end interface 2:
	return 0;
}

int uas_bye(sessionId inviteId)
{
	return csenn_eXosip_bye(inviteId);

	//interface 3: do something with responseSdp ;
	//turn off the steam of the video transport
	//end interface 3:

	//return 0;
	}

int uas_send_info(sessionId inviteId)
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

int uas_send_message(sessionId inviteId,char * type ,char * type_info,char * message_str)
{
	osip_message_t *message;
	char message_body[1000];
	int i;
	eXosip_lock ();
	i = eXosip_call_build_request (inviteId.did,type/*"MESSAGE" or "INFO"*/, &message);
	if (i == 0)
	{
		snprintf (message_body, 999, message_str/*"message_info"*/);
		if(type_info!=NULL)
		osip_message_set_content_type (message, type_info/*"Application/MANSRTSP"*/);
		osip_message_set_body (message, message_body, strlen (message_body));
		i = eXosip_call_send_request (inviteId.did, message);
	}
	eXosip_unlock ();

	return i;
}
#endif
