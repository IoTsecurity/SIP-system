/*
 * dispatch.c
 *
 *  Created on: 2014年2月13日
 *      Author: root
 */

#include <stdio.h>
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <memory.h>


#include<sys/types.h>
#include<fcntl.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<sys/ioctl.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

#include "dispatch.h"
#include "interface.h"
#include "sip_com.h"

int user_type;
int call_type;
int invite_user_type;
int invite_type;




int uac_get_sdp(char *sdp_data)
{
	if(user_type==USER_TYPE_IPC)
		;//uac_get_Transportsdp(sdp_data);
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_get_Playsdp(sdp_data);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_get_Historysdp(sdp_data);
		else
			return 0;
	}
	else
		return 0;
	return 1;
	}

int uac_handle_sdp(char *sdp_data)
{
	if(user_type==USER_TYPE_IPC)
		;//uac_handle_Transportsdp(sdp_data);
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_handle_Playsdp(sdp_data);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_handle_Historysdp(sdp_data);
		else
			return 0;
	}
	else
		return 0;
	return 1;
}

int uac_start_media(FILE **media_p, char * peer_location)
{printf("uac_start_media:%s",peer_location);
	char selfip[16];
	char ipc_shell[1024];
	memset(ipc_shell,0,1024);
	if(user_type==USER_TYPE_IPC)
	{
		getNetInfo(selfip,NULL);
		//FILE *fp;
		char buffer[1024];
		memset(buffer,'\0',sizeof(buffer));
		sprintf(ipc_shell,"ffmpeg -i rtsp://%s:8557/PSIA/Streaming/"
				"channels/2?videoCodecType=H.264 -vcodec copy -an -f h264 tcp://%s:10000",peer_location,selfip);
		(*media_p)=popen(ipc_shell,"r");
		if((*media_p)==NULL)
		{
			printf("start program error\n");
		}
		fgets(buffer,sizeof(buffer),(*media_p));
		printf("结果:%s",buffer);
		//pclose(fp);
		;//uac_send_Transportmedia(peer_location);
	}
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_receive_Playmedia(peer_location);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_receive_Historymedia(peer_location);
		else
			return 0;
	}
	else
		return 0;
	return 1;
	}

int uac_close_media(FILE *media_p)
{
	if(user_type==USER_TYPE_IPC)
	{
		pclose(media_p);
		;//uac_close_Transportmedia();
	}
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_close_Playmedia();
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_close_Historymedia();
		else
			return 0;
	}
	else
		return 0;
	return 1;
}

//uas

int uas_handle_sdp(char *sdp_data)
{
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_handle_Transportsdp(sdp_data);
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_handle_Playsdp(sdp_data);
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_handle_Historysdp(sdp_data);
		else
			return 0;
	}
	else
		return 0;
	return 1;}

int uas_get_sdp(char *sdp_data)
{
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_get_Transportsdp(sdp_data);
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_get_Playsdp(sdp_data);
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_get_Historysdp(sdp_data);
		else
			return 0;
	}
	else
		return 0;
	return 1;}

int uas_start_media(char *peer_location)
{
	printf("uas_start_media:%s\n",peer_location);
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_receive_Transportmedia(peer_location);
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_send_Playmedia(peer_location);
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_send_Historymedia(peer_location);
		else
			return 0;
	}
	else
		return 0;
	return 1;}

int uas_close_media()
{

	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_close_Transportmedia();
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_close_Playmedia();
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_close_Historymedia();
		else
			return 0;
	}
	else
		return 0;
	return 1;}

//end uas interface


//begin register interface

int handle_response_data(void *data,void * in_data)
{
	//printf("handle_response_data:%s\n",data);
	if(HandleWAPIProtocolAccessAuthResp(RegisterCon,(AccessAuthRequ *)in_data, (AccessAuthResp *) data))
	{
		return 1;
	}
	return 0;}

//end register interface



