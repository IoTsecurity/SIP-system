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

#include "dispatch.h"
#include "interface.h"
/*
int uas_function_run(funcP fun_name,void(*arg))
{
	(*fun_name)(arg);
	return 0;
	}
*/


int interface_init()
{
	user_type=0;
	call_type=0;

	invite_user_type=0;
	invite_type=0;
/*
	uas_handle_invite_sdp=uas_handle_Playsdp;
	uas_get_invite_sdp=uas_get_Playsdp;
	uas_start_transport=uas_send_Playmedia;
	uas_handle_Message=uas_handle_rtsp;
	uas_stop_transport=uas_close_Playmedia;
	*/
	//uas_get_info=uas_get_message;
	return 0;
}

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
			return -1;
	}
	else
		return -1;
	return 0;
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
			return -1;
	}
	else
		return -1;
	return 0;
}

int uac_start_media(char * peer_location)
{printf("uac_start_media:%s",peer_location);
	if(user_type==USER_TYPE_IPC)
		;//uac_send_Transportmedia(peer_location);
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_receive_Playmedia(peer_location);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_receive_Historymedia(peer_location);
		else
			return -1;
	}
	else
		return -1;
	return 0;
	}

int uac_close_media()
{
	if(user_type==USER_TYPE_IPC)
		;//uac_close_Transportmedia();
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_close_Playmedia();
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_close_Historymedia();
		else
			return -1;
	}
	else
		return -1;
	return 0;
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
			return -1;
	}
	else
		return -1;
	return 0;}

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
			return -1;
	}
	else
		return -1;
	return 0;}

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
			return -1;
	}
	else
		return -1;
	return 0;}

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
			return -1;
	}
	else
		return -1;
	return 0;}

//end uas interface


//begin register interface

int handle_401_Unauthorized_data(void *data)
{
	//printf("handle_401_Unauthorized_data:%s\n",data);

	//struct  RegisterContext * registerCon;
	registerCon=(struct  RegisterContext *)malloc(sizeof(struct  RegisterContext));

	registerCon->radius_id=device_info.radius_id;
	registerCon->peer_id=device_info.server_id;
	//registerCon->peer_ip=device_info.server_ip;
	registerCon->self_id=device_info.ipc_id;
	registerCon->self_password=device_info.ipc_pwd;
	//registerCon->self_type=;

	//struct  auth_active auth_active_packet;
	if(HandleWAPIProtocolAuthActive(registerCon,(AuthActive *)data));
	{
		return 1;
	}
	return 0;}

int get_register2_data(void *data,void * in_data)
{
	//memcpy(data,"+register2_data+", 17);
	//printf("get_register2_data:%s\n",data);
	if(ProcessWAPIProtocolAccessAuthRequest
			(registerCon,(AuthActive *)in_data,(AccessAuthRequ *)data))
	{
		return 1;
	}
	return 0;}

int handle_response_data(void *data,void * in_data)
{
	//printf("handle_response_data:%s\n",data);
	if(HandleWAPIProtocolAccessAuthResp(registerCon,(AccessAuthRequ *)in_data, (AccessAuthResp *) data))
	{
		return 1;
	}
	return 0;}

//end register interface
