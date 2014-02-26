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

	init_Contextconf(device_info.cfgFile);
/*
	uas_handle_invite_sdp=uas_handle_Playsdp;
	uas_get_invite_sdp=uas_get_Playsdp;
	uas_start_transport=uas_send_Playmedia;
	uas_handle_Message=uas_handle_rtsp;
	uas_stop_transport=uas_close_Playmedia;
	*/
	//uas_get_info=uas_get_message;
	return 1;
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
			return 0;
	}
	else
		return 0;
	return 1;
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

int handle_401_Unauthorized_data(void *data)
{
	//printf("handle_401_Unauthorized_data:%s\n",data);

	//struct  RegisterContext * registerCon;

	//RegisterCon->radius_id=device_info.radius_id;
	//RegisterCon->peer_id=device_info.server_id;
	//RegisterCon->peer_ip=device_info.server_ip;
	//RegisterCon->self_id=device_info.ipc_id;
	//RegisterCon->self_password=device_info.ipc_pwd;
	//registerCon->self_type=;

	printf("registerCon->self_id:%s",RegisterCon->self_id);
	//struct  auth_active auth_active_packet;

	if(!HandleWAPIProtocolAuthActive(RegisterCon,(AuthActive *)data));
	{
		return 1;
	}

	return 0;}

int get_register2_data(char *data,char * in_data)
{
	//memcpy(data,"+register2_data+", 17);
	//printf("get_register2_data:%s\n",data);

	//AccessAuthRequ *data2=(char*)malloc(sizeof(AccessAuthRequ)*2);
	if(!ProcessWAPIProtocolAccessAuthRequest(RegisterCon,(AuthActive *)in_data,(AccessAuthRequ *)(data)))
	{
		printf("ProcessWAPIProtocolAccessAuthRequest error\n");
		return 1;
	}

	printf("ProcessWAPIProtocolAccessAuthRequest success\n");
	return 0;}

int handle_response_data(void *data,void * in_data)
{
	//printf("handle_response_data:%s\n",data);
	if(HandleWAPIProtocolAccessAuthResp(RegisterCon,(AccessAuthRequ *)in_data, (AccessAuthResp *) data))
	{
		return 1;
	}
	return 0;}

//end register interface


int codeToChar(char *data,int lenth)
{
	int i,j;
	i=lenth-1;
	j=lenth/2-1;
	for(i=lenth-1;i>=0;i=i-2,j--)
	{
		data[i]=(data[j]&0x0f)+0x30;
		data[i-1] = ((data[j]>>4)&0x0f)+0x30;
	}
	return 1;
}
int decodeFromChar(char *data,int lenth)
{
	int i,j;
	i=1;
	j=0;
	for(j=0;i<lenth ;i=i+2,j++)
	{
		data[j]=(data[i] - 0x30 ) +((data[i-1]-0x30) <<4);
	}
	return 1;
}

int init_Contextconf(char * file)
{
	RegisterCon=(RegisterContext *)malloc(sizeof(RegisterContext));

	int fd=open(file,O_RDONLY);
	    if(fd>2){   //确保文件存在
	    	//static  char * cfgFile ;
	    	//cfgFile=(char *)malloc(sizeof(char)*30);
	    	//strcpy(cfgFile,file);
	    	//device_info.cfgFile=cfgFile;

	    	char *value=(char *)malloc(sizeof(char)*20);
	    	get_conf_value( "radius_id",value,file);
	    	RegisterCon->radius_id=value;

	    	value=(char *)malloc(sizeof(char)*20);
	    	get_conf_value( "self_type", value,file);
	    	if(strcmp(value,"SIPserver")==0)
	    	{
	    		Self_type=SIPserver;
	    	}
	    	else if(strcmp(value,"IPC")==0)
	    	{
	    		Self_type=IPC;
	    		//user_type=USER_TYPE_IPC;
	    	}
	    		else if(strcmp(value,"CLIENT")==0)
	    	{
	    		//Self_type=CLIENT;
	    		//user_type=USER_TYPE_CLIENT;
	    	}
	    		else if(strcmp(value,"NVR")==0)
	    	{
	    		Self_type=NVR;
	    		//user_type=USER_TYPE_NVR;
	    	}

	    	free(value);

	    	value=(char *)malloc(sizeof(char)*20);
	    	get_conf_value( "self_id",value,file);
	    	RegisterCon->self_id=value;

	    	value=(char *)malloc(sizeof(char)*20);
	    	get_conf_value( "self_password",value,file);
	    	RegisterCon->self_password=value;

	    	if(Self_type!=SIPserver)
	    	{
	    		value=(char *)malloc(sizeof(char)*20);
	    		get_conf_value("server_ip",value,file);
	    		RegisterCon->peer_ip=value;

	    		value=(char *)malloc(sizeof(char)*20);
	    		get_conf_value("server_id",value,file);
	    		RegisterCon->peer_id=value;
	    	}

	        close(fd);
	        printf("open config file:%s success\n",file);
	    }
	    else{
	       printf("can not open config file:%s\n",file);
	       exit(1);
	    }
	return 1;
	}
