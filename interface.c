/*
 * interface.c
 *
 *  Created on: 2014年1月2日
 *      Author: root
 */
#include "interface.h"

//end uac interface

/*filled by yaoyao*/ // get sdp, fill in INVITE, send to media server by client
int uac_get_Playsdp(char *sdp_data)
{/*
	snprintf(sdp_data,1024,
			"v=0\r\n"
            "o=josua  0 0 IN IP4 192.168.1.1\r\n"
            "s=Playback\r\n"
			  "u=34020000001310000054:3\r\n"
            "c=IN IP4 192.168.1.1\r\n"
            "t=11111 22222\r\n"
            "m=audio 8000 RTP/AVP 0 8 101\r\n");*/
	snprintf(sdp_data,1024,
				"v=0 \r\n"
"o=- 0 0 IN IP4 127.0.0.1 \r\n"
"s=Play \r\n"
"c=IN IP4 0.0.0.0 \r\n"
"t=0 0 \r\n"
"a=tool:libavformat 55.12.102 \r\n"
"m=video 0 RTP/AVP 96 \r\n"
"a=rtpmap:96 H264/90000 \r\n"
"a=fmtp:96 packetization-mode=1 \r\n"
"a=control:streamid=0 \r\n"
);
	return 0;
}

/*filled by yaoyao*/ // handle sdp received from media server in client
int uac_handle_Playsdp(char *sdp_data)
{
	printf("uac_handle_Playsdp\n");
	return 0;
}

/*filled by yaoyao*/ // start request: media receiving process from media server in client
int uac_receive_Playmedia()
{
	printf("uac_receive_Playmedia\n");
	return 0;
}

/*filled by yaoyao*/ // close media receiving process from media server in client
int uac_close_Playmedia()
{
	printf("uac_close_Playmedia\n");
	return 0;
}

// get rtsp data, fill in INFO for sending to media server by client
int uac_get_Historyrtsp(char *rtsp_data, struct st_rtsptype  *ptr_st_rtsptype)
{
	// if rtsp datatype in {"PLAY", "FAST", "SLOW"}: check scale
	snprintf(rtsp_data,1024,
				"this is test data!");
	printf("uac_get_Historyrtsp\n");
	return 0;
}

// handle MESSAGE, received from media server in client
int handle_HistoryEOFmessage(char *message)
{
	printf("uac_handle_HistoryEOFmessage\n");
	return 0;
}

//end uac interface


//begin uas interface
/*
int uas_function_run(funcP fun_name,void(*arg))
{
	(*fun_name)(arg);
	return 0;
	}
*/
/*filled by yaoyao*/ // handle sdp data via INVITE received from client in media server
int uas_handle_Playsdp(char *sdp_data)
{
	//

	printf("uas_handle_Playsdp:%s\n",sdp_data);
	return 0;
	}

/*filled by yaoyao*/ // get sdp data for sending to client in media server
/*filled by yaoyao*/ // p -> 1024 bytes
int uas_get_Playsdp(char *sdp_data)
{
	/*
	snprintf(sdp_data, 1024,
			"v=0\r\n"
			"o=%s 0 0 IN IP4 \r\n"
			"s=PLAY\r\n"
			"c=IN IP4 \r\n"
			"t=0 0\r\n"
			"m=video  STP/AVP 96\r\n"
			"a=sendonly\r\n"
			"a=rtpmap:96 H264/90000\r\n"
			"f=\r\n");*/
	snprintf(sdp_data,1024,
					"v=0 \r\n"
	"o=- 0 0 IN IP4 127.0.0.1 \r\n"
	"s=Play \r\n"
	"c=IN IP4 0.0.0.0 \r\n"
	"t=0 0 \r\n"
	"a=tool:libavformat 55.12.102 \r\n"
	"m=video 0 RTP/AVP 96 \r\n"
	"a=rtpmap:96 H264/90000 \r\n"
	"a=fmtp:96 packetization-mode=1 \r\n"
	"a=control:streamid=0 \r\n"
	);

	return 0;
}

/*filled by yaoyao*/ // start response: media sending process to client in media server
int uas_send_Playmedia()
{
	printf("uas_send_Playmedia\n");
	return 0;
}

/*filled by yaoyao*/ // close media sending process to client in media server
int uas_close_Playmedia()
{
	printf("uas_close_Playmedia\n");
	return 0;
}

// handle rtsp data via INFO, received from client by media server
int uas_handle_Historyrtsp(char *rtsp_data)
{
	printf("uas_handle_Historyrtsp\n");
	return 0;
}

// get MESSAGE for sending to client in media server
// p -> 1024 bytes
int get_HistoryEOFmessage(char *message, char *message_type)
{
	// message_type: "EOF"
	snprintf(message,1024,
			"<?xml version=\"1.0\"?>"
			"<Notify>"
			"<CmdType>MediaStatus</CmdType>"
			"<SN>8</SN>"
			"<DeviceID>000</DeviceID>"
			"<NotifyType>121</NotifyType>"
			"</Notify>");
	return 0;
}

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
			return -1;
	}
	else
		return -1;
	return 1;
}

int uac_start_media()
{
	if(user_type==USER_TYPE_IPC)
		;//uac_send_Transportmedia();
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_receive_Playmedia();
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_receive_Historymedia();
		else
			return -1;
	}
	else
		return -1;
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
			return -1;
	}
	else
		return -1;
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
			return -1;
	}
	else
		return -1;
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
			return -1;
	}
	else
		return -1;
	return 1;}

int uas_start_media()
{
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_receive_Transportmedia();
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_send_Playmedia();
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_send_Historymedia();
		else
			return -1;
	}
	else
		return -1;
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
			return -1;
	}
	else
		return -1;
	return 1;}

//end uas interface



