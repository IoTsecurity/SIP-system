/*
 * interface.c
 *
 *  Created on: 2014年1月2日
 *      Author: root
 */
#include "interface.h"

//end uac interface

// get sdp, fill in INVITE, send to media server by client
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

// handle sdp received from media server in client
int uac_handle_Playsdp(char *sdp_data)
{
	return 0;
}

// start request: media receiving process from media server in client
int uac_receive_Playmedia()
{

	return 0;
}

// get rtsp data, fill in INFO for sending to media server by client
int uac_get_rtsp(char *rtsp_data, struct st_rtsptype  *ptr_st_rtsptype)
{
	// if rtsp datatype in {"PLAY", "FAST", "SLOW"}: check scale
	snprintf(rtsp_data,1024,
				"this is test data!");
	return 0;
}

// handle MESSAGE, received from media server in client
int uac_handle_message(char *message)
{
	return 0;
}

// close media receiving process from media server in client
int uac_close_Playmedia()
{

	return 0;
}

//end uac interface


//begin uas interface

int uas_function_run(funcP fun_name,void(*arg))
{
	(*fun_name)(arg);
	return 0;
	}

// handle sdp data via INVITE received from client in media server
int uas_handle_Playsdp(char *sdp_data)
{
	//

	printf("handle_invite2:%s\n",sdp_data);
	return 0;
	}

// get sdp data for sending to client in media server
// p -> 1024 bytes
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

// start response: media sending process to client in media server
int uas_send_Playmedia()
{
	return 0;
}

// handle rtsp data via INFO, received from client by media server
int uas_handle_rtsp(char *rtsp_data)
{
	return 0;
}

// get MESSAGE for sending to client in media server
// p -> 1024 bytes
int get_message(char *message, char *message_type)
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

// close media sending process to client in media server
int uas_close_Playmedia()
{
	return 0;
}

int interface_init()
{
	uas_handle_invite_sdp=uas_handle_Playsdp;
	uas_get_invite_sdp=uas_get_Playsdp;
	uas_start_transport=uas_send_Playmedia;
	uas_handle_Message=uas_handle_rtsp;
	uas_stop_transport=uas_close_Playmedia;
	//uas_get_info=uas_get_message;
	return 0;
	}

//end uas interface



