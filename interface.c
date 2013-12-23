/*
 * interface.c
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */

// get sdp, fill in INVITE, send to media server by client
int get_sdp(char *sdp_data)
{

}

// handle sdp received from media server in client
int handle_sdp(char *sdp_data)
{

}

// start request: media receiving process from media server in client
int receive_media()
{

}

// get rtsp data, fill in INFO for sending to media server by client
struct st_rtsptype{
	char *rtsp_datatype;// rtsp datatype: "PLAY", "PAUSE", "TEARDOWN", "FAST", "SLOW"
	int scale;

};
int get_rtsp(char *rtsp_data, struct *ptr_st_rtsptype)
{
	// if rtsp datatype in {"PLAY", "FAST", "SLOW"}: check scale

}

// handle MESSAGE, received from media server in client
int handle_message(char *message)
{

}

// close media receiving process from media server in client
int close_media()
{

}



