/*
 * interface.c
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */
#ifndef INTERFACE_H
#define INTERFACE_H

//end uac interface

// get sdp, fill in INVITE, send to media server by client
//int uac_get_sdp(char *sdp_data);

// handle sdp received from media server in client
//int uac_handle_sdp(char *sdp_data);

/*filled by yaoyao*/ // get sdp, fill in INVITE, send to media server by client by Play way
int uac_get_Playsdp(char *sdp_data);

/*filled by yaoyao*/ // handle sdp received from media server in client by Play way
int uac_handle_Playsdp(char *sdp_data);

/*filled by yaoyao*/ // start request: media receiving process from media server in client
int uac_receive_Playmedia();

/*filled by yaoyao*/ // close media receiving process from media server in client
int uac_close_Playmedia();

// get rtsp data, fill in INFO for sending to media server by client
struct st_rtsptype{
	char *rtsp_datatype;// rtsp datatype: "PLAY", "PAUSE", "TEARDOWN", "FAST", "SLOW"
	//int scale;
	float scale;	//modify by jzw, because it will be 0.5

};

int uac_get_rtsp(char *rtsp_data, struct st_rtsptype  *ptr_st_rtsptype);

// handle MESSAGE, received from media server in client
int uac_handle_message(char *message);



//end uac interface


//begin uas interface

typedef void (*funcP)();

funcP uas_handle_invite_sdp;	//1 char *
funcP uas_get_invite_sdp;		//1 char **
funcP uas_start_transport;		//0				//maybe more time and should use multithread
funcP uas_handle_Message;		//1	char *		//maybe more time and should use multithread
funcP uas_stop_transport;		//0
funcP uas_get_info;				//char *message, char *message_type
									//get info data

/*filled by yaoyao*/ // handle sdp data via INVITE received from client in media server
int uas_handle_Playsdp(char *sdp_data);

/*filled by yaoyao*/ // get sdp data for sending to client in media server
/*filled by yaoyao*/ // p -> 1024 bytes
int uas_get_Playsdp(char *sdp_data);

/*filled by yaoyao*/ // start response: media sending process to client in media server
int uas_send_Playmedia();

/*filled by yaoyao*/ // close media sending process to client in media server
int uas_close_Playmedia();

int uas_function_run(funcP fun_name,void(*arg));

// handle rtsp data via INFO, received from client by media server
int uas_handle_rtsp(char *rtsp_data);

// get MESSAGE for sending to client in media server
// p -> 1024 bytes
int get_message(char *message, char *message_type);

int interface_init();

//end uas interface

#endif

