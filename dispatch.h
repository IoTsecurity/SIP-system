/*
 * dispatch.h
 *
 *  Created on: 2014年2月13日
 *      Author: root
 */

#ifndef DISPATCH_H_
#define DISPATCH_H_

#include "interface.h"
#include "csenn_eXosip2.h"
#include "sip_com.h"

//#define DATA_LEN 4096

extern int user_type;
extern int call_type;
extern int invite_user_type;
extern int invite_type;

#define USER_TYPE_IPC 		IPC
#define USER_TYPE_CLIENT 		Client
#define USER_TYPE_NVR 		NVR


#define CALL_TYPE_PLAY 		1
#define CALL_TYPE_PLAYBACK 		2


#define INVITE_USER_TYPE_IPC 	1
#define INVITE_USER_TYPE_CLIENT 	2


#define INVITE_TYPE_PLAY 		1
#define INVITE_TYPE_PLAYBACK 	2

//init
//int interface_init();

//uac

int uac_get_sdp(char *sdp_data);

int uac_handle_sdp(char *sdp_data);

int uac_start_media(char * peer_location);

int uac_close_media();

//uas

int uas_handle_sdp(char *sdp_data);

int uas_get_sdp(char *sdp_data);

int uas_start_media(char * peer_location);

int uas_close_media();

//register

int handle_401_Unauthorized_data(void *data);

int get_register2_data(char *data,char * auth_active_packet_data);

int handle_response_data(void *data,void *access_auth_request_packet_data);

//end uac uas call interface function
//////////////////////////////////////////////////////////////

#endif /* DISPATCH_H_ */
