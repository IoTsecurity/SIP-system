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

#define DATA_LEN 4096

int user_type;
int call_type;
int invite_user_type;
int invite_type;

extern int user_type;
extern int call_type;
extern int invite_user_type;
extern int invite_type;

RegisterContext * RegisterCon;
extern RegisterContext * RegisterCon;

#define USER_TYPE_IPC 		1
#define USER_TYPE_CLIENT 		2
#define USER_TYPE_NVR 		3


#define CALL_TYPE_PLAY 		1
#define CALL_TYPE_PLAYBACK 		2


#define INVITE_USER_TYPE_IPC 	1
#define INVITE_USER_TYPE_CLIENT 	2


#define INVITE_TYPE_PLAY 		1
#define INVITE_TYPE_PLAYBACK 	2

/*
typedef void (*funcP)();

funcP uas_handle_invite_sdp;	//1 char *
funcP uas_get_invite_sdp;		//1 char **
funcP uas_start_transport;		//0				//maybe more time and should use multithread
funcP uas_handle_Message;		//1	char *		//maybe more time and should use multithread
funcP uas_stop_transport;		//0
funcP uas_get_info;				//char *message, char *message_type
									//get info data
*/
//int uas_function_run(funcP fun_name,void(*arg));

////////////////////////////filled by jiangzaiwei//////////////////////////////////
//begin uac uas call interface function

//init
int interface_init();

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

int get_register2_data(void **data,void * auth_active_packet_data);

int handle_response_data(void *data,void *access_auth_request_packet_data);

//end uac uas call interface function
//////////////////////////////////////////////////////////////

int codeTOChar(char *data,int lenth);

int decodeFromChar(char *data,int lenth);

int init_Contextconf(char * file);

#endif /* DISPATCH_H_ */
