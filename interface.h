/*
 * interface.h
 *
 *  Created on: 2013年12月18日
 *      Author: jzw yaoyao
 */
#ifndef INTERFACE_H
#define INTERFACE_H

#define DATA_LEN 4096

int user_type;
int call_type;
int invite_user_type;
int invite_type;

extern int user_type;
extern int call_type;
extern int invite_user_type;
extern int invite_type;

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

/////////////////////////// filled by yaoyao ///////////////////////////////////
/* Scene 1 :
 * Register and authentication process
 * (step 1-6 11-16)
 */
enum DeviceType{
	IPC,
	SIPserver,
	NVR
};
typedef struct KeyData{
	//
}KeyData;
typedef struct KeyRing{
	char *key_partner_id;
	unsigned char master[];
	unsigned char CK[];
	unsigned char IK[];
	unsigned char KEK[];
	unsigned char reauth_IK[];
}KeyRing;
typedef struct MACaddr{
	char macaddr[6];
}MACaddr;

#define MAXKEYRINGS 10
typedef struct RegisterContext{
	char *radius_id;
	char *peer_id;
	char *self_id;
	char *self_password;
	enum DeviceType self_type;
	KeyData keydata;
	MACaddr self_MACaddr;
	MACaddr peer_MACaddr;
	unsigned char auth_id_next[32];
	unsigned char MK_ID[16];
	unsigned char self_randnum_next[];
	unsigned char peer_randnum_next[];
	unsigned char self_rtp_port;
	unsigned char self_rtcp_port;
	unsigned char peer_rtp_port;
	unsigned char peer_rtcp_port;
	unsigned char nonce_seed[];
	KeyRing key_table[MAXKEYRINGS];
}RegisterContext;

//<auth active packet>
int ProcessWAPIProtocolAuthActive(RegisterContext *rc,
AuthActive *auth_active_packet);

int HandleWAPIProtocolAuthActive(RegisterContext *rc,
AuthActive *auth_active_packet);

//<access auth request packet>
int ProcessWAPIProtocolAccessAuthRequest(RegisterContext *rc,
AuthActive *auth_active_packet, AccessAuthRequ *access_auth_requ_packet);

int HandleWAPIProtocolAccessAuthRequest(RegisterContext *rc,
AuthActive *auth_active_packet,
AccessAuthRequ *access_auth_requ_packet);

//<access auth response packet>
int HandleWAPIProtocolAccessAuthResp(RegisterContext *rc,
AccessAuthRequ *access_auth_requ_packet,AccessAuthResp *access_auth_resp_packet);

//Unicast key negotiation request
int ProcessUnicastKeyNegoRequest(RegisterContext *rc,
UnicastKeyNegoRequ *unicast_key_nego_requ_packet);

int HandleUnicastKeyNegoRequest(RegisterContext *rc,
const UnicastKeyNegoRequ *unicast_key_nego_requ_packet);

//Unicast key negotiation Response
int ProcessUnicastKeyNegoResponse(RegisterContext *rc,
UnicastKeyNegoResp *unicast_key_nego_resp_packet);

int HandleUnicastKeyNegoResponse(RegisterContext *rc,
const UnicastKeyNegoResp *unicast_key_nego_resp_packet);

//Unicast key negotiation Confirm
int ProcessUnicastKeyNegoConfirm(RegisterContext *rc,
UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet);

int HandleUnicastKeyNegoConfirm(RegisterContext *rc,
const UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet);

/* Scene 1 :
 * Key negotiation process
 * (step 7-10 17-20)
 */

/* Scene 1 :
 * IPC access to NVR process
 * (step 21-22)
 */

/* Scene 1 :
 * IPC communicate to NVR process
 * (step 23-30)
 */
/////////////////////////// written by yaoyao ///////////////////////////////////
/* uac Transport beteewn IPC and NVR interface begin */
int uac_get_Transportsdp(char *sdp_data);
int uac_handle_Transportsdp(char *sdp_data);
int uac_send_Transportmedia();
int uac_close_Transportmedia();
/*uac Transport beteewn IPC and NVR interface end*/

/*uas Transport beteewn IPC and NVR interface begin*/
int uas_handle_Transportsdp(char *sdp_data);
int uas_get_Transportsdp(char *sdp_data);
int uas_receive_Transportmedia();
int uas_close_Transportmedia();
/* uas Transport beteewn IPC and NVR interface end */

/* uac PLAY interface begin */
// get sdp, fill in INVITE, send to media server by client by Play way
int uac_get_Playsdp(char *sdp_data);
// handle sdp received from media server in client by Play way
int uac_handle_Playsdp(char *sdp_data);
// start request: media receiving process from media server in client
int uac_receive_Playmedia();
// close media receiving process from media server in client
int uac_close_Playmedia();
/*uac PLAY interface end*/

/*uas PLAY interface begin*/
// handle sdp data via INVITE received from client in media server
int uas_handle_Playsdp(char *sdp_data);
// get sdp data for sending to client in media server
// p -> 1024 bytes
int uas_get_Playsdp(char *sdp_data);
// start response: media sending process to client in media server
int uas_send_Playmedia();
// close media sending process to client in media server
int uas_close_Playmedia();
/*uas PLAY interface end*/
//////////////////////////////////////////////////////////////

////////////////////////////filled by liuqinghao//////////////////////////////////
/*uac PLAYBACK interface end*/

int uac_get_Historysdp(char *sdp_data);

int uac_handle_Historysdp(char *sdp_data);

int uac_receive_Historymedia();

int uac_close_Historymedia();

// get rtsp data, fill in INFO for sending to media server by client
struct st_rtsptype{
	char *rtsp_datatype;// rtsp datatype: "PLAY", "PAUSE", "TEARDOWN", "FAST", "SLOW"
	//int scale;
	float scale;	//modify by jzw, because it will be 0.5

};

int uac_get_Historyrtsp(char *rtsp_data, struct st_rtsptype  *ptr_st_rtsptype);

// handle MESSAGE, received from media server in client
int handle_HistoryEOFmessage(char *message);

/*uac PLAYBACK interface end*/


/*uas PLAYBACK interface begin*/

int uas_handle_Historysdp(char *sdp_data);

int uas_get_Historysdp(char *sdp_data);

int uas_send_Historymedia();

int uas_close_Historymedia();

// handle rtsp data via INFO, received from client by media server
int uas_handle_Historyrtsp(char *rtsp_data);

// get MESSAGE for sending to client in media server
// p -> 1024 bytes
int get_HistoryEOFmessage(char *message, char *message_type);

/*uas PLAYBACK interface end*/
//////////////////////////////////////////////////////////////



/////////////////////////////filled by lvshichao/////////////////////////////////
//begin register interface
/*=========================================
* funtion handle_ceat_auth_request_packet
* parameter：	(input)	char * cert_auth_request_packet,
				(output)	char * cert_auth_response_packet
* descripts:	handle ceat auth request packet
* 				and fill the cert auth response packet
* ..............
* return：0 for sucess, -1 for failure
===========================================*/
int handle_ceat_auth_request_packet(char * cert_auth_request_packet,
		char * cert_auth_response_packet);

//end register interface
//////////////////////////////////////////////////////////////

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

int get_register2_data(void *data);

int handle_response_data(void *data);

//end uac uas call interface function
//////////////////////////////////////////////////////////////
#endif

