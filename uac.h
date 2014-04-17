/*
 * uac.h
 *
 *	Describe:
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */

#include "csenn_eXosip2.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "dispatch.h"
#include <string.h>

#ifndef UAC_H
#define UAC_H

typedef struct sip_entity_{
	char ip[4*3+3+1];
	int port;
	char username[CHARLEN];
}sip_entity;

typedef struct alter_message_{
	char * subject;			// 消息的subject字段
	char * method_type;		// 请求方式字段，消息是INFO还是MESSAGE
	char * content_type;		// 消息Content_Type字段，body中的类型，如"Application/MANSRTSP" ，"text/code" 等
	char * body;				// 消息中的Message Body，有效负荷，承载的消息
	char * route;				// 消息route字段
}alter_message;

//#define CharLen 50

//char *auth_request_packet_data;
//extern char *auth_request_packet_data;

/*================================================================
* funtion name：uac_init
* parameter：void
* descripts:init the uac
* ..............
* return：1 for sucess, 0 for failure
================================================================*/
int uac_init();

/*================================================================
* funtion name：uac_register
* parameter：void
* descripts:send the register to the sip server
* ..............
* return：1 for sucess, 0 for failure
================================================================*/
int uac_register();

/*================================================================
* funtion name：uac_invite
* parameter：	sessionId * inviteId,
 				char *to,
				char * sdp_message,
				char * responseSdp
* descripts:send the invite request
* ..............
* return：1 for sucess, 0 for failure
================================================================*/
int uac_invite(sessionId * inviteId,char *to,
		char * sdp_message,char * responseSdp);

//send bye request by the inviteID
int uac_bye(sessionId inviteId);

//send INFO package by the inviteID
int uac_send_info(sessionId inviteId);

//send MESSAGE/INFO (according to type_info) package by the inviteID
//int uac_send_message(sessionId inviteId,char * type ,char * type_info,char * message_str,char * subject);
int uac_send_message(sessionId inviteId,  alter_message * alter_m);

//int uac_send_noSessionMessage(char * to, char * from, char * route,char * content,char * subject);
int uac_send_noSessionMessage(sip_entity* to, alter_message * alter_m);

int uac_key_nego();

int uac_waitfor(sessionId* id, eXosip_event_type_t t,eXosip_event_t **event);

int uac_sendInvite(sessionId * id, sip_entity* to, alter_message * alter_m);

/* 跟一个sip ua 第一次交换token， 进行p2p通信 */
int uac_token_exchange(sip_entity* target);

//init the configure file
int init_conf(char * file);



#endif
