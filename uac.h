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

#include "interface.h"
#include <string.h>

#ifndef UAC_H
#define UAC_H


/*================================================================
* funtion name：uac_init
* parameter：void
* descripts:init the uac
* ..............
* return：0 for sucess, -1 for failure
================================================================*/
int uac_init();

/*================================================================
* funtion name：uac_register
* parameter：void
* descripts:send the register to the sip server
* ..............
* return：0 for sucess, -1 for failure
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
* return：0 for sucess, -1 for failure
================================================================*/
int uac_invite(sessionId * inviteId,char *to,
		char * sdp_message,char * responseSdp);

//send bye request by the inviteID
int uac_bye(sessionId inviteId);

//send INFO package by the inviteID
int uac_send_info(sessionId inviteId);

//send MESSAGE/INFO (according to type_info) package by the inviteID
int uac_send_message(sessionId inviteId,char * type ,
		char * type_info,char * message_str);

//获取地址
//返回IP地址字符串
int getlocalip(char* outip);

//get the key_value from the configure file by the key_name
int get_conf_value( char *key_name, char *value);

//init the configure file
int init_conf(char * file);

#endif
