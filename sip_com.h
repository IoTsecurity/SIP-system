/*
 * 	File name: 	sip_com.h
 *	Description:	the common funtions works in the SIP UA and SIP SERVER
 *
 * Created on: 	2014年3月20日
 * Author: 		jiangzaiwei
 */

#ifndef SIP_COM_H_
#define SIP_COM_H_

#include "interface.h"

extern RegisterContext *RegisterCon;			//the rigsiter
extern AuthActive *authactive_data;
extern P2PLinkContext * P2PLinkContext_data;
extern char *auth_request_packet_data;

#define CHARLEN 50

/*-----------------common function----------------------*/

int get_conf_value( char *key_name, char *value,char *filename);

int init_Contextconf(char * file);

int codeToChar(char *data,int lenth);

int decodeFromChar(char *data,int lenth);

int getNetInfo(char* outip,char *outmac);

int mac_stox(char *x,char * s);



#endif /* SIP_COM_H_ */
