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

extern RegisterContext *RegisterCon;			/* 注册使用的上下文 */
extern AuthActive *authactive_data;			/* 认证 */
extern P2PLinkContext * P2PLinkContext_data;
extern AccessAuthRequ *auth_request_packet_data;

#define CHARLEN 32

/*-----------------common function----------------------*/

/* 读入配置文件的一条信息 */
int get_conf_value( char *key_name, char *value,char *filename);

/* 初始化读入配置文件 */
int init_Contextconf(char * file);

/* 编码字符 */
int codeToChar(char *data,int lenth);

/* 解码字符 */
int decodeFromChar(char *data,int lenth);

/* 获取网络信息，包括ip地址和mac地址，如果值获取其中一个，可以指定另外一个为NULL */
int getNetInfo(char* outip,char *outmac);

/* mac地址 从字符串类型转化为16进制类型 */
int mac_stox(char *x,char * s);



#endif /* SIP_COM_H_ */
