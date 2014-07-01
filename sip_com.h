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

extern RegisterContext *RegisterCon;                    // 注册使用的上下文
extern AuthActive *authactive_data;                     // 注册第二步认证数据包，后面需要使用
extern AccessAuthRequ *auth_request_packet_data;        // 注册认证是使用的数据结构   （后续分析可以作为局部变量，可以修改）
extern P2PLinkContext * P2PLinkContext_data;            // 在密钥分发时需要使用的上下文结构体
extern P2PCommContext *p2pcc;                           // p2p交互时需要使用的上下文结构体

#define P2PAUTH_SUBJECT ("P2Pauthentication")           // token交互时第一次认证时的标示
#define P2PREAUTH_SUBJECT ("P2Preauthentication")       // token交互时重认证时的标示
#define P2PBYESESSION_SUBJECT ("P2PByesession")         // token交互时Byesession时的标示
#define P2PBYELINK_SUBJECT ("P2PByelink")               // token交互时Byelink时的标示

#define CHARLEN 32                                      // 字符限长，用于用户名等


/*-----------------common function----------------------*/


/*================================================================
* Function: get_conf_value
* Descripts: 从指定的配置文件中，对于一个键名读入相应的键值
* Parameter： (input) const char *key_name     : 键值名称
*             (output) char *value              : 对应读入的值
*             (input) const char *filename      : 配置文件名及路径
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int get_conf_value( const char *key_name, char *value, const char *filename);


/*================================================================
* Function: init_Contextconf
* Descripts: 从指定的配置文件中，读入相应的配置
* Parameter： (input) const char *file      : 配置文件名及路径
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int init_Contextconf(const char * file);


/*================================================================
* Function: codeToChar
* Descripts: 编码字符， 对于data指向的数据进行编码，，编码后的数据覆盖编码前的数据存放在data里
* Parameter： (input) char *data      : 指向需要编码的数据
*             (input) const int lenth : 编码完数据的长度，编码后为编码前的2倍
* Other: 现在的算法为简单的把一个字节的数据变为两个字节的字符，后期可能需要修改
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int codeToChar(char *data,const int lenth);


/*================================================================
* Function: codeToChar
* Descripts: 解码字符， 对于data指向的数据进行编码，解码后的数据覆盖解码前的数据存放在data里
* Parameter： (input) char *data      : 指向需要解码的数据
*             (input) const int lenth : 解码前的长度，一般解码前是解码后的两倍
* Other: 和编码函数存在相同的问题
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int decodeFromChar(char *data, const int lenth);


/*================================================================
* Function: getNetInfo
* Descripts: 获取网络信息，包括ip地址和mac地址，如果只获取其中一个，可以指定另外一个为NULL
* Parameter： (output) char* outip      : 输出自己的ip地址
*             (output) char *outmac     : 输出自己的mac地址
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int getNetInfo(char* outip,char *outmac);


/*================================================================
* Function: mac_stox
* Descripts: mac地址 从字符串类型转化为16进制类型
* Parameter： (output) char *x            : 输出的16进制mac地址
*             (input) const char * s      : 输入字符串类型的mac地址（00：01:02:03:04:05）
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int mac_stox(char *x,const char * s);

/*================================================================
* Function: printfx_s
* Descripts: mac地址 从字符串类型转化为16进制类型
* Parameter： (output) char *x            : 输出的16进制mac地址
*             (input) const char * s      : 输入字符串类型的mac地址（00：01:02:03:04:05）
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
//int printfx_s( const unsigned char *p, const int len);

/*================================================================
* Function: printfx
* Descripts: 测试语句，在屏幕上打印数据的二进制信息
* Parameter： (output) const unsigned char *p           : 指向需要打印的数据区域
*             (input) const int len                     : 该数据区域的长度
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int printfx(const unsigned char *p, const int len);

/*================================================================
* Function: P2PLinkContext_Conversion_C
* Descripts: 在sip客户端中用注册上下文初始化密钥协商上下文
* Parameter： (input) const RegisterContext *rc             : 注册上下文结构
*             (output) P2PLinkContext *lc                   : 需要初始化的密钥协商上下文结构
*             (input) const enum DeviceType target_type     : 对方的设备类型
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int P2PLinkContext_Conversion_C(const RegisterContext *rc, P2PLinkContext *lc, const enum DeviceType target_type);

/*================================================================
* Function: P2PLinkContext_Conversion_C
* Descripts: 在sip服务端中用注册上下文初始化密钥协商上下文，因为用户1和用户2需要通信，所以需要同时初始化他们
* Parameter： (input) const RegisterContext *rc_IPC             : 用户1的注册上下文
*             (input) const RegisterContext *rc_NVR             : 用户2的注册上下文
*             (output) P2PLinkContext *lc_to_IPC                : 需要初始化的用户1的密钥协商上下文
*             (output) P2PLinkContext *lc_to_NVR                : 需要初始化的用户2的密钥协商上下文
* Other: 在client接入时需要判断，这一步还未测试
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int P2PLinkContext_Conversion_S(const RegisterContext *rc_IPC, const RegisterContext *rc_NVR,
		P2PLinkContext *lc_to_IPC, P2PLinkContext *lc_to_NVR);

/*================================================================
* Function: P2PCommContext_Conversion
* Descripts: 在密钥协商之前需要转化上下文数据结构，该函数用密钥协商上下文结构初始化p2p交互上下文结构
* Parameter： (input) const P2PLinkContext *lc             : 密钥协商上下文结构
*             (output) P2PCommContext *cc                    : 需要初始化的p2p上下文结构
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int P2PCommContext_Conversion(const P2PLinkContext *lc,P2PCommContext *cc);




#endif /* SIP_COM_H_ */
