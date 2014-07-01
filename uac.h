/*
 * uac.h
 *
 *	Describe:
 *
 *  Created on: 2013年12月18日
 *      Author: jzw
 */

//#include "csenn_eXosip2.h"
#include <eXosip2/eXosip.h>
#include <osip2/osip_mt.h>

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

#define DEFAULT_CFG ("default.cfg")	// 默认配置文件，如果程序没有跟配置文件参数，
											// 就读取默认配置文件，如果没有默认配置文件，程序出错返回
#define CONTENT_CODE ("text/code")    // sip载荷标示
#define METHODMESSAGE ("MESSAGE")     // Message消息标示
#define METHODINFO ("INFO")           // INFO消息标示

#define IPLEN		16                   //ip长度
#define CALLIDLEN		30               // callid字符限长

extern int g_register_id  ;//= 0;/*注册ID/用来更新注册或取消注册*/
extern int g_call_id      ;//= 0;/*INVITE连接ID/用来分辨不同的INVITE连接，每个时刻只允许有一个INVITE连接*/
extern int g_did_realPlay ;//= 0;/*会话ID/用来分辨不同的会话：实时视音频点播*/
extern int g_did_backPlay ;//= 0;/*会话ID/用来分辨不同的会话：历史视音频回放*/
extern int g_did_fileDown ;//= 0;/*会话ID/用来分辨不同的会话：视音频文件下载*/

struct _device_info/*设备信息结构体*/
{
	char *server_id;/*SIP服务器ID*//*默认值：34020000002000000001*/
	char *server_ip;/*SIP服务器IP地址*//*默认值：192.168.1.178*/
	char *server_port;/*SIP服务器IP端口*//*默认值：5060*/

	char *ipc_id;/*媒体流发送者ID*//*默认值：34020000001180000002*/
	char *ipc_pwd;/*媒体流发送者密码*//*默认值：12345678*/
	char *ipc_ip;/*媒体流发送者IP地址*//*默认值：192.168.1.144*/
	char *ipc_port;/*媒体流发送者IP端口*//*默认值：6000*/

	char *device_name;/*设备/区域/系统名称*//*默认值：IPC*/
	char *device_manufacturer;/*设备厂商*//*默认值：CSENN*/
	char *device_model;/*设备型号*//*默认值：GB28181*/
	char *device_firmware;/*设备固件版本*//*默认值：V1.0*/
	char *device_encode;/*是否编码*//*取值范围：ON/OFF*//*默认值：ON*/
	char *device_record;/*是否录像*//*取值范围：ON/OFF*//*默认值：OFF*/

	char * cfgFile;
	char * radius_id;
}device_info;

struct _device_status/*设备状态结构体*/
{
	char *status_on;/*设备打开状态*//*取值范围：ON/OFF*//*默认值：ON*/
	char *status_ok;/*是否正常工作*//*取值范围：OK/ERROR*//*默认值：OFF*/
	char *status_online;/*是否在线*//*取值范围：ONLINE/OFFLINE*//*默认值：ONLINE*/
	char *status_guard;/*布防状态*//*取值范围：ONDUTY/OFFDUTY/ALARM*//*默认值：OFFDUTY*/
	char *status_time;/*设备日期和时间*//*格式：xxxx-xx-xxTxx:xx:xx*//*默认值：2012-12-20T12:12:20*/
}device_status;

typedef struct _sessionId{
	int cid;
	int did;
	char call_id[30];

}sessionId;

typedef struct sip_entity_{
	char ip[IPLEN];			// sip实体的ip
	int port;					// sip实体的端口
	char username[CHARLEN];	// sip实体的用户名
}sip_entity;

typedef struct alter_message_{
	char * subject;			// 消息的subject字段
	char * method_type;		// 请求方式字段，消息是INFO还是MESSAGE
	char * content_type;		// 消息Content_Type字段，body中的类型，如"Application/MANSRTSP" ，"text/code" 等
	char * body;				// 消息中的Message Body，有效负荷，承载的消息
	char * route;				// 消息route字段
}alter_message;

typedef enum TokenType_{
	Auth,                    //authentication token
	Reauth,                  //reauthentication token
	Byesession,              //Byesession token
	Byelink                  //Byelink token
}TokenType;

/*被调函数*/
/*启动并注册eXosip*/
void csenn_eXosip_launch(void);

/* send invite message */
//int csenn_eXosip_sendinvite(char * to,char * sdpMessage, char ** responseSdp,sessionId * id);//by jzw
int csenn_eXosip_invit(sessionId * id, char * to, char * sdpMessage, char * responseSdp);

/*================================================================
* Function: check_conf
* Descripts: 确认配置文件是否存在可用
* Parameter： (input) const char * file : 文件名及路径
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int check_conf(const char * file);


/*================================================================
* Funtion： uac_init
* Descripts: 初始化sip客户端
* Parameter： (input) const char *conf  :配置文件名及其路径
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_init(const char *conf);


/*================================================================
* Funtion： uac_register
* Descripts: 向服务器发出一系列注册动作
* Parameter： void
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_register();


/*================================================================
* Funtion： uac_invite
* Descripts:向目标发送invite动作，并携带sdp数据，获取到对方的sdp数据，
*             并把会话号记录到inviteId里面 （该函数后续可能会修改）
* Parameter：	(output)  sessionId * inviteId       ：用来保存成功的会话号
 				(input)  const char *to              ：发出invite的对象，格式为：”用户名@ip：端口“ （后续可能需要修改）
				(input)  const char * sdp_message    ：需要发给对方的sdp数据
				(output) char * responseSdp          ：获取到的sdp数据
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_invite(sessionId * inviteId,const char *to,
		const char * sdp_message,char * responseSdp);


/*================================================================
* Funtion： uac_bye
* Descripts: 根据会话号来终止该会话
* Parameter：	(input) const sessionId Id    ：会话号
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_bye(const sessionId Id);


/*================================================================
* Funtion： uac_send_info
* Descripts: 根据会话号来发送INFO消息，并携带MANSRTSP指令
* Parameter：	(input) const sessionId Id    ：会话号
* Other: （后续可能会修改，修改成传入的参数中有MANSRTSP指令，这样更灵活）
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_send_info(const sessionId Id);


/*================================================================
* Funtion： uac_send_message
* Descripts: 根据会话号来发送Message消息，该消息是必须需要建立会话才能发送的
* Parameter：	(input) const sessionId Id               ：会话号
*             (input) const alter_message * alter_m    ：需要修改的信息
*                     alter_message结构中的参数method_type ：（必须）信息类型，指定是message还是info消息
*                                            body        ：（必须）消息携带的负荷
*                                            content_type：（必选）消息的标示
*                                            subject     ：（可选）消息的主题
* Other:（返回值可能需要修改）
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_send_message(const sessionId inviteId, const alter_message * alter_m);


/*================================================================
* Funtion： uac_send_noSessionMessage
* Descripts: 根据目标to来发送无会话Message
* Parameter：	(input) const sip_entity* to             ：发送目标
*             (input) const alter_message * alter_m    ：需要修改的信息
*                      alter_message结构中的参数method_type ：（必须）信息类型，指定是message还是info消息
*                                             body        ：（必须）消息携带的负荷
*                                             content_type：（必选）消息的标示
*                                             subject     ：（可选）消息的主题
*                                             route       ：（可选）消息的路由，一般为NULL
* Other:（返回值可能需要修改）
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_send_noSessionMessage(const sip_entity* to, const alter_message * alter_m);


/*================================================================
* Funtion： uac_key_nego
* Descripts: 与服务器进行密钥协商
* Parameter：(void)
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_key_nego();


/*================================================================
* Funtion： uac_key_distribute
* Descripts: 与服务器进行密钥分发阶段，并得到对方的sip信息，这个便于后面p2p交互
* Parameter： (input) const char *peer_id             :对方的用户名
*             (output) sip_entity *sip_target         :得到的对方的sip信息
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_key_distribute(const char *peer_id, sip_entity *sip_target);


/*================================================================
* Funtion： uac_waitfor
* Descripts: 根据会话id号等待消息，如果接收到消息类型为t时返回1，其他消息则返回0，没有消息时event为NULL
* Parameter： (input) const sessionId* id             ：会话的ID号
*             (input) const eXosip_event_type_t t     ：需要对方返回的消息类型
*             (output) eXosip_event_t **event         ：接受到的消息
* Other:
* ..............
* Return： 接收到消息类型为t时返回 1, 其他消息或者没有消息则返回 0
================================================================*/
int uac_waitfor(const sessionId* id, const eXosip_event_type_t t,eXosip_event_t **event);


/*================================================================
* Funtion： uac_sendInvite
* Descripts: 向目标目标发送invite请求，并把成功的会话号记录到id上去，便于后面管理这个会话
* Parameter： (output) sessionId * id                    ：会话的ID号
*             (input) const sip_entity* to              ：目标sip
*             (input) const alter_message * alter_m     ：需要发送的消息
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_sendInvite(sessionId * id, const sip_entity* to, const alter_message * alter_m);


/*================================================================
* Funtion： uac_token_exchange
* Descripts: 与目标sip进行token交互
* Parameter： (input) const sip_entity* to             ：目标sip
*             (input) const TokenType toketype_        ：token类型，可能是认证token交互，重认证token交互，
*                                                         会话结束token交互，链路结合token交互
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int uac_token_exchange(const sip_entity* to,const TokenType toketype_);


/*================================================================
* Funtion： send_token
* Descripts: 向目标sip发送token信息
* Parameter： (input) const sip_entity* to             ：目标sip
*             (input) const TokenType toketype_        ：token类型
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int send_token(const sip_entity* to, const TokenType toketype_);


/*================================================================
* Funtion： handle_token
* Descripts: 对于接受到的token信息进行处理
* Parameter： (input) const osip_message_t *sip_message     ：接受到的token信息
*             (input) const TokenType toketype_             ：token类型
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int handle_token(const osip_message_t *sip_message, const TokenType toketype_);


/*================================================================
* Funtion： getSipEntity
* Descripts: 从sip消息中获取对方sip实体的信息
* Parameter： (output)       sip_entity * target_sip                     ：需要得到的sip实体信息
*             (input) const const osip_message_t *sip_message            ：sip消息
* Other:
* ..............
* Return： 1 for success, 0 for failure
================================================================*/
int getSipEntity(sip_entity * target_sip, const osip_message_t *sip_message);

#endif
