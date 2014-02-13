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

#include <stdio.h>
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <memory.h>
#include <errno.h>
#include <pthread.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket

#define CHAT_SERVER_PORT    (1111)


#define MAC_LEN                  6           /* MAC地址长度 */
#define MAX_COMM_DATA_LEN        65535       /* 通用数据的最大长度 */
#define MAX_X509_DATA_LEN        1024 * 4    /* 存放X509DER编解码缓冲的最大长度 */
#define MAX_BYTE_DATA_LEN        256	     /* 最大字节数据长度 */
#define RAND_LEN                 32          /* 随机数长度 */

#define MAX_IDENTITY_NUMBER      16          /* 身份列表最大身份个数 */
//#define USER_DN_SIZE             16          /* 认证服务器的每个用户(客户端)的DN(distinguished name)长度 */
#define USER_AMOUNT_MAX          10          /* 认证服务器支持的最大用户(客户端)数量 */

#define NOT_LOGIN    (-1)
#define NOT_IN_USE    (NOT_LOGIN -1)

#define    NO_COMMAND    (100)

/************************************************************
*WAI协议分组基本格式包头，分组子类型定义
*************************************************************/
#define PRE_AUTH_BEGIN          (1)
#define STA_KEY_REQU            (2)
#define AUTH_ACTIVE             (3)
#define ACCESS_AUTH_REQU        (4)
#define CERTIFICATE_AUTH_REQU   (5)
#define CERTIFICATE_AUTH_RESP   (6)
#define ACCESS_AUTH_RESP        (7)
#define SESSION_KEY_NEG_REQU    (8)
#define SESSION_KEY_NEG_RESP    (9)
#define SESSION_KEY_NEG_ACK     (10)

#define REQUEST_CERTIFICATE       (11) //client send to the server,for requesting a new certificate,i.e a certificate request
#define ISSUE_CERTIFICATE         (12) //server send to the client,after signing the new certificate
#define SEARCH_CERTIFICATE        (13) //client send to the server,for searching for a certificate
#define SEARCH_CERTIFICATE_RESULT (14) //server send to the client,after searching in the certificate database,
                                       //in addition,including the certificate state
#define EXIT                      (15)


typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned long  DWORD;
typedef unsigned short BOOL;

//宏定义布尔类型
#define TRUE 1
#define FALSE 0

#define AE_OK_ASUE_OK 2     //AE\u548cASUE\u8bc1\u4e66\u9a8c\u8bc1\u90fd\u6b63\u786e
#define AE_OK_ASUE_ERROR 3  //AE\u8bc1\u4e66\u9a8c\u8bc1\u6b63\u786e\uff0cASUE\u8bc1\u4e66\u9a8c\u8bc1\u9519\u8bef
#define AE_ERROR_ASUE_OK 4  //AE\u8bc1\u4e66\u9a8c\u8bc1\u9519\u8bef\uff0cASUE\u8bc1\u4e66\u9a8c\u8bc1\u6b63\u786e
#define AE_ERROR_ASUE_ERROR 5  //AE\u8bc1\u4e66\u9a8c\u8bc1\u9519\u8bef\uff0cASUE\u8bc1\u4e66\u9a8c\u8bc1\u9519\u8bef

typedef struct _byte_data
{
	BYTE  length;				     /* \u957f\u5ea6 */
	BYTE  data[MAX_BYTE_DATA_LEN];	 /* \u5185\u5bb9 */
}byte_data;


/* WAI协议分组基本格式包头 */
typedef struct _packet_head
{
    WORD  version;                   /* 版本号:表示鉴别基础结构的版本号。当前版本为1 */
    BYTE  type;                      /* 协议类型,1-WAPI,其他值保留*/
    BYTE  subtype;                   /* 子类型，type字段的值为1时，子类型字段值区分不同分组*/
    WORD  reserved;                  /* 保留  */
    WORD  length;                    /* 长度  */
    WORD  packetnumber;              /* 分组序号 */
    BYTE  fragmentnumber;            /* 分片序号 */
    BYTE  identify;                  /* 标识字段的比特0表示后续是否有分片，值为0-表示没有，值为1-表示有，比特1至比特7保留*/
}packet_head;


/* 证书 */
typedef struct _certificate
{
    WORD                  cer_identify;                         /* 证书标识 */
    WORD                  cer_length;                           /* 证书长度 */

//	struct
//	{//X.509证书结构体
//		//X.509证书DER编解码数据定义，数据长度为cer_length  当证书格式为X.509时采用
	BYTE                 cer_X509[MAX_X509_DATA_LEN];          /* X.509证书DER编解码流 */
//	};
}certificate;

//身份的DER数据
typedef struct _der_identity
{
	BYTE  data[MAX_BYTE_DATA_LEN * 3];
}der_identity;

/* 身份字段 */
typedef struct _identity
{
    WORD             identity_identify;           /* 身份标识 */
    WORD             identity_length;             /* 身份长度 */

	struct
	{//X509身份
		der_identity     cer_der;                     /* DER身份数据 */
	};
}identity;


/* 地址索引 */
typedef struct _addindex
{
    BYTE       mac1[MAC_LEN];                    /*  AE的MAC地址 */
    BYTE       mac2[MAC_LEN];                    /*  ASUE的MAC地址 */
}addindex;


/* OID 参数 */
typedef struct _oid_param
{
    BYTE  oid_code[MAX_BYTE_DATA_LEN];  /* oid 方式 */
}oid_param;

/* 签名算法 */
typedef struct _sign_arithmetic
{
    WORD      length;               /* 长度字段 */
    BYTE      hash_identify;        /* 杂凑算法标识 */
    BYTE      sign_identify;        /*  签名算法标识 */

    BYTE      param_identify;      /*  参数标识 */
    WORD      param_length;        /*  参数长度 */

    oid_param   oid;               /* OID 方式参数 */

}sign_arithmetic;

//签名数据
typedef struct _sign_data
{
	WORD  length;                    /* 长度 */
	BYTE  data[MAX_BYTE_DATA_LEN];   /* 内容 */
}sign_data;

/* 签名属性 */
typedef struct _sign_attribute
{
    BYTE              type;                                     /* 签名属性类型 (1)*/
    WORD              signattributelength;                      /* 签名属性长度 */
    identity          signidentity;                             /* 签名身份 */
    sign_arithmetic   signarithmetic;                           /* 签名算法 */
    sign_data         sign;                                     /* 签名值 */
}sign_attribute;

/* 证书验证结果 */
typedef struct _certificate_valid_result
{
    BYTE             type;                                      /* 证书验证结果属性类型 (2)*/
    WORD             length;                                    /* 长度 */
    BYTE             random1[RAND_LEN];                         /* 一次性随机数1 */
    BYTE             random2[RAND_LEN];                         /* 二次性随机数2 */
    BYTE             cerresult1;                                /* 验证结果1 */
    certificate      certificate1;                              /* 证书1 */
    BYTE             cerresult2;                                /* 验证结果2 */
    certificate      certificate2;                              /* 证书2 */
}certificate_valid_result;

/* 复合的证书验证结果 由证书认证响应分组中除ADDID外的其他各个字段组成，并且内容和它们相同*/
typedef struct _certificate_valid_result_complex
{
	certificate_valid_result ae_asue_cert_valid_result;          /* ae和asue证书验证结果*/
	sign_attribute           ae_asue_cert_valid_result_asu_sign; /* asu对ae_asue_cert_valid_result字段的签名 */
}certificate_valid_result_complex;

/* 身份列表 */
typedef struct _identity_list
{
    BYTE         type;                                      /* 身份列表类型（3）*/
    WORD         length;                                    /* 身份列表长度 */
    BYTE         reserved;                                  /* 保留 */

    WORD         identitynumber;                            /* 身份个数 */
    identity     identityset[MAX_IDENTITY_NUMBER];          /* 身份列表 */
}identity_list;

/* ECDH \u53c2\u6570 */
typedef struct _ecdh_param
{
    BYTE     param_identify;               /*  \u53c2\u6570\u6807\u8bc6 */
    WORD     param_length;                 /*  \u53c2\u6570\u957f\u5ea6 */

    oid_param   oid;                       /* OID \u65b9\u5f0f\u53c2\u6570 */

}ecdh_param;

/************************************************************
*WAI认证协议于认证服务器直接相关的证书认证请求分组和证书认证响应分组
*************************************************************/
/* 鉴别激活分组 */
typedef struct _auth_active
{
	packet_head    wai_packet_head;                             /* WAI协议分组基本格式包头 */
    BYTE           flag;                                      /* 标志FLAG */
    BYTE           authidentify[RAND_LEN];                    /* 鉴别标识 */
	BYTE		   aechallenge[RAND_LEN];
	identity       localasuidentity;                          /* 本地ASU的身份 */
	ecdh_param     ecdhparam;                                 /* ECDH参数 */
    certificate    certificatestaae;                          /* STAae的证书 */
    sign_attribute aesign;                                      /* AE的签名 */

}AuthActive;

/* 接入鉴别请求 */
typedef struct _access_auth_requ
{
	packet_head    wai_packet_head;                             /* WAI协议分组基本格式包头 */
    BYTE             flag;                                        /* 标志 */
    BYTE             authidentify[RAND_LEN];                      /* 鉴别标识 */
    BYTE             asuechallenge[RAND_LEN];                     /* ASUE挑战 */
    byte_data        asuekeydata;                                 /* ASUE密钥数据 */
	BYTE			 aechallenge[RAND_LEN];
    identity         staaeidentity;                             /* STAae的身份 */
    ecdh_param       ecdhparam;                                   /* ECDH参数 */
    certificate      certificatestaasue;                          /* STAasue证书 */
    sign_attribute   asuesign;                                    /* ASUE的签名 */
}AccessAuthRequ;

/* 证书认证请求分组 */
typedef struct _certificate_auth_requ
{
	packet_head       wai_packet_head;                             /* WAI协议分组基本格式包头 */
    addindex          addid;                                       /* 地址索引 ADDID*/
    BYTE              aechallenge[RAND_LEN];                       /* AE挑战 */
    BYTE              asuechallenge[RAND_LEN];                     /* ASUE挑战 */
    certificate       staasuecer;                                  /* STAasue的证书 */
    certificate       staaecer;                                    /* STAae的证书 */
    sign_attribute    aesign;                                      /* AE的签名 */
}certificate_auth_requ;

/* 证书认证响应分组 */
typedef struct _certificate_auth_resp
{
	packet_head       wai_packet_head;                             /* WAI协议分组基本格式包头 */
    addindex                   addid;                             /* 地址索引ADDID */
    certificate_valid_result   cervalidresult;                    /* 证书验证结果 */
    sign_attribute             asusign;                           /* ASU服务器签名 */
}certificate_auth_resp;

/* 接入鉴别响应 */
typedef struct _access_auth_resp
{
	packet_head 				 wai_packet_head; 				  /* WAI协议分组基本格式包头 */
    BYTE                         flag;                            /* 标识FLAG */
	BYTE           				 authidentify[RAND_LEN];          /* 鉴别标识 */
    BYTE                         asuechallenge[RAND_LEN];         /* ASUE挑战 */
    BYTE                         aechallenge[RAND_LEN];           /* AE挑战 */
	byte_data                    aekeydata;                       /* AE密钥数据 */
	BYTE						 accessresult;					  /* 接入结果 */
	certificate_valid_result_complex   cervalrescomplex;                /* 复合证书验证结果 */
    sign_attribute               aesign;                          /* AE的签名 */
}AccessAuthResp;

BOOL getCertData(char *userID, BYTE buf[], int *len);

BOOL writeCertFile(char *userID, BYTE buf[], int len);
/*************************************************
Description: // 从数字证书(PEM文件)中读取公钥
Calls:       // openssl中读PEM文件的API
Output:      //	数字证书公钥
*************************************************/
EVP_PKEY *getpubkeyfromcert(char *userID);

BOOL gen_sign(BYTE * input,int inputLength,BYTE * sign_value, unsigned int *sign_len,EVP_PKEY * privKey);

/*************************************************
Calls:       // openssl验证签名的API
Input:	     //	input---待验证签名的整个数据包
                sign_input_len---待验证签名的有效数据字段的长度，并非整个input长度
                sign_value---签名字段
                sign_output_len---签名字段的长度
                pubKey---验证签名所使用的公钥
Output:      //	验证签名结果
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改
*************************************************/
BOOL verify_sign(BYTE *input,int sign_input_len,BYTE * sign_value, unsigned int sign_output_len,EVP_PKEY * pubKey);

/*************************************************
Calls:       // openssl SHA256的API函数以及RAND_bytes函数
Return:      // 256bit(32Byte)MAC
*************************************************/
void gen_randnum(BYTE *randnum,int randnum_len);

EVP_PKEY * getprivkeyfromprivkeyfile(char *userID);

int getECDHparam(ecdh_param *ecdhparam, const char *oid);

int getLocalIdentity(identity *localIdentity, char *localUserID);

int par_certificate_auth_resp_packet(certificate_auth_requ * cert_auth_resp_buffer_recv);

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
enum DeviceType Self_type;

typedef struct KeyData{
	//
}KeyData;
typedef struct KeyRing{
	char *key_partner_id;
	unsigned char master[16];
	unsigned char CK[16];
	unsigned char IK[16];
	unsigned char KEK[16];
	unsigned char reauth_IK[16];
}KeyRing;
typedef struct MACaddr{
	char macaddr[MAC_LEN];
}MACaddr;

#define MAXKEYRINGS 10
typedef struct RegisterContext{
	char *radius_id;
	char *peer_id;
	char *self_id;
	char *self_password;
	// enum DeviceType self_type;
	KeyData keydata;
	MACaddr self_MACaddr;
	MACaddr peer_MACaddr;
	unsigned char auth_id_next[32];
	unsigned char MK_ID[16];
	unsigned char self_randnum_next[32];
	unsigned char peer_randnum_next[32];
	unsigned char self_rtp_port;
	unsigned char self_rtcp_port;
	unsigned char peer_rtp_port;
	unsigned char peer_rtcp_port;
	unsigned char nonce_seed[32];
	KeyRing key_table[MAXKEYRINGS];
}RegisterContext;

//<auth active packet>
int ProcessWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet);

int HandleWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet);

//<access auth request packet>
int ProcessWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet);

int HandleWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet);

//<access auth response packet>
int HandleWAPIProtocolAccessAuthResp(RegisterContext *rc, AccessAuthRequ *access_auth_requ_packet,
		AccessAuthResp *access_auth_resp_packet);

/* Scene 1 :
 * Key negotiation process
 * (step 7-10 17-20)
 */

typedef struct _UnicastKeyNegoRequ
{
	//
}UnicastKeyNegoRequ;

typedef struct _UnicastKeyNegoResp
{
	//
}UnicastKeyNegoResp;

typedef struct _UnicastKeyNegoConfirm
{
	//
}UnicastKeyNegoConfirm;

//Unicast key negotiation request
int ProcessUnicastKeyNegoRequest(RegisterContext *rc, UnicastKeyNegoRequ *unicast_key_nego_requ_packet);

int HandleUnicastKeyNegoRequest(RegisterContext *rc, const UnicastKeyNegoRequ *unicast_key_nego_requ_packet);

//Unicast key negotiation response
int ProcessUnicastKeyNegoResponse(RegisterContext *rc, UnicastKeyNegoResp *unicast_key_nego_resp_packet);

int HandleUnicastKeyNegoResponse(RegisterContext *rc, const UnicastKeyNegoResp *unicast_key_nego_resp_packet);

//Unicast key negotiation confirm
int ProcessUnicastKeyNegoConfirm(RegisterContext *rc, UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet);

int HandleUnicastKeyNegoConfirm(RegisterContext *rc, const UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet);

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

