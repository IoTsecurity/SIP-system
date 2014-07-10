/*
 * interface.h
 *
 *  Created on: 2013年12月18日
 *      Author: jzw yaoyao
 */
#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdio.h>
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket

#define CHAT_SERVER_PORT    (6666)

#define MAC_LEN                  6           /* MAC地址长度 */
#define RAND_LEN                 32          /* 随机数长度 */
#define SHA256_DIGEST_SIZE       32
#define KEY_LEN                  16
#define CIPHER_TEXT_LEN			 128

#define MAX_COMM_DATA_LEN        65535       /* 通用数据的最大长度 */
#define MAX_X509_DATA_LEN        1024 * 4    /* 存放X509DER编解码缓冲的最大长度 */
#define MAX_BYTE_DATA_LEN        256	     /* 最大字节数据长度 */
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

/* 证书 */
typedef struct _certificate
{
    WORD                  cer_identify;                         /* 证书标识 */
    WORD                  cer_length;                           /* 证书长度 */

    //X.509证书结构体,DER编解码数据定义，数据长度为cer_length  当证书格式为X.509时采用
	BYTE                 cer_X509[MAX_X509_DATA_LEN];          /* X.509证书DER编解码流 */
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

    //X509身份
	struct{
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


// Return 32Byte digest
//SHA256(input, input_len, output);

// Return 32Byte digest
void hmac_sha256(unsigned char *data, unsigned int data_len, unsigned char *key, unsigned int key_len, unsigned char* result, unsigned int result_len);

void kd_hmac_sha256(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char *output, unsigned int length);

BOOL getCertData(char *userID, BYTE buf[], int *len);

BOOL writeCertFile(char *userID, BYTE buf[], int len);

/*************************************************
Description: // 从数字证书(PEM文件)中读取公钥
Output:      //	数字证书公钥
*************************************************/
EVP_PKEY *getpubkeyfromcert(char *userID);

BOOL gen_sign(BYTE * input,int inputLength,BYTE * sign_value, unsigned int *sign_len,EVP_PKEY * privKey);

/*************************************************
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
Return:      // 32Byte MAC
*************************************************/
void gen_randnum(BYTE *randnum,int randnum_len);

EVP_PKEY * getprivkeyfromprivkeyfile(char *userID);

int getLocalIdentity(identity *localIdentity, char *localUserID);


/////////////////////////// filled by yaoyao ///////////////////////////////////
/* Scene 1 :
 * Register and authentication process
 * (step 1-6 11-16)
 */

enum DeviceType{
	IPC,
	SIPserver,
	NVR,
	Client
};
extern enum DeviceType Self_type;

enum ConnectStatus{
	NolinkNosession,
	LinkNosession,
	LinkSession
};

#define MAXIDSTRING 32
#define MAXKEYRINGS 10
typedef struct KeyRing{
	char partner_id[MAXIDSTRING];
	unsigned char MasterKey[KEY_LEN];
	unsigned char CK[KEY_LEN];
	unsigned char IK[KEY_LEN];
	unsigned char KEK[KEY_LEN];
	unsigned char reauth_IK[KEY_LEN];
}KeyRing;

typedef struct KeyBox{
	KeyRing keyrings[MAXKEYRINGS];
	int nkeys;
}KeyBox;
extern KeyBox Keybox;

typedef struct MACaddr{
	unsigned char macaddr[MAC_LEN];
}MACaddr;

typedef struct Ports{
	int rtp_send;
	int rtcp_send;
	int rtp_recv;
	int rtcp_recv;
}Ports;

#define ECDH_SIZE 33

typedef struct RegisterContext{
	char radius_id[MAXIDSTRING];

	char self_id[MAXIDSTRING];
	MACaddr self_MACaddr;
	char self_password[MAXIDSTRING];

	char peer_id[MAXIDSTRING];
	char peer_ip[MAXIDSTRING];
	MACaddr peer_MACaddr;
	char peer_password[MAXIDSTRING];
	//enum DeviceType peer_type;

	// used in register part
	unsigned char keydata[ECDH_SIZE];
	unsigned char auth_id_next[SHA256_DIGEST_SIZE]; // for re-authentiation

	// used in key negotiation part
	EC_KEY *ecdh; // should call "EC_KEY_free(ecdh);" after register process
	unsigned char MK_ID[SHA256_DIGEST_SIZE];
	unsigned char self_randnum_next[RAND_LEN];
	unsigned char peer_randnum_next[RAND_LEN];
	Ports peer_ports; // SIP Server should save this data
	unsigned char nonce[RAND_LEN]; // for re-key-negotiation, reserved
    BOOL key_nego_result;
}RegisterContext;

#ifdef __x86_64__
#define _time_t unsigned long
#else
#define _time_t unsigned long long
#endif

#pragma pack (4) //alignment with 4B

// step2: SIP Server - SIP UA(NVR)
/* WAI认证协议 鉴别激活分组 */
typedef struct _auth_active
{
//	packet_head    wai_packet_head;                             /* WAI协议分组基本格式包头 */
    BYTE           flag;                                      /* 标志FLAG */
    BYTE           authidentify[RAND_LEN];                    /* 鉴别标识 */
	BYTE		   aechallenge[RAND_LEN];
	_time_t         authactivetime;
	identity       localasuidentity;                          /* 本地ASU的身份 */
	ecdh_param     ecdhparam;                                 /* ECDH参数 */
    certificate    certificatestaae;                          /* STAae的证书 */
    sign_attribute aesign;                                      /* AE的签名 */

}AuthActive;

int ProcessWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet);

// step3: SIP UA(NVR) - SIP Server
/* WAI认证协议 接入鉴别请求 */
typedef struct _access_auth_requ
{
    BYTE             flag;                                        /* 标志 */
    BYTE             authidentify[RAND_LEN];                      /* 鉴别标识 */
    BYTE             asuechallenge[RAND_LEN];                     /* ASUE挑战 */
    BYTE         	 asuekeydata[ECDH_SIZE];                                 /* ASUE密钥数据 */
	BYTE			 aechallenge[RAND_LEN];
    identity         staaeidentity;                             /* STAae的身份 */
    ecdh_param       ecdhparam;                                   /* ECDH参数 */
    certificate      certificatestaasue;                          /* STAasue证书 */
    sign_attribute   asuesign;                                    /* ASUE的签名 */
}AccessAuthRequ;
int HandleWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet);
int ProcessWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet);

// step4: SIP Server - Radius Server
/* WAI认证协议 证书认证请求分组 */
typedef struct _certificate_auth_requ
{
    addindex          addid;                                       /* 地址索引 ADDID*/
    BYTE              aechallenge[RAND_LEN];                       /* AE挑战 */
    BYTE              asuechallenge[RAND_LEN];                     /* ASUE挑战 */
    certificate       staasuecer;                                  /* STAasue的证书 */
    certificate       staaecer;                                    /* STAae的证书 */
    sign_attribute    aesign;                                      /* AE的签名 */
}CertificateAuthRequ;
int HandleWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet);
int ProcessWAPIProtocolCertAuthRequest(RegisterContext *rc,
		AccessAuthRequ *access_auth_requ_packet,
		CertificateAuthRequ *certificate_auth_requ_packet);

// step5: Radius Server - SIP Server
/* WAI认证协议 证书认证响应分组
typedef struct _certificate_auth_resp
{
    addindex                   addid;                             // 地址索引ADDID
    certificate_valid_result   cervalidresult;                    // 证书验证结果
    sign_attribute             asusign;                           // ASU服务器签名
}CertificateAuthResp;*/
//replaced by lvshichao 20140416
/* WAI认证协议 证书认证响应分组 */
typedef struct _certificate_auth_resp
{
    addindex                   addid;                             /* 地址索引ADDID */
    certificate_valid_result   cervalidresult;                    /* 证书验证结果 */
    sign_attribute             cervalresasusign;                  /* ASU服务器对证书验证结果字段的签名 */
    sign_attribute             cerauthrespasusign;                /* ASU服务器对整个证书认证响应分组(除本字段外)的签名 */
}CertificateAuthResp;
int talk_to_asu(CertificateAuthRequ *certificate_auth_requ_packet,	CertificateAuthResp *certificate_auth_resp_packet);

/* WAI认证协议 接入鉴别响应 */
typedef struct _access_auth_resp
{
    BYTE                         flag;                            /* 标识FLAG */
	BYTE           				 authidentify[RAND_LEN];          /* 鉴别标识 */
    BYTE                         asuechallenge[RAND_LEN];         /* ASUE挑战 */
    BYTE                         aechallenge[RAND_LEN];           /* AE挑战 */
	BYTE                    	 aekeydata[ECDH_SIZE];                       /* AE密钥数据 */
	BYTE						 accessresult;					  /* 接入结果 */
	certificate_valid_result_complex   cervalrescomplex;                /* 复合证书验证结果 */
    sign_attribute               aesign;                          /* AE的签名 */
}AccessAuthResp;

int HandleProcessWAPIProtocolCertAuthResp(RegisterContext *rc,
		CertificateAuthRequ *certificate_auth_requ_packet,
		CertificateAuthResp *certificate_auth_resp_packet,
		AccessAuthResp *access_auth_resp_packet);

// step6: SIP Server - SIP UA(NVR)
int ProcessWAPIProtocolAccessAuthResp(RegisterContext *rc,
		AccessAuthRequ *access_auth_requ_packet, AccessAuthResp *access_auth_resp_packet);

// step6+: SIP UA(NVR)
int HandleWAPIProtocolAccessAuthResp(RegisterContext *rc, AccessAuthRequ *access_auth_requ_packet,
		AccessAuthResp *access_auth_resp_packet);

/* Scene 1 :
 * Key negotiation process
 * (step 7-10 17-20)
 */

// step7
// Unicast key negotiation request
typedef struct _UnicastKeyNegoRequ
{
    BYTE                         flag;                            /* 标识FLAG */
	unsigned char                MK_ID[SHA256_DIGEST_SIZE];
    addindex                     addid;                             /* 地址索引ADDID */
    BYTE                         aechallenge[RAND_LEN];           /* AE挑战 */
    sign_attribute               aesign;                          /* AE的签名 */
}UnicastKeyNegoRequ;
int ProcessUnicastKeyNegoRequest(RegisterContext *rc, UnicastKeyNegoRequ *unicast_key_nego_requ_packet);
int HandleUnicastKeyNegoRequest(RegisterContext *rc, const UnicastKeyNegoRequ *unicast_key_nego_requ_packet);

// step8
// Unicast key negotiation response
typedef struct _UnicastKeyNegoResp
{
    BYTE                         flag;                            /* 标识FLAG */
	unsigned char                MK_ID[SHA256_DIGEST_SIZE];
    addindex                     addid;                             /* 地址索引ADDID */
    BYTE                         asuechallenge[RAND_LEN];         /* ASUE挑战 */
    BYTE                         aechallenge[RAND_LEN];           /* AE挑战 */
	Ports						 myports;
    unsigned char 				 digest[SHA256_DIGEST_SIZE]; // Unicast data digest code
}UnicastKeyNegoResp;
int ProcessUnicastKeyNegoResponse(RegisterContext *rc, UnicastKeyNegoResp *unicast_key_nego_resp_packet);
int HandleUnicastKeyNegoResponse(RegisterContext *rc, const UnicastKeyNegoResp *unicast_key_nego_resp_packet);

// step9
// Unicast key negotiation confirm
typedef struct _UnicastKeyNegoConfirm
{
    BYTE                         flag;                            /* 标识FLAG */
	unsigned char                MK_ID[SHA256_DIGEST_SIZE];
    addindex                     addid;                             /* 地址索引ADDID */
    BYTE                         asuechallenge[RAND_LEN];         /* ASUE挑战 */
    int							 key_nego_result;
    unsigned char 				 digest[SHA256_DIGEST_SIZE]; // Unicast data digest code
}UnicastKeyNegoConfirm;

/*
 * rc->key_nego_result should be set to proper true/false value before ProcessUnicastKeyNegoConfirm is called
 */
int ProcessUnicastKeyNegoConfirm(RegisterContext *rc, UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet);

int HandleUnicastKeyNegoConfirm(RegisterContext *rc, const UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet);

/* Scene 1 :
 * IPC access to NVR process
 * (step 21 22)
 */
#define MAXLINKS 10
typedef struct SLink{
	char partner_id[MAXIDSTRING];
	char partner_ip[MAXIDSTRING];
	unsigned char IK[KEY_LEN];
	unsigned char IK_ID[SHA256_DIGEST_SIZE];
	unsigned char reauth_IK[SHA256_DIGEST_SIZE];
	unsigned char reauth_IK_ID[SHA256_DIGEST_SIZE];
	unsigned char CK[KEY_LEN];
	unsigned char CK_ID[SHA256_DIGEST_SIZE];
	Ports ports;
}SLink;

typedef struct SecureLinks{
	SLink links[MAXLINKS];
	int nlinks;
}SecureLinks;
extern SecureLinks Securelinks;

int getSecureLinkNum(const SecureLinks *securelinks, const char *id);

typedef struct P2PLinkContext{
	char self_id[MAXIDSTRING];
	MACaddr self_MACaddr;

	char peer_id[MAXIDSTRING];
	enum DeviceType peer_type;
	MACaddr peer_MACaddr;
	char peer_ip[MAXIDSTRING];

	char target_id[MAXIDSTRING];
	enum DeviceType target_type;
	MACaddr target_MACaddr;
	char target_ip[MAXIDSTRING];
	Ports target_ports; // SIP Server should give this data

	//unsigned char IK_P2P_ID[SHA256_DIGEST_SIZE]; // SIP Server should give this data
	//unsigned char CK_P2P_ID[SHA256_DIGEST_SIZE]; // SIP Server should give this data
}P2PLinkContext;

// step21
// P2P key distribution
typedef struct _P2PKeyDistribution
{
    BYTE                         flag;                            /* 标识FLAG */
	unsigned char                IK_P2P_ID[SHA256_DIGEST_SIZE];
	unsigned char                CK_P2P_ID[SHA256_DIGEST_SIZE];
    addindex                     addid;                             /* 地址索引ADDID */
    unsigned char                secure_link_info[CIPHER_TEXT_LEN];
    BYTE                         randnum[RAND_LEN];
    time_t						 timestamp;
    unsigned char 				 digest[SHA256_DIGEST_SIZE]; // Unicast data digest code
}P2PKeyDistribution;
int ProcessP2PKeyDistribution(P2PLinkContext *lc, P2PKeyDistribution *p2p_key_dist_packet);

// step21+
int HandleP2PKeyDistribution(P2PLinkContext *lc, const P2PKeyDistribution *p2p_key_dist_packet);

/* Scene 1 :
 * IPC communicate to NVR process
 * (step 23-30)
 */
typedef struct _P2PCommContext{
	char self_id[MAXIDSTRING];
	MACaddr self_MACaddr;
	char self_randnum[RAND_LEN];

	char peer_id[MAXIDSTRING];
	enum DeviceType peer_type;
	MACaddr peer_MACaddr;
	char peer_randnum[RAND_LEN];
}P2PCommContext;

typedef struct _P2PAuthToken
{
    BYTE                         flag;                            /* 标识FLAG */
	unsigned char                IK_P2P_ID[SHA256_DIGEST_SIZE];
    addindex                     addid;                             /* 地址索引ADDID */
    BYTE                         randnum[RAND_LEN];
    unsigned char 				 digest[SHA256_DIGEST_SIZE]; // Unicast data digest code
}P2PAuthToken;

// step23a/23b: IPC - NVR / NVR - IPC
int ProcessP2PAuthToken(P2PCommContext *cc, P2PAuthToken *p2p_auth_token);
// step24: IPC/NVR
int HandleP2PAuthToken(P2PCommContext *cc, P2PAuthToken *p2p_auth_token);

// step25a/25b: IPC - NVR / NVR - IPC
int ProcessP2PReauthToken(P2PCommContext *cc, P2PAuthToken *p2p_reauth_token);
// step26: IPC/NVR
int HandleP2PReauthToken(P2PCommContext *cc, P2PAuthToken *p2p_reauth_token);

// step27a/27b: IPC - NVR / NVR - IPC
int ProcessP2PByeSessionToken(P2PCommContext *cc, P2PAuthToken *p2p_bye_session_token);
// step28: IPC/NVR
int HandleP2PByeSessionToken(P2PCommContext *cc, P2PAuthToken *p2p_bye_session_token);

// step29a/29b: IPC - NVR / NVR - IPC
int ProcessP2PByeLinkToken(P2PCommContext *cc, P2PAuthToken *p2p_bye_link_token);
// step30: IPC/NVR
int HandleP2PByeLinkToken(P2PCommContext *cc, P2PAuthToken *p2p_bye_link_token);
/////////////////////////// written by yaoyao ///////////////////////////////////

int par_certificate_auth_resp_packet(CertificateAuthRequ *cert_auth_resp_buffer_recv);


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

#endif
