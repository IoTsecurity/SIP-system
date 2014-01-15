/*
 * ae.h
 *
 *  Created on: 2013-7-29
 *      Author: lsc
 */

#ifndef AE_H_
#define AE_H_


#include <stdio.h>
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <memory.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wait.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
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


/************************************************************
*服务器端口定义
*************************************************************/

#define MAC_LEN                  6           /* MAC地址长度 */
#define MAX_COMM_DATA_LEN        65535       /* 通用数据的最大长度 */
#define MAX_X509_DATA_LEN        1024 * 4    /* 存放X509DER编解码缓冲的最大长度 */
#define MAX_BYTE_DATA_LEN        256	     /* 最大字节数据长度 */
#define RAND_LEN                 32          /* 随机数长度 */

#define MAX_IDENTITY_NUMBER      16          /* 身份列表最大身份个数 */
//#define USER_DN_SIZE             16          /* 认证服务器的每个用户(客户端)的DN(distinguished name)长度 */
#define USER_AMOUNT_MAX          10          /* 认证服务器支持的最大用户(客户端)数量 */

#define    SUCCEED     (0)
#define    FAIL        (-1)

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

#define AE_OK_ASUE_OK 2     //AE和ASUE证书验证都正确
#define AE_OK_ASUE_ERROR 3  //AE证书验证正确，ASUE证书验证错误
#define AE_ERROR_ASUE_OK 4  //AE证书验证错误，ASUE证书验证正确
#define AE_ERROR_ASUE_ERROR 5  //AE证书验证错误，ASUE证书验证错误

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


/* EAP header */
typedef struct _EAP_header
{
	BYTE code;
	BYTE identifier;
	WORD length;
	BYTE type;
}EAP_header;
/************************************************************
*WAI认证协议相关的认证激活分组、接入认证请求分组、证书认证请求分组、证书认证响应分组、接入认证响应分组
*************************************************************/
/* 认证激活分组 */
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
    
}auth_active;

typedef struct _EAP_auth_active
{
	EAP_header eap_header;
	auth_active auth_active_packet;
}EAP_auth_active;

/* 接入认证请求 */
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
}access_auth_requ;

typedef struct _EAP_access_auth_requ
{
	EAP_header eap_header;
	access_auth_requ access_auth_requ_packet;
}EAP_access_auth_requ;


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

/* New code */
/* The EAP format of certificate_auth_requ */
typedef struct _EAP_certificate_auth_requ
{
	EAP_header eap_header;
	certificate_auth_requ certificate_auth_requ_packet;
}EAP_certificate_auth_requ;

/* 证书认证响应分组 */
typedef struct _certificate_auth_resp
{
	packet_head                wai_packet_head;                   /* WAI协议分组基本格式包头 */
    addindex                   addid;                             /* 地址索引ADDID */
    certificate_valid_result   cervalidresult;                    /* 证书验证结果 */
    sign_attribute             cervalresasusign;                  /* ASU服务器对证书验证结果字段的签名 */
    sign_attribute             cerauthrespasusign;                /* ASU服务器对整个证书认证响应分组(除本字段外)的签名 */
}certificate_auth_resp;

/* New code */
/* The EAP format of _certificate_auth_requ */
typedef struct _EAP_certificate_auth_resp
{
	EAP_header eap_header;
	certificate_auth_resp certificate_auth_resp_packet;
}EAP_certificate_auth_resp;

/* 接入认证响应 */
typedef struct _access_auth_resp
{
	packet_head 				       wai_packet_head; 				/* WAI协议分组基本格式包头 */
    BYTE                               flag;                            /* 标识FLAG */
	BYTE           				       authidentify[RAND_LEN];          /* 鉴别标识 */
    BYTE                               asuechallenge[RAND_LEN];         /* ASUE挑战 */
    BYTE                               aechallenge[RAND_LEN];           /* AE挑战 */
	byte_data                          aekeydata;                       /* AE密钥数据 */
	BYTE						       accessresult;				    /* 接入结果 */
	certificate_valid_result_complex   cervalrescomplex;                /* 复合证书验证结果 */
    sign_attribute                     aesign;                          /* AE的签名 */
}access_auth_resp;

typedef struct _EAP_access_auth_resp
{
	EAP_header eap_header;
	access_auth_resp access_auth_resp_packet;
}EAP_access_auth_resp;



/* 证书签发请求分组 */
typedef struct _certificate_sign_requ
{
	packet_head       wai_packet_head;                                   /* WAI协议分组基本格式包头 */
	WORD              certificate_sign_requ_buffer_len;                  /* 证书签发请求buffer数组数据有效长度 */
    BYTE              certificate_sign_requ_buffer[MAX_X509_DATA_LEN];   /* 证书签发请求buffer数组 */
}certificate_sign_requ;

/* 证书签发响应分组 */
typedef struct _certificate_sign_resp
{
	packet_head       wai_packet_head;                                   /* WAI协议分组基本格式包头 */
	certificate       usercer;                                           /* 用户的证书(签发后的) */
}certificate_sign_resp;



BOOL getCertData(char *userID, BYTE buf[], int *len);

BOOL writeCertFile(char *userID, BYTE buf[], int len);

BOOL writeUserCertFile(char *userID, BYTE buf[], int len);


/*************************************************

Function:    // getprivkeyfromprivkeyfile
Description: // CA(驻留在ASU中)从cakey.pem中提取CA的私钥，以便后续进行ASU的签名
Calls:       // openssl读取私钥PEM文件相关函数
Called By:   // 待添加！！！
Input:	     //	无
Output:      //	CA(驻留在ASU中)的私钥
Return:      // EVP_PKEY *privKey
Others:      // 该函数只是在本工程中为asu.c专用，即提取CA(驻留在ASU中)的私钥，如需提取其他私钥，还有待于将打开文件的目录及文件名做点修改

*************************************************/
EVP_PKEY * getprivkeyfromprivkeyfile(char *userID);


/*************************************************

Function:    // getprivkeyfromkeyfile
Description: // 从密钥文件中提取出私钥的RSA结构体，以便后续进行公钥的提取以及私钥的签名操作
Calls:       // openssl读取私钥PEM文件函数、从PEM文件读取私钥RSA函数
Called By:   //
Input:	     //	userID-用户名，0-CA，非零-用户编号
Output:      //	私钥的RSA指针
Return:      // RSA *
Others:      // 本函数不要与getprivkeyfromprivkeyfile混淆，本函数为了2013.8.15认证服务其签发证书的演示所填加,请不要调用此函数。

*************************************************/

RSA * getprivkeyfromkeyfile(char *userID);


/*************************************************

Function:    // getpubkeyfromcert
Description: // 从数字证书(PEM文件)中读取公钥
Calls:       // openssl中读PEM文件的API
Called By:   // 待添加！！！
Input:	     //	用户证书的用户名certnum
Output:      //	数字证书公钥
Return:      // EVP_PKEY *pubKey
Others:      // 用户证书的用户名certnum最好是用字符串形式，但是目前是int值，有待改进

*************************************************/
EVP_PKEY *getpubkeyfromcert(char *userID);

/*************************************************

Function:    // verify_sign
Description: // 验证数字签名
Calls:       // openssl验证签名的API
Called By:   // 待添加！！！
Input:	     //	input---待验证签名的整个数据包
                sign_input_len---待验证签名的有效数据字段的长度，并非整个input长度
                sign_value---签名字段
                sign_output_len---签名字段的长度
                pubKey---验证签名所使用的公钥
Output:      //	验证签名结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/
BOOL verify_sign(BYTE *input,int sign_input_len,BYTE * sign_value, unsigned int sign_output_len,EVP_PKEY * pubKey);

/*************************************************

Function:    // SHA256
Description: // SHA256散列函数
Calls:       // openssl SHA256的API函数
Called By:   //
Input:	     //	input---待计算摘要的输入数据
                input_len---待计算摘要的输入数据长度
                output---摘要结果输出
Output:      //	摘要值
Return:      // 256bit(32Byte)摘要
Others:      // 本处注释只是为了大家理解，待理解后，本处注释可删除

*************************************************/
//SHA256(input, input_len, output);


/*************************************************

Function:    // hmac_sha256
Description: // WAPI消息认证MAC算法
Calls:       // openssl SHA256的API函数
Called By:   // 待添加！！！
Input:	     //	text---待计算MAC的输入数据
                text_len---待计算MAC的输入数据长度
                key---hmac密钥
                key_len---hmac密钥长度
                digest---输出MAC值
Output:      //	MAC值
Return:      // 256bit(32Byte)MAC
Others:      // 如果想设定输出MAC的长度，可考虑添加一个输出MAC长度的形参

*************************************************/

void hmac_sha256(
		const BYTE *text,      /* pointer to data stream        */
		int        text_len,   /* length of data stream         */
		const BYTE *key,       /* pointer to authentication key */
		int        key_len,    /* length of authentication key  */
		void       *digest);    /* caller digest to be filled in */

/*************************************************

Function:    // gen_randnum
Description: // 生成随机数
Calls:       // openssl SHA256的API函数以及RAND_bytes函数
Called By:   // 待添加！！！
Input:	     //	randnum---保存生成的随机数
                randnum_len---随机数长度
Output:      //	随机数
Return:      // 256bit(32Byte)MAC
Others:      //

*************************************************/
void gen_randnum(BYTE *randnum,int randnum_len);


int getECDHparam(ecdh_param *ecdhparam, const char *oid);


int getLocalIdentity(identity *localIdentity, char *localUserID);


/*************************************************

Function:    // gen_sign
Description: // 生成数字签名
Calls:       // openssl生成签名的API
Called By:   // fill_certificate_auth_resp_packet
Input:	     //	input---待生成签名的整个数据包(分组)
                sign_input_len---待生成签名的有效数据字段的长度，并非整个input长度
                sign_value---保存生成的字段
                sign_output_len---生成的签名字段的长度
                privKey---生成签名所使用的私钥
Output:      //	生成签名操作结果，TRUE or FALSE
Return:      // TRUE or FALSE
Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

*************************************************/

BOOL gen_sign(BYTE * input,int sign_input_len,BYTE * sign_value, unsigned int *sign_output_len,EVP_PKEY * privKey);


/*************************************************

Function:    // user_gen_cert_request
Description: // 用户生成自签名证书请求文件
Calls:       // X509_REQ相关函数
Called By:   //
Input:	     //	userID---待读取文件编号，0-CA，非零-用户编号
Output:      //	证书请求文件(txt和PEM文件)
Return:      // void
Others:      //

*************************************************/

void user_gen_cert_request(char *userID,char *username);

int fill_auth_active_packet(char *userID,auth_active *auth_active_packet);
int fill_certificate_auth_requ_packet(char *userID,const access_auth_requ *access_auth_requ_packet,certificate_auth_requ *certificate_auth_requ_packet);
int fill_access_auth_resp_packet(char *userID, const access_auth_requ *access_auth_requ_packet, access_auth_resp *access_auth_resp_packet);


/* Authentication */
// 1) Process AuthActive packet
int ProcessWAPIProtocolAuthActive(char *userID, auth_active *auth_active_packet);

// 2) Handle AccessAuthRequest packet
int HandleWAPIProtocolAccessAuthRequest(char *userID, const auth_active *auth_active_packet, access_auth_requ *access_auth_requ_packet);

// 3) Process CertAuthRequest packet
int ProcessWAPIProtocolCertAuthRequest(char *userID,const access_auth_requ *access_auth_requ_packet,certificate_auth_requ *certificate_auth_requ_packet);

// 4) HandleProcess CertAuthResp packet
int HandleProcessWAPIProtocolCertAuthResp(char *userID, const certificate_auth_requ *certificate_auth_requ_packet, const certificate_auth_resp *certificate_auth_resp_packet,access_auth_resp *access_auth_resp_packet);

// 5) Process AccessAuthResp packet
int ProcessWAPIProtocolAccessAuthResp(char *userID, const access_auth_requ *access_auth_requ_packet, access_auth_resp *access_auth_resp_packet);

/* Key negotiation */
/*
// 1) Process Unicast key negotiation request packet
int ProcessUnicastKeyNegoRequest(unicast_key_nego_requ *unicast_key_nego_requ_packet);

// 2) Handle Unicast key negotiation response packet
int HandleUnicastKeyNegoResponse(const unicast_key_nego_resp *unicast_key_nego_resp_packet);

// 3) Process Unicast key negotiation confirm packet
int ProcessUnicastKeyNegoConfirm(unicast_key_nego_confirm *unicast_key_nego_confirm_packet);
*/
#endif /* AE_H_ */
