/*
 * interface.c
 *
 * Author: jiangzaiwei yaoyao
 */

#include "interface.h"

#include <stdio.h>
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <memory.h>
#include <errno.h>
#include <pthread.h>

#include <sys/wait.h>
#include <unistd.h>
#include <wait.h>


#define HOME "./"
const char *CAID = "0";

#define USER_REQ  HOME "user/user_req.pem"  //用户证书申请PEM文件存放路径
#define USER_REQ_PRINT  HOME "user/user_req.txt"  //用户证书申请TXT文件存放路径

#define USER_RSA_PRIV  HOME "user/user_rsa_priv.pem"        //用户密钥PEM文件存放路径
#define USER_RSA_PRIV_PRINT  HOME "user/user_rsa_priv.txt"  //用户密钥TXT文件存放路径

#define USER_CERT  HOME "user/user_cert.pem"        //用户证书PEM文件存放路径
#define USER_CERT_PRINT  HOME "user/user_cert.txt"  //用户证书TXT文件存放路径

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

static int annotation = 2;  //1-lvshichao,2-yaoyao

BOOL getCertData(char *userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (strcmp(userID, CAID) == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%s.pem", userID);


	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	fp = fopen(certname, "rb");
	if (fp == NULL)
	{
		printf("reading the cert file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
	if(annotation == 2)
		printf("  cert's length is %d\n", *len);
	fclose(fp);
	if(annotation == 2)
		printf("  将证书保存到缓存buffer成功!\n");

	return TRUE;
}

BOOL writeCertFile(char *userID, BYTE buf[], int len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (strcmp(userID, CAID) == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%s.pem", userID);

	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}
	int res = fwrite(buf, 1, len, fp);
	if(annotation == 2)
		printf("  cert's length is %d\n", len);
	fclose(fp);
	if(annotation == 2)
		printf("  write cert complete!\n");

	return TRUE;
}

BOOL writeUserCertFile(char *userID, BYTE buf[], int len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	sprintf(certname, "./user/usercert%s.pem", userID);

	printf("user cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}
	int res = fwrite(buf, 1, len, fp);
	printf("user cert's length is %d\n", len);
	fclose(fp);
	printf("write user cert complete!\n");

	return TRUE;
}

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
EVP_PKEY * getprivkeyfromprivkeyfile(char *userID)
{
	EVP_PKEY * privKey;
	FILE* fp;
	//RSA rsa_struct;
	RSA* rsa;
	char keyname[40];

	if (strcmp(userID, CAID) == 0)
		sprintf(keyname, "./private/cakey.pem");
	else
		sprintf(keyname, "./private/userkey%s.pem", userID);
	fp = fopen(keyname, "r");

	if(annotation == 2)
		printf("  key file name: %s\n", keyname);
	if (fp == NULL)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n", keyname);
		return NULL;
	}

	rsa = RSA_new();
	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL)) == NULL)
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL;
	}
	fclose(fp);

	// print
	//printf("Content of Private key PEM file\n");
	//RSA_print_fp(stdout, rsa, 0);
	//printf("\n");

	privKey = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(privKey, rsa) != 1) //保存RSA结构体到EVP_PKEY结构体
	{
		printf("EVP_PKEY_set1_RSA err\n");
		RSA_free (rsa);
		return NULL;
	} else
	{
		RSA_free (rsa);
		return privKey;
	}
}

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

RSA * getprivkeyfromkeyfile(char *userID)
{
	EVP_PKEY * Key;
	FILE* fp;
	//RSA rsa_struct;
	RSA* rsa;

	char keyname[40];

	if (strcmp(userID, CAID) == 0)
		sprintf(keyname, "./private/cakey.pem");
	else
		sprintf(keyname, "./private/userkey%s.pem", userID);

	BIO * in = BIO_new_file(keyname, "rb");
	if (in == NULL )
		return FALSE;
	rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL ); //提取私钥
	BIO_free(in);
	return rsa;
}

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
EVP_PKEY *getpubkeyfromcert(char *userID)
{
	EVP_PKEY *pubKey;

	BIO * key = NULL;
	X509 * Cert = NULL; //X509证书结构体，保存CA证书
	key = BIO_new(BIO_s_file());

	char certname[60];
	memset(certname, '\0', sizeof(certname)); //初始化certname,以免后面写如乱码到文件中
	if (strcmp(userID, CAID) == 0)
		sprintf(certname, "./cacert/cacert.pem"); //./demoCA/
	else
		sprintf(certname, "./cert/usercert%s.pem", userID);

	BIO_read_filename(key,certname);
	if (!PEM_read_bio_X509(key, &Cert, 0, NULL))
	{
		/* Error 读取证书失败！*/
		printf("读取证书失败!\n");
		return NULL;
	}

	pubKey = EVP_PKEY_new();
	//获取证书公钥
	pubKey = X509_get_pubkey(Cert);
	return pubKey;
}

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

BOOL verify_sign(BYTE *input,int sign_input_len,BYTE * sign_value, unsigned int sign_output_len,EVP_PKEY * pubKey)
{
	EVP_MD_CTX mdctx;		 //摘要算法上下文变量

	EVP_MD_CTX_init(&mdctx); //初始化摘要上下文

	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	if (!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))	//验证初始化，设置摘要算法，一定要和签名一致。
	{
		printf("EVP_VerifyInit_ex err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyUpdate(&mdctx, sign_input_buffer, sign_input_len))	//验证签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyFinal(&mdctx, sign_value,sign_output_len, pubKey))		//验证签名（摘要）Update
	{
		printf("EVP_Verify err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	} else
	{
		printf("  验证签名正确!!!\n");
	}
	//释放内存
//	EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}


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
		void       *digest)    /* caller digest to be filled in */
{
	BYTE k_ipad[65]; /* inner padding -
	                  * key XORd with ipad
	                  */
	BYTE k_opad[65]; /* outer padding -
	                  * key XORd with opad
	                  */
	BYTE tk[SHA256_DIGEST_LENGTH];
	BYTE tk2[SHA256_DIGEST_LENGTH];
	BYTE bufferIn[1024];
	BYTE bufferOut[1024];
	int i;
	/* if key is longer than 64 bytes reset it to key=sha256(key) */
	if (key_len > 64)
	{
		SHA256(key, key_len, tk);
		key = tk;
		key_len = SHA256_DIGEST_LENGTH;
	}
	/*
	 * the HMAC_SHA256 transform looks like:
	 *
	 * SHA256(K XOR opad, SHA256(K XOR ipad, text))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times
	 * opad is the byte 0x5c repeated 64 times
	 * and text is the data being protected
	 */
	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof k_ipad);
	memset(k_opad, 0, sizeof k_opad);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++)
	{
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	/*
	 * perform inner SHA256
	 */
	memset(bufferIn, 0x00, 1024);
	memcpy(bufferIn, k_ipad, 64);
	memcpy(bufferIn + 64, text, text_len);
	SHA256(bufferIn, 64 + text_len, tk2);
	/*
	 * perform outer SHA256
	 */
	memset(bufferOut, 0x00, 1024);
	memcpy(bufferOut, k_opad, 64);
	memcpy(bufferOut + 64, tk2, SHA256_DIGEST_LENGTH);
	SHA256(bufferOut, 64 + SHA256_DIGEST_LENGTH, digest);
}
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
void gen_randnum(BYTE *randnum,int randnum_len)
{
	int ret;
	BYTE randnum_seed[randnum_len];

	ret = RAND_bytes(randnum_seed, randnum_len);
	if(ret!=1)
	{
		printf("生成随机数种子失败！\n");
	}
	//参考WAPI实施指南P49 SHA-256(挑战种子)--->挑战，随机数生成算法：SHA-256(随机数种子)--->随机数
	SHA256(randnum_seed, randnum_len, randnum);
}




int getECDHparam(ecdh_param *ecdhparam, const char *oid)
{
	unsigned char  *buf;
	int oidlen = 0;

	oidlen=a2d_ASN1_OBJECT(NULL,0,oid,-1);
	if (oidlen <= 0){
		printf("oid encode failed.\n");
		return FALSE;
	}
	buf=(unsigned char *)malloc(sizeof(unsigned char)*oidlen);
	oidlen=a2d_ASN1_OBJECT(buf,oidlen,oid,-1);

	ecdhparam->param_identify = 1;
	ecdhparam->param_length = oidlen;
	memcpy(ecdhparam->oid.oid_code, buf, oidlen);
	free(buf);

	return TRUE;
}

int getLocalIdentity(identity *localIdentity, char *localUserID)
{
	BIO *b=NULL;    //bio\u63a5\u53e3
	X509 *local_cert=NULL;  //X509\u683c\u5f0f\u670d\u52a1\u7aef\u8bc1\u4e66
	X509_NAME *issuer_name=NULL;   //\u8bc1\u4e66\u9881\u53d1\u8005\u540d\u5b57
	X509_NAME *subject_name=NULL;   //\u8bc1\u4e66\u6240\u6709\u8005\u540d\u5b57
	char issuer_str[256] = {0};          //\u9881\u53d1\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	char subject_str[256] = {0};         //\u6240\u6709\u8005\u540d\u5b57\u5b58\u50a8\u5b57\u7b26\u4e32
	long serialnum;
	int offset;
	//\u5c06PEM\u683c\u5f0f\u7684\u8bc1\u4e66\u5b58\u4e3aX509\u8bc1\u4e66\u683c\u5f0f
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

	if (strcmp(localUserID, CAID) == 0)
		//sprintf(certname, "./demoCA/cacert.pem");//./demoCA/
		sprintf(certname, "./cacert/cacert.pem");//./demoCA/
	else
		//sprintf(certname, "./demoCA/newcerts/usercert%d.pem", certnum);  //终端运行./client
		sprintf(certname, "./cert/usercert%s.pem", localUserID);                //eclipse调试或运行

	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	SSLeay_add_all_algorithms();   //\u52a0\u8f7d\u76f8\u5173\u7b97\u6cd5

	b=BIO_new_file(certname,"r");
	local_cert=PEM_read_bio_X509(b,NULL,NULL,NULL);
	BIO_free(b);
	if(local_cert==NULL)
	{
		printf("open local cert failed.\n");
		X509_free(local_cert);
		return FALSE;
	}

	issuer_name=X509_get_issuer_name(local_cert);
	X509_NAME_oneline(issuer_name,issuer_str,256);

	subject_name=X509_get_subject_name(local_cert);
	X509_NAME_oneline(subject_name,subject_str,256);

	serialnum = ASN1_INTEGER_get(X509_get_serialNumber(local_cert));
	X509_free(local_cert);

	localIdentity->identity_identify = 1; //X.509 cert

	offset = 0;
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)subject_str, strlen(subject_str));
	offset += strlen(subject_str);
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)issuer_str, strlen(issuer_str));
	offset += strlen(issuer_str);
	memcpy(localIdentity->cer_der.data + offset, (BYTE*)&serialnum, sizeof(serialnum)/sizeof(BYTE));
	offset += sizeof(serialnum);

	localIdentity->identity_length = offset;

	return TRUE;

}

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

BOOL gen_sign(BYTE * input,int sign_input_len,BYTE * sign_value, unsigned int *sign_output_len,EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	unsigned int i;
	BYTE sign_input_buffer[10000];


	memset(sign_input_buffer,0,sizeof(sign_input_buffer));
	memcpy(sign_input_buffer,input,sign_input_len);    //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, sign_input_buffer, sign_input_len))	//计算签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同;
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, & temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	* sign_output_len = temp_sign_len;
/*
	printf("签名值是: \n");
	for (i = 0; i < * sign_output_len; i++)
	{
		if (i % 16 == 0)
			printf("\n%08xH: ", i);
		printf("%02x ", sign_value[i]);
	}
	printf("\n");
*/
	//清理内存
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

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

void user_gen_cert_request(char *user_ID,char *username)
{
	X509_REQ *req;
	int ret = 0;
	long version = 3;
	X509_NAME *name;
	char mdout[20]; //bytes不要超过30位
	int mdlen = 0;
	const EVP_MD *md;
	BIO *b;

	RSA *rsa;
	EVP_PKEY * privkey,* pubkey;

	//初始化申请
	req = X509_REQ_new();
	ret = X509_REQ_set_version(req, version);

	//填写申请者相关信息
	char countryname[10] = "CN";
	char provincename[10] = "JS";
	char organizationname[10] = "CIOTC";

	char commonname[50];
	memset(commonname,0,sizeof(commonname));
	memcpy(commonname,username,strlen(username));
	commonname[strlen(username)] = '\0';

	name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_NID(name, NID_countryName, V_ASN1_PRINTABLESTRING,
			(unsigned char*) countryname, strlen(countryname), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName,
			V_ASN1_PRINTABLESTRING, (unsigned char*) provincename,
			strlen(provincename), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationName,
			V_ASN1_PRINTABLESTRING, (unsigned char*) organizationname,
			strlen(organizationname), -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_commonName, V_ASN1_PRINTABLESTRING,
			(unsigned char*) commonname, strlen(commonname), -1, 0);



	/*提取用户的公钥*/
	rsa = RSA_new();
	rsa = getprivkeyfromkeyfile(user_ID);

	RSA *tem = RSAPublicKey_dup(rsa);
	if (tem == NULL )
	{
		printf("提取用户公钥失败\n");
	}

	//将用户的RSA公钥转换成EVP_PKEY格式
	pubkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pubkey, tem);
	if (pubkey == NULL )
	{
		printf("RSA->EVP_PKEY 转化公钥失败\n");
	}

	//将用户的EVP_PKEY格式公钥添加到证书申请文件中的公钥字段部分
	ret = X509_REQ_set_pubkey(req, pubkey);
	printf("证书请求文件中的公钥字段添加完成！\n");


	/*提取用户的私钥来对证书认证申请文件进行签名(除签名字段之外的所有字段)*/
//	rsa = RSA_new();
//	rsa = getprivkeyfromkeyfile(user_ID);

	if (rsa == NULL )
	{
		printf("提取用户私钥失败！\n");
		return;
	}
	privkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(privkey, rsa);
	if (privkey == NULL )
	{
		printf("RSA->EVP_PKEY 转化私钥失败\n");
	}

	//hash 算法
	md = EVP_sha1();
	ret = X509_REQ_digest(req, md, (unsigned char *) mdout, &mdlen); //摘要
	ret = X509_REQ_sign(req, privkey, md); //用私钥签名
	if (!ret)
	{
		printf("私钥签名失败\n");
		X509_REQ_free(req);
		return;
	}
	// 写入文件,PEM和TXT格式
	else
	{
		printf("私钥签名成功\n");
		//将用户证书请求可视化打印输出出来，输出保存到txt文件
		b = BIO_new_file(USER_REQ_PRINT, "w");
		X509_REQ_print(b, req);
		BIO_free(b);

		//将用户证书请求保存起来，保存到PEM文件
		b = BIO_new_file(USER_REQ, "w");
		PEM_write_bio_X509_REQ(b, req);
		BIO_free(b);

//		//用户用自己的公钥先自己来验证证书请求的签名字段
//		ret = X509_REQ_verify(req, pubkey);
//		if (ret == 0)
//		{
//			printf("证书请求验证失败\n");
//		}
//		//printf("证书请求签名字段验证结果为：%d\n", ret);
//		printf("证书请求验证成功\n");
		X509_REQ_free(req);

		printf("证书请求文件已生成\n");
		return;
	}
}

/////////////////////////// filled by yaoyao ///////////////////////////////////
/* Scene 1 :
 * Register and authentication process
 * (step 1-6 11-16)
 */
//<auth active packet>
int ProcessWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet){

}

int HandleWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet){

}

//<access auth request packet>
int ProcessWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet){

}

int HandleWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet){

}

//<access auth response packet>
int HandleWAPIProtocolAccessAuthResp(RegisterContext *rc, AccessAuthRequ *access_auth_requ_packet,
		AccessAuthResp *access_auth_resp_packet){

}
/* Scene 1 :
 * Key negotiation process
 * (step 7-10 17-20)
 */
//Unicast key negotiation request
int ProcessUnicastKeyNegoRequest(RegisterContext *rc, UnicastKeyNegoRequ *unicast_key_nego_requ_packet){

}

int HandleUnicastKeyNegoRequest(RegisterContext *rc, const UnicastKeyNegoRequ *unicast_key_nego_requ_packet){

}

//Unicast key negotiation response
int ProcessUnicastKeyNegoResponse(RegisterContext *rc, UnicastKeyNegoResp *unicast_key_nego_resp_packet){

}

int HandleUnicastKeyNegoResponse(RegisterContext *rc, const UnicastKeyNegoResp *unicast_key_nego_resp_packet){

}

//Unicast key negotiation confirm
int ProcessUnicastKeyNegoConfirm(RegisterContext *rc, UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet){

}

int HandleUnicastKeyNegoConfirm(RegisterContext *rc, const UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet){

}

/* Scene 1 :
 * IPC access to NVR process
 * (step 21-22)
 */

/* Scene 1 :
 * IPC communicate to NVR process
 * (step 23-30)
 */
//////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////
//begin interface beteewn IPC and NVR
/*uac Transport beteewn IPC and NVR interface begin*/

int uac_get_Transportsdp(char *sdp_data)
{
	snprintf(sdp_data,21,"uac_get_Transportsdp\n");
	printf("uac_get_Transportsdp:%s\n",sdp_data);
	return 0;}

int uac_handle_Transportsdp(char *sdp_data)
{
	printf("uac_handle_Transportsdp:%s\n",sdp_data);
	return 0;}

int uac_send_Transportmedia(char * peer_location)
{
	printf("uac_send_Transportmedia\n");
	return 0;}

int uac_close_Transportmedia()
{
	printf("uac_close_Transportmedia\n");
	return 0;}

/*uac Transport beteewn IPC and NVR interface end*/

/*uas Transport beteewn IPC and NVR interface begin*/

int uas_handle_Transportsdp(char *sdp_data)
{
	printf("uas_handle_Transportsdp:%s\n",sdp_data);
	return 0;}

int uas_get_Transportsdp(char *sdp_data)
{
	snprintf(sdp_data,21,"uas_get_Transportsdp");
	printf("uas_get_Transportsdp:%s\n",sdp_data);
	return 0;}

int uas_receive_Transportmedia(char * peer_location)
{
	printf("uas_receive_Transportmedia\n");
	return 0;}

int uas_close_Transportmedia()
{
	printf("uas_close_Transportmedia\n");
	return 0;}

/*uas Transport beteewn IPC and NVR interface end*/

//end interface beteewn IPC and NVR
//////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////
//begin Play interface
//begin Play interface in uac
/*filled by yaoyao*/ // get sdp, fill in INVITE, send to media server by client
int uac_get_Playsdp(char *sdp_data)
{/*
	snprintf(sdp_data,1024,
			"v=0\r\n"
            "o=josua  0 0 IN IP4 192.168.1.1\r\n"
            "s=Playback\r\n"
			  "u=34020000001310000054:3\r\n"
            "c=IN IP4 192.168.1.1\r\n"
            "t=11111 22222\r\n"
            "m=audio 8000 RTP/AVP 0 8 101\r\n");*/
	snprintf(sdp_data,1024,
				"v=0 \r\n"
"o=- 0 0 IN IP4 127.0.0.1\r\n"
"s=Play\r\n"
"c=IN IP4 0.0.0.0\r\n"
"t=0 0\r\n"
"a=tool:libavformat 55.12.102\r\n"
"m=video 0 RTP/AVP 96\r\n"
"a=rtpmap:96 H264/90000\r\n"
"a=fmtp:96 packetization-mode=1\r\n"
"a=control:streamid=0\r\n"
);
	return 0;
}

/*filled by yaoyao*/ // handle sdp received from media server in client
int uac_handle_Playsdp(char *sdp_data)
{
	// nothing to do, just print
	printf("sdp_data in uac_handle_Playsdp: %s\n",sdp_data);
	return 0;
}

/*filled by yaoyao*/ // start request: media receiving process from media server in client
pid_t pid = -1;
int uac_receive_Playmedia(char * peer_location)
{
	// start ffplay process
    if(pid < 0){
            char *ffplay_prog_dir="";//"/home/yaoyao/ffmpeg_sources/ffplay/";
            char ffplay_cmd[256];
            char *ffplay_cmd_ptr = ffplay_cmd;
            snprintf(ffplay_cmd_ptr, 255,
            "%sffplay rtsp://192.168.115.42:5454/live.h264 >/dev/null 2>/dev/null",
            ffplay_prog_dir);

            printf("%s", ffplay_cmd_ptr);
            printf("\n");

            if((pid = fork()) < 0){
                    perror("fork()");
            }else if(pid == 0){
                    if(execl("/bin/sh", "sh", "-c", ffplay_cmd, (char *)0) < 0){
                            perror("execl failed");
                    }
                    pid++;
            }else{}
    }
	return 0;
}

/*filled by yaoyao*/ // close media receiving process from media server in client
int uac_close_Playmedia()
{

	// terminate ffplay process
    printf("kill %d\n",pid);
    kill(pid,SIGABRT);
    wait(NULL);
    pid++;
    printf("kill %d\n",pid);
    kill(pid,SIGABRT);
    wait(NULL);

    pid = -1;
	return 0;
}

//end Play interface in uac

//begin Play interface in uas
/*filled by yaoyao*/ // handle sdp data via INVITE received from client in media server
int uas_handle_Playsdp(char *sdp_data)
{
	// nothing to do, just print
	printf("sdp_data in uas_handle_Playsdp: %s\n",sdp_data);
	return 0;
}

/*filled by yaoyao*/ // get sdp data for sending to client in media server
/*filled by yaoyao*/ // p -> 1024 bytes
int uas_get_Playsdp(char *sdp_data)
{
	/*
	snprintf(sdp_data, 1024,
			"v=0\r\n"
			"o=%s 0 0 IN IP4 \r\n"
			"s=PLAY\r\n"
			"c=IN IP4 \r\n"
			"t=0 0\r\n"
			"m=video  STP/AVP 96\r\n"
			"a=sendonly\r\n"
			"a=rtpmap:96 H264/90000\r\n"
			"f=\r\n");*/
	snprintf(sdp_data,1024,
					"v=0 \r\n"
	"o=- 0 0 IN IP4 127.0.0.1 \r\n"
	"s=Play \r\n"
	"c=IN IP4 0.0.0.0 \r\n"
	"t=0 0 \r\n"
	"a=tool:libavformat 55.12.102 \r\n"
	"m=video 0 RTP/AVP 96 \r\n"
	"a=rtpmap:96 H264/90000 \r\n"
	"a=fmtp:96 packetization-mode=1 \r\n"
	"a=control:streamid=0 \r\n"
	);

	return 0;
}

/*filled by yaoyao*/ // start response: media sending process to client in media server
int uas_send_Playmedia(char * peer_location)
{
	// Nothing to do, because ffserver is running before uas started.
	return 0;
}

/*filled by yaoyao*/ // close media sending process to client in media server
int uas_close_Playmedia()
{
	// Nothing to do, because ffserver will be running all the time.
	return 0;
}
//end Play interface in uas
//end Play interface
//////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////
//begin History interface

//uac
// get rtsp data, fill in INFO for sending to media server by client
int uac_get_Historyrtsp(char *rtsp_data, struct st_rtsptype  *ptr_st_rtsptype)
{
	// if rtsp datatype in {"PLAY", "FAST", "SLOW"}: check scale
	snprintf(rtsp_data,1024,
				"this is test data!");
	printf("uac_get_Historyrtsp\n");
	return 0;
}

// handle MESSAGE, received from media server in client
int handle_HistoryEOFmessage(char *message)
{
	printf("uac_handle_HistoryEOFmessage\n");
	return 0;
}

//uas
// handle rtsp data via INFO, received from client by media server
int uas_handle_Historyrtsp(char *rtsp_data)
{
	printf("uas_handle_Historyrtsp\n");
	return 0;
}

// get MESSAGE for sending to client in media server
// p -> 1024 bytes
int get_HistoryEOFmessage(char *message, char *message_type)
{
	// message_type: "EOF"
	snprintf(message,1024,
			"<?xml version=\"1.0\"?>"
			"<Notify>"
			"<CmdType>MediaStatus</CmdType>"
			"<SN>8</SN>"
			"<DeviceID>000</DeviceID>"
			"<NotifyType>121</NotifyType>"
			"</Notify>");
	return 0;
}

//end History interface
//////////////////////////////////////////////////////////////



/*
int uas_function_run(funcP fun_name,void(*arg))
{
	(*fun_name)(arg);
	return 0;
	}
*/


int interface_init()
{
	user_type=0;
	call_type=0;

	invite_user_type=0;
	invite_type=0;
/*
	uas_handle_invite_sdp=uas_handle_Playsdp;
	uas_get_invite_sdp=uas_get_Playsdp;
	uas_start_transport=uas_send_Playmedia;
	uas_handle_Message=uas_handle_rtsp;
	uas_stop_transport=uas_close_Playmedia;
	*/
	//uas_get_info=uas_get_message;
	return 0;
}

int uac_get_sdp(char *sdp_data)
{
	if(user_type==USER_TYPE_IPC)
		;//uac_get_Transportsdp(sdp_data);
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_get_Playsdp(sdp_data);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_get_Historysdp(sdp_data);
		else
			return -1;
	}
	else
		return -1;
	return 0;
	}

int uac_handle_sdp(char *sdp_data)
{
	if(user_type==USER_TYPE_IPC)
		;//uac_handle_Transportsdp(sdp_data);
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_handle_Playsdp(sdp_data);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_handle_Historysdp(sdp_data);
		else
			return -1;
	}
	else
		return -1;
	return 0;
}

int uac_start_media(char * peer_location)
{printf("uac_start_media:%s",peer_location);
	if(user_type==USER_TYPE_IPC)
		;//uac_send_Transportmedia(peer_location);
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_receive_Playmedia(peer_location);
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_receive_Historymedia(peer_location);
		else
			return -1;
	}
	else
		return -1;
	return 0;
	}

int uac_close_media()
{
	if(user_type==USER_TYPE_IPC)
		;//uac_close_Transportmedia();
	else if(user_type==USER_TYPE_CLIENT)
	{
		if(call_type==CALL_TYPE_PLAY)
			uac_close_Playmedia();
		else if(call_type==CALL_TYPE_PLAYBACK)
			;//uac_close_Historymedia();
		else
			return -1;
	}
	else
		return -1;
	return 0;
}

//uas

int uas_handle_sdp(char *sdp_data)
{
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_handle_Transportsdp(sdp_data);
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_handle_Playsdp(sdp_data);
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_handle_Historysdp(sdp_data);
		else
			return -1;
	}
	else
		return -1;
	return 0;}

int uas_get_sdp(char *sdp_data)
{
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_get_Transportsdp(sdp_data);
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_get_Playsdp(sdp_data);
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_get_Historysdp(sdp_data);
		else
			return -1;
	}
	else
		return -1;
	return 0;}

int uas_start_media(char *peer_location)
{
	printf("uas_start_media:%s\n",peer_location);
	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_receive_Transportmedia(peer_location);
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_send_Playmedia(peer_location);
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_send_Historymedia(peer_location);
		else
			return -1;
	}
	else
		return -1;
	return 0;}

int uas_close_media()
{

	if(invite_user_type==INVITE_USER_TYPE_IPC)
		;//uas_close_Transportmedia();
	else if(invite_user_type==INVITE_USER_TYPE_CLIENT)
	{
		if(invite_type==INVITE_TYPE_PLAY)
			uas_close_Playmedia();
		else if(invite_type==INVITE_TYPE_PLAYBACK)
			;//uas_close_Historymedia();
		else
			return -1;
	}
	else
		return -1;
	return 0;}

//end uas interface


//begin register interface

int handle_401_Unauthorized_data(void *data)
{
	printf("handle_401_Unauthorized_data:%s\n",data);
	return 0;}

int get_register2_data(void *data)
{
	memcpy(data,"+register2_data+", 17);
	printf("get_register2_data:%s\n",data);
	return 0;}

int handle_response_data(void *data)
{
	printf("handle_response_data:%s\n",data);
	return 0;}

//end register interface

