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

const time_t TimeThreshold = 10; // seconds

static int getKeyRingNum(KeyBox *keybox, char *id)
{
	int i;
	for(i=0; i < keybox->nkeys; i++){
		if(!strcmp(keybox->keyrings[i].partner_id, id)){
			return i;
		}
	}
	return -1;
}

BOOL getCertData(char *userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写如乱码到文件中

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

	sprintf(certname, "./cert/usercert%s.pem", userID);

	if(annotation == 2)
		printf("  cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}
	fwrite(buf, 1, len, fp);
	if(annotation == 2)
		printf("  cert's length is %d\n", len);
	fclose(fp);
	if(annotation == 2)
		printf("  write cert complete!\n");

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
	//RSA rsa_struct;
	RSA* rsa;

	char keyname[40];

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


// Return 32Byte digest
//SHA256(input, input_len, output);

// Return 32Byte digest
void hmac_sha256(unsigned char *data, unsigned int data_len, unsigned char *key, unsigned int key_len, unsigned char* result, unsigned int result_len)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);
        //HMAC_Init_ex(&ctx, key, 16, EVP_sha256(), NULL);
	HMAC_Init_ex(&ctx, key, key_len, EVP_sha256(), NULL);
        //HMAC_Update(&ctx, data, 8);
	HMAC_Update(&ctx, data, data_len);
        HMAC_Final(&ctx, result, &result_len);
        HMAC_CTX_cleanup(&ctx);
}

void kd_hmac_sha256(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char *output, unsigned int length)
{
	int i;
	for(i=0; length/SHA256_DIGEST_SIZE; i++,length-=SHA256_DIGEST_SIZE){
		hmac_sha256(text,text_len,key,key_len,&output[i*SHA256_DIGEST_SIZE],SHA256_DIGEST_SIZE);
		text=&output[i*SHA256_DIGEST_SIZE];
		text_len=SHA256_DIGEST_SIZE;
	}
	if(length>0)
		hmac_sha256(text,text_len,key,key_len,&output[i*SHA256_DIGEST_SIZE],length);
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

static EVP_PKEY *genECDHtemppubkey()
{
	EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *params = NULL;
	/* NB: assumes pkey, peerkey have been already set up */

	/* Create the context for parameter generation */
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) printf("Error in genECDHtemppubkey\n");

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx)) printf("Error in genECDHtemppubkey\n");

	/* We're going to use the ANSI X9.62 Prime 256v1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) printf("error in genECDHtemppubkey\n");

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &params)) printf("Error in genECDHtemppubkey\n");

	/* Create the context for the key generation */
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) printf("Error in genECDHtemppubkey\n");

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(kctx)) printf("Error in genECDHtemppubkey\n");
	if (1 != EVP_PKEY_keygen(kctx, &pkey)) printf("Error in genECDHtemppubkey\n");

	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);

	return pkey;
}

static unsigned char *genECDHsharedsecret(EVP_PKEY *pkey, EVP_PKEY *peerkey, size_t *secret_len)
{
		EVP_PKEY_CTX *ctx;
		unsigned char *secret;

		/* Get the peer's public key, and provide the peer with our public key -
		 * how this is done will be specific to your circumstances */
		// one of input parameters

		/* Create the context for the shared secret derivation */
		if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) printf("Error in genECDHsharedsecret\n");

		/* Initialise */
		if(1 != EVP_PKEY_derive_init(ctx)) printf("Error in genECDHsharedsecret\n");

		/* Provide the peer public key */
		if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) printf("Error in genECDHsharedsecret\n");

		/* Determine buffer length for shared secret */
		if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) printf("Error in genECDHsharedsecret\n");

		/* Create the buffer */
		if(NULL == (secret = OPENSSL_malloc(*secret_len))) printf("Error in genECDHsharedsecret\n");

		/* Derive the shared secret */
		if(1 != (EVP_PKEY_derive(ctx, secret, secret_len))) printf("Error in genECDHsharedsecret\n");

		EVP_PKEY_CTX_free(ctx);

		/* Never use a derived secret directly. Typically it is passed
		 * through some hash function to produce a key */
		return secret;
}

static int getECDHparam(ecdh_param *ecdhparam, const char *oid)
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
	//BYTE sign_input_buffer[10000];
	BYTE *sign_input_buffer = (BYTE *)malloc(sign_input_len);

	memset(sign_input_buffer,0,sign_input_len);
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
	free(sign_input_buffer);
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

// step2: SIP Server - SIP UA(NVR)
int ProcessWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet)
{
	//fill flag
	if(annotation == 2)
		printf("fill flag:\n");
	auth_active_packet->flag = 2; // step2

	//fill auth identify, first time random number
	if(annotation == 2)
		printf("fill auth identify:\n");

	//fill ae rand number
	if(annotation == 2)
		printf("fill ae rand number:\n");
	gen_randnum((BYTE *)&auth_active_packet->aechallenge, sizeof(auth_active_packet->aechallenge));

	//fill auth active time
	time(&auth_active_packet->authactivetime);

	/*
	 * auth_id = SHA256(n_{SIP Server} XOR Password_{SIP UA} XOR Time_{active})
	 */
	unsigned char text[RAND_LEN];
	memset(text, 0, RAND_LEN);
	int password_len = strlen(rc->peer_password);
	memcpy(text, rc->peer_password, (password_len>RAND_LEN ? RAND_LEN : password_len));
	int i;
	for(i=0; i<RAND_LEN; i++){
		text[i] ^= auth_active_packet->aechallenge[i];
		//text[i] ^= ??? auth_active_packet->authactivetime;
	}
	SHA256(text, RAND_LEN, auth_active_packet->authidentify);

	//fill local ASU identity
	if(annotation == 2)
		printf("fill local ASU identity:\n");

	getLocalIdentity(&auth_active_packet->localasuidentity, rc->radius_id);

	//fill ecdh param
	if(annotation == 2)
		printf("fill ecdh param:\n");
	const  char  oid[]={"1.2.156.11235.1.1.2.1"};

	getECDHparam(&auth_active_packet->ecdhparam, oid);

	//fill ae certificate
	if(annotation == 2)
		printf("fill ae certificate:\n");
	auth_active_packet->certificatestaae.cer_identify = 1; //X.509 cert

	BYTE cert_buffer[5000];
	int cert_len = 0;

	if (!getCertData(rc->self_id, cert_buffer, &cert_len))    //先读取ASUE证书
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}

	auth_active_packet->certificatestaae.cer_length = cert_len;   //证书长度字段
	memcpy((auth_active_packet->certificatestaae.cer_X509),(BYTE*)cert_buffer,strlen((char*)cert_buffer));


	//fill ae signature
	if(annotation == 2)
		printf("fill ae signature:\n");
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(rc->self_id);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)auth_active_packet,(sizeof(AuthActive)-sizeof(auth_active_packet->aesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	auth_active_packet->aesign.sign.length = sign_len;
	memcpy(auth_active_packet->aesign.sign.data,sign_value,sign_len);

	return TRUE;
}

// step3: SIP UA(NVR) - SIP Server
int HandleWAPIProtocolAuthActive(RegisterContext *rc, AuthActive *auth_active_packet)
{
	//write ae cert into cert file
	printf("write ae cert into cert file:\n");
	char *ae_ID = rc->peer_id;
	writeCertFile(ae_ID, (BYTE *)auth_active_packet->certificatestaae.cer_X509, (int)auth_active_packet->certificatestaae.cer_length);

	//verify sign of AE
	printf("verify sign of AE:\n");
	//read ae certificate get ae pubkey(公钥)
	EVP_PKEY *aepubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE deraepubkey[1024];
	int aepubkeyLen;
	aepubKey = getpubkeyfromcert(ae_ID);
	if(aepubKey == NULL){
		printf("get ae's public key failed.\n");
		return FALSE;
		}
	pTmp = deraepubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);

	//verify the sign
	if (verify_sign((BYTE *) auth_active_packet,
			sizeof(AuthActive) - sizeof(sign_attribute),
			auth_active_packet->aesign.sign.data,
			auth_active_packet->aesign.sign.length, aepubKey))
	{
		printf("  验证AE签名正确......\n");
		EVP_PKEY_free(aepubKey);
	}else{
		printf("ae's sign verify failed.\n");
		return FALSE;
		}

	//verify FLAG
	printf("verify FLAG:\n");
	if(auth_active_packet->flag != 2){
		printf("Not the first time access.\n");
		return FALSE;
	}

	//verify auth active time
    time_t  t;
    time(&t);
    if((t - auth_active_packet->authactivetime) > TimeThreshold)
    	return FALSE;

	//verify auth_id
    printf("verify auth identity.\n");
	/*
	 * auth_id = SHA256(n_{SIP Server} XOR Password_{SIP UA} XOR Time_{active})
	 * then compare
	 */
	unsigned char text[RAND_LEN];
	memset(text, 0, RAND_LEN);
	int password_len = strlen(rc->self_password);
	memcpy(text, rc->self_password, (password_len>RAND_LEN ? RAND_LEN : password_len));
	int i;
	for(i=0; i<RAND_LEN; i++){
		text[i] ^= auth_active_packet->aechallenge[i];
		//text[i] ^= ??? auth_active_packet->authactivetime;
	}
	BYTE authidentify[RAND_LEN];
	SHA256(text, RAND_LEN, authidentify);

	if(memcmp(authidentify, auth_active_packet->authidentify, RAND_LEN)){
		printf("ae's auth identity verify failed.\n");
		return FALSE;
	}
	return TRUE;
}

int ProcessWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet)
{
		//fill flag
		printf("fill flag:\n");
		access_auth_requ_packet->flag = 3; // step3

		//fill auth identify, same as auth active packet
		printf("fill auth identify:\n");
		memcpy((BYTE *)&access_auth_requ_packet->authidentify, (BYTE *)&auth_active_packet->authidentify, sizeof(access_auth_requ_packet->authidentify));

		//fill asue rand number
		printf("fill asue rand number:\n");
		gen_randnum((BYTE *)&access_auth_requ_packet->asuechallenge, sizeof(access_auth_requ_packet->aechallenge));

		//fill asue key data
		printf("fill asue cipher data.\n");
		/*
		 * temporary key for ECDH
		 */
		memcpy(&rc->keydata, genECDHtemppubkey(), sizeof(rc->keydata));
		memcpy(&access_auth_requ_packet->asuekeydata, &rc->keydata, sizeof(access_auth_requ_packet->asuekeydata));

		//fill ae rand number, same as auth active packet
		printf("fill ae rand number:\n");
		memcpy((BYTE *)&access_auth_requ_packet->aechallenge, (BYTE *)&auth_active_packet->aechallenge, sizeof(access_auth_requ_packet->aechallenge));

		//fill ae identity
		printf("fill ae identity:\n");
		char *ae_ID = rc->peer_id;
		getLocalIdentity(&access_auth_requ_packet->staaeidentity, ae_ID);

		//fill ecdh param, same as auth active packet
		printf("fill ecdh param:\n");
		const  char  oid[]={"1.2.156.11235.1.1.2.1"};
		getECDHparam(&access_auth_requ_packet->ecdhparam, oid);

		//fill asue certificate
		printf("fill asue certificate:\n");
		access_auth_requ_packet->certificatestaasue.cer_identify = 1; //X.509 cert

		BYTE cert_buffer[5000];
		int cert_len = 0;

		if (!getCertData(rc->self_id, cert_buffer, &cert_len))	  //先读取ASUE证书
		{
			printf("将证书保存到缓存buffer失败!");
			return FALSE;
		}

		access_auth_requ_packet->certificatestaasue.cer_length = cert_len;   //证书长度字段
		memcpy((access_auth_requ_packet->certificatestaasue.cer_X509),(BYTE*)cert_buffer,strlen((char*)cert_buffer));

		//fill asue signature
		printf("fill asue signature:\n");
		//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
		EVP_PKEY * privKey;
		BYTE sign_value[1024];					//保存签名值的数组
		unsigned int  sign_len;

		privKey = getprivkeyfromprivkeyfile(rc->self_id);
		if(privKey == NULL)
		{
			printf("getprivkeyitsself().....failed!\n");
			return FALSE;
		}

		if(!gen_sign((BYTE *)access_auth_requ_packet,(sizeof(AccessAuthRequ)-sizeof(access_auth_requ_packet->asuesign)),sign_value, &sign_len,privKey))
		{
			printf("generate signature failed.\n");
			return FALSE;
		}

		access_auth_requ_packet->asuesign.sign.length = sign_len;
		memcpy(access_auth_requ_packet->asuesign.sign.data,sign_value,sign_len);

		return TRUE;
}

// step4: SIP Server - Radius Server
int HandleWAPIProtocolAccessAuthRequest(RegisterContext *rc, AuthActive *auth_active_packet,
		AccessAuthRequ *access_auth_requ_packet)
{
	//write asue cert into cert file
	if(annotation == 2)
		printf("write asue cert into cert file:\n");
	char *asue_ID = rc->peer_id;
	writeCertFile(asue_ID, (BYTE *)access_auth_requ_packet->certificatestaasue.cer_X509, (int)access_auth_requ_packet->certificatestaasue.cer_length);

	//verify sign of ASUE
	if(annotation == 2)
		printf("verify sign of ASUE:\n");
	//read ae certificate get ae pubkey(公钥)
	EVP_PKEY *asuepubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE derasuepubkey[1024];
	int asuepubkeyLen;
	asuepubKey = getpubkeyfromcert(asue_ID);
	if(asuepubKey == NULL){
		printf("get asue's public key failed.\n");
		return FALSE;
		}

	pTmp = derasuepubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	asuepubkeyLen = i2d_PublicKey(asuepubKey, &pTmp);

	//verify the sign
	if (verify_sign((BYTE *) access_auth_requ_packet,
			sizeof(AccessAuthRequ) - sizeof(sign_attribute),
			access_auth_requ_packet->asuesign.sign.data,
			access_auth_requ_packet->asuesign.sign.length, asuepubKey))
	{
		printf("  验证ASUE签名正确......\n");
		EVP_PKEY_free(asuepubKey);
	}else{
		printf("asue's sign verify failed.\n");
		return FALSE;
		}

	//verify FLAG
	if(annotation == 2)
		printf("verify FLAG:\n");
	if(access_auth_requ_packet->flag != 0x04){
		printf("verify flag failed.\n");
		return FALSE;
	}

	//verify auth identity, is same auth active packet
	if(annotation == 2)
		printf("verify auth identity:\n");
	if(memcmp(access_auth_requ_packet->authidentify,
		auth_active_packet->authidentify,
		sizeof(access_auth_requ_packet->authidentify)) != 0)
		printf("verify auth identity failed!\n");

	//verify AE identity
	if(annotation == 2)
		printf("verify AE identity\n");
	identity localaeidentity;
	getLocalIdentity(&localaeidentity, rc->self_id);

	if( memcmp(access_auth_requ_packet->staaeidentity.cer_der.data,
		localaeidentity.cer_der.data,
		localaeidentity.identity_length) != 0){
		printf("verify AE identity failed.\n");
		printf("length:%d, %d\n", localaeidentity.identity_length, access_auth_requ_packet->staaeidentity.identity_length);
		printf("data[:20]: %20s, %20s\n", localaeidentity.cer_der.data, access_auth_requ_packet->staaeidentity.cer_der.data);
		return FALSE;
	}else {
		if(annotation == 2)
			printf("verify AE identity succeed.\n");
	}

	//verify AE rand number, is same auth active packet
	if(annotation == 2)
		printf("verify AE rand number:\n");
	if(memcmp(access_auth_requ_packet->aechallenge,
		auth_active_packet->aechallenge,
		sizeof(access_auth_requ_packet->aechallenge)) != 0)
		printf("verify AE rand number failed!\n");

	return TRUE;
}
int ProcessWAPIProtocolCertAuthRequest(RegisterContext *rc,
		AccessAuthRequ *access_auth_requ_packet, CertificateAuthRequ *certificate_auth_requ_packet)
{
	//fill addid
	memcpy((BYTE *)&(certificate_auth_requ_packet->addid.mac1),rc->peer_MACaddr.macaddr,sizeof(certificate_auth_requ_packet->addid.mac1));
	memcpy((BYTE *)&(certificate_auth_requ_packet->addid.mac2),rc->self_MACaddr.macaddr,sizeof(certificate_auth_requ_packet->addid.mac2));

	//fill ae and asue rand number
	memcpy((BYTE *)&(certificate_auth_requ_packet->aechallenge), (BYTE *)&(access_auth_requ_packet->aechallenge), sizeof(certificate_auth_requ_packet->aechallenge));
	memcpy((BYTE *)&(certificate_auth_requ_packet->asuechallenge), (BYTE *)&(access_auth_requ_packet->asuechallenge), sizeof(certificate_auth_requ_packet->asuechallenge));

	//fill asue certificate
	memcpy(&(certificate_auth_requ_packet->staasuecer),&(access_auth_requ_packet->certificatestaasue),sizeof(certificate));
	//memset((BYTE *)&(certificate_auth_requ_packet->staasuecer),0,sizeof(certificate));

	//fill ae certificate
	BYTE cert_buffer[5000];
	int cert_len = 0;

	memset(cert_buffer,0,sizeof(cert_buffer));
	cert_len = 0;

	if (!getCertData(rc->self_id, cert_buffer, &cert_len)) //读取AE证书，"usercert2.pem",uesrID=2
	{
		printf("将证书保存到缓存buffer失败!");
		return FALSE;
	}

	certificate_auth_requ_packet->staaecer.cer_length = cert_len;   //证书长度字段
	memcpy((certificate_auth_requ_packet->staaecer.cer_X509),cert_buffer, cert_len);

	//fill ae signature
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(rc->self_id);

	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign( (BYTE *)certificate_auth_requ_packet, sizeof(CertificateAuthRequ)-sizeof(certificate_auth_requ_packet->aesign),sign_value, &sign_len,privKey ))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	certificate_auth_requ_packet->aesign.sign.length = sign_len;
	memcpy(certificate_auth_requ_packet->aesign.sign.data,sign_value,sign_len);

	return TRUE;
}

// step5: Radius Server - SIP Server
// implemented source files on Radius Server

// step6: SIP Server - SIP UA(NVR)
int HandleProcessWAPIProtocolCertAuthResp(RegisterContext *rc,
		CertificateAuthRequ *certificate_auth_requ_packet,
		CertificateAuthResp *certificate_auth_resp_packet,
		AccessAuthResp *access_auth_resp_packet)
{
	memset((BYTE *)access_auth_resp_packet, 0, sizeof(AccessAuthResp));

	//读取CA(驻留在ASU)中的公钥证书获取CA公钥
	EVP_PKEY *asupubKey = NULL;
	BYTE *pTmp = NULL;
	BYTE derasupubkey[1024];
	int asupubkeyLen;
	asupubKey = getpubkeyfromcert(rc->radius_id);
	if(asupubKey == NULL){
		printf("get asu's public key failed.\n");
		return FALSE;
		}

	pTmp = derasupubkey;
	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
	asupubkeyLen = i2d_PublicKey(asupubKey, &pTmp);

	//验证ASU服务器对整个证书认证响应分组(除本字段外)的签名，检验该分组的完整性、验证该份组的发送源身份
	if (verify_sign((BYTE *) certificate_auth_resp_packet,
			sizeof(CertificateAuthResp) - sizeof(sign_attribute),
			certificate_auth_resp_packet->asusign.sign.data,
			certificate_auth_resp_packet->asusign.sign.length, asupubKey))
	{
		printf("验证ASU服务器对整个证书认证响应分组(除本字段外)的签名正确！！！......\n");
		EVP_PKEY_free(asupubKey);
	}

	//验证ASUE随机数是否一致(证书认证请求分组vs证书认证响应分组)
	if(annotation == 2)
		printf("verify AE rand number between certificate_auth_requ vs certificate_auth_resp_packet:\n");
	if (memcmp(certificate_auth_resp_packet->cervalidresult.random1,
			certificate_auth_requ_packet->aechallenge,
			sizeof(certificate_auth_requ_packet->aechallenge)) != 0)
	{
		printf("verify ASUE random number failed between certificate_auth_requ vs certificate_auth_resp_packet!\n");
		return FALSE;
	}

	//检查ASU对ASUE证书的验证结果字段(certificate_auth_resp_packet->cervalidresult.cerresult1)
	if(annotation == 2)
		printf("verify cert valid result of ASUE:\n");
	if (certificate_auth_resp_packet->cervalidresult.cerresult1!= 0)
	{
		//printf("asu verify asue cert valid result failed.\n");
		printf("警告：网络硬盘录像机验证摄像机失败！不允许该摄像机接入！.\n");
		return FALSE;
	}
	else if(annotation == 2)
		printf("Authentication succeed!!\n");       //asu verify asue cert valid result succeed
	else if(annotation == 1)
		printf("网络硬盘录像机验证摄像机成功！允许该摄像机接入！\n");       //asu verify asue cert valid result succeed

	//读取证书认证响应分组中的证书验证结果字段，将该字段拷贝到接入认证响应分组中的复合证书验证结果的证书验证结果字段中
	memcpy(&(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result),&(certificate_auth_resp_packet->cervalidresult),sizeof(certificate_valid_result));

	//读取证书认证响应分组中的ASU服务器对证书验证结果字段的签名字段，将该字段拷贝到接入认证响应分组中的复合证书验证结果的签名字段中
	memcpy(&(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign),
			&(certificate_auth_resp_packet->asusign),
			sizeof(certificate_valid_result));

	return TRUE;

}

int ProcessWAPIProtocolAccessAuthResp(RegisterContext *rc,
		AccessAuthRequ *access_auth_requ_packet, AccessAuthResp *access_auth_resp_packet)
{
	//fill flag, same as access auth requ packet
	if(annotation == 2)
		printf("fill flag:\n");
	access_auth_resp_packet->flag = 6; // step6

	//fill auth identify, same as access auth requ packet
	if(annotation == 2)
		printf("fill auth identify:\n");
	memcpy((BYTE *)&access_auth_resp_packet->authidentify,(BYTE *)&access_auth_requ_packet->authidentify, sizeof(access_auth_resp_packet->authidentify));

	//fill asue rand number
	if(annotation == 2)
		printf("fill asue rand number:\n");
	memcpy((BYTE *)&access_auth_resp_packet->asuechallenge, (BYTE *)&access_auth_requ_packet->asuechallenge, sizeof(access_auth_resp_packet->aechallenge));

	//fill ae rand number
	if(annotation == 2)
		printf("fill ae rand number:\n");
	memcpy((BYTE *)&access_auth_resp_packet->aechallenge, (BYTE *)&access_auth_requ_packet->aechallenge, sizeof(access_auth_resp_packet->aechallenge));

	//fill ae key data
	if(annotation == 2)
		printf("fill ae cipher data:\n");
	/*
	 * temporary key for ECDH
	 */
	memcpy(&rc->keydata, genECDHtemppubkey(), sizeof(rc->keydata));
	memcpy(&access_auth_resp_packet->aekeydata, &rc->keydata, sizeof(access_auth_resp_packet->aekeydata));

	//fill certificate valid result
	if(annotation == 2)
		printf("fill certificate valid result complete.\n");
	//almost same type and content as certificate_auth_resp_packet, except addid segment
	//access_auth_resp_packet->cervalidresult is filled in "HandleProcessWAPIProtocolCertAuthResp" function called before
	//So skip this step.

	//fill asue access result, depend on "fill certificate valid result" step
	if(annotation == 2)
		printf("fill access result:\n");
	if(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result.cerresult1 == 0)
	{
		access_auth_resp_packet->accessresult = 0; // by means of asu's asue cerresult1,ae set asue's access result(0-succeed,1-failed)
	}

	//fill ae signature
	if(annotation == 2)
		printf("fill ae signature:\n");
	//AE\u4f7f\u7528AE\u7684\u79c1\u94a5(userkey2.pem)\u6765\u751f\u6210AE\u7b7e\u540d
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(rc->self_id);
	if(privKey == NULL)
	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)access_auth_resp_packet,(sizeof(AccessAuthResp)-sizeof(access_auth_resp_packet->aesign)),sign_value, &sign_len,privKey))
	{
		printf("generate signature failed.\n");
		return FALSE;
	}

	access_auth_resp_packet->aesign.sign.length = sign_len;
	memcpy(access_auth_resp_packet->aesign.sign.data,sign_value,sign_len);

	// compute MasterKey and auth_id_next
	/*
	 * [MasterKey, auth_id_next_seed] = KD-HMAC-SHA256(ECDH_keydata,
	 *                    n_SIPServer || n_SIPUA || "masterkeyexpansionforkeyandadditionalnonce")
	 * auth_id_next = SHA256(auth_id_next_seed)
	 */
	unsigned char *ECDH_keydata; // shared secret
	size_t secretlen=KEY_LEN;
	ECDH_keydata = genECDHsharedsecret(&rc->keydata, &access_auth_requ_packet->asuekeydata, &secretlen);

	char *tempstring = "masterkeyexpansionforkeyandadditionalnonce";
	int outputlen = sizeof(rc->keybox.keyrings[0].MasterKey) + sizeof(rc->auth_id_next);
	int textlen = sizeof(access_auth_requ_packet->aechallenge) +
			sizeof(access_auth_requ_packet->asuechallenge) +
			strlen(tempstring);
	unsigned char *output = malloc(outputlen);
	unsigned char *text = malloc(textlen);
	kd_hmac_sha256(text, textlen, ECDH_keydata, KEY_LEN, output, outputlen);

	int i;
	if( (i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0 ){
		if(i >= MAXKEYRINGS){
			printf("Key rings is full!\n");
		}else{
		strcpy(rc->keybox.keyrings[rc->keybox.nkeys].partner_id, rc->peer_id);
		i = rc->keybox.nkeys;
		rc->keybox.nkeys++;
		}
	}
	memcpy(rc->keybox.keyrings[i].MasterKey, output, sizeof(rc->keybox.keyrings[i].MasterKey));
	SHA256(output+sizeof(rc->keybox.keyrings[i].MasterKey), sizeof(rc->auth_id_next), rc->auth_id_next);
	free(output);
	free(text);

	return TRUE;
}

// step6+: SIP UA(NVR)
int HandleWAPIProtocolAccessAuthResp(RegisterContext *rc, AccessAuthRequ *access_auth_requ_packet,
		AccessAuthResp *access_auth_resp_packet)
{
		//verify sign of AE
		printf("verify sign of AE:\n");
		//read ae certificate get ae pubkey(公钥)
		EVP_PKEY *aepubKey = NULL;
		BYTE *pTmp = NULL;
		BYTE deraepubkey[1024];
		int aepubkeyLen;
		char *ae_ID = rc->peer_id;
		aepubKey = getpubkeyfromcert(ae_ID);
		if(aepubKey == NULL){
			printf("get ae's public key failed.\n");
			return FALSE;
			}

		pTmp = deraepubkey;
		//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
		aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);

		//verify the sign
		if (verify_sign((BYTE *) access_auth_resp_packet,
				sizeof(AccessAuthResp) - sizeof(sign_attribute),
				access_auth_resp_packet->aesign.sign.data,
				access_auth_resp_packet->aesign.sign.length, aepubKey))
		{
			printf("  验证AE签名正确......\n");
			EVP_PKEY_free(aepubKey);
		}else{
			printf("ae's sign verify failed.\n");
			return FALSE;
			}

		//verify access result
		printf("verify access result:\n");
		if(access_auth_resp_packet->accessresult != 0){
			printf("verity access result failed.\n");
			return FALSE;
		}

		//verify FLAG
		printf("verify FLAG:\n");
		if(access_auth_resp_packet->flag != 0x04){
			printf("verity flag failed.\n");
			return FALSE;
		}

		//verify ASUE AE random number
		printf("verify ASUE, AE rand number:\n");
		if(memcmp(access_auth_resp_packet->asuechallenge,
			access_auth_requ_packet->asuechallenge,
			sizeof(access_auth_resp_packet->asuechallenge)) != 0)
		{
			printf("verify ASUE random number failed!\n");
			return FALSE;
		}

		if(memcmp(access_auth_resp_packet->aechallenge,
			access_auth_requ_packet->aechallenge,
			sizeof(access_auth_resp_packet->aechallenge)) != 0)
		{
			printf("verify AE random number failed!\n");
			return FALSE;
		}

		//verify auth identity is same as access auth requ packet
		printf("verify auth identity:\n");
		if(memcmp(access_auth_resp_packet->authidentify,
			access_auth_requ_packet->authidentify,
			sizeof(access_auth_resp_packet->authidentify)) != 0){
			printf("verify auth identity failed!\n");
			return FALSE;
			}

		//verify cert valid result: verify sign of ASU
		printf("verify cert valid result: verify sign of ASU:\n");
		//read ae certificate get ae pubkey(公钥)
		EVP_PKEY *asupubKey = NULL;
		//BYTE *pTmp = NULL;
		BYTE derasupubkey[1024];
		int asupubkeyLen;
		char *asu_ID = rc->radius_id;
		asupubKey = getpubkeyfromcert(asu_ID);

		pTmp = derasupubkey;
		//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
		asupubkeyLen = i2d_PublicKey(asupubKey, &pTmp);

		//verify the sign
		if (verify_sign((BYTE *)&access_auth_resp_packet->cervalrescomplex,
				sizeof(access_auth_resp_packet->cervalrescomplex) - sizeof(sign_attribute),
				access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.data,
				access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.length,
				asupubKey))
		{
			printf("  验证ASU签名正确......\n");
			EVP_PKEY_free(asupubKey);
		}else{
			printf("asu's sign verify failed.\n");

			int i;
			printf("length=%d\n",access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.length);
			for (i = 0; i < access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.length; i++)
			{
				if (i % 16 == 0)
					printf("\n%08xH: ", i);
				printf("%02x ", access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result_asu_sign.sign.data[i]);
			}
			printf("\n");


			return FALSE;
			}

		//verify cert valid result of AE
		printf("verify cert valid result of AE:\n");
		if(access_auth_resp_packet->cervalrescomplex.ae_asue_cert_valid_result.cerresult2 != 0){
			printf("verify cert valid result failed.\n");
			return FALSE;
			}

		printf("Authentication succeed!!\n");

		// compute MasterKey and auth_id_next
		/*
		 * [MasterKey, auth_id_next_seed] = KD-HMAC-SHA256(ECDH_keydata,
		 *                    n_SIPServer || n_SIPUA || "masterkeyexpansionforkeyandadditionalnonce")
		 * auth_id_next = SHA256(auth_id_next_seed)
		 */
		unsigned char *ECDH_keydata; // shared secret
		size_t secretlen = KEY_LEN;
		ECDH_keydata = genECDHsharedsecret(&rc->keydata, &access_auth_resp_packet->aekeydata, &secretlen);

		char *tempstring = "masterkeyexpansionforkeyandadditionalnonce";
		int outputlen = sizeof(rc->keybox.keyrings[0].MasterKey) + sizeof(rc->auth_id_next);
		int textlen = sizeof(access_auth_requ_packet->aechallenge) +
				sizeof(access_auth_requ_packet->asuechallenge) +
				strlen(tempstring);
		unsigned char *output = malloc(outputlen);
		unsigned char *text = malloc(textlen);
		kd_hmac_sha256(text, textlen, ECDH_keydata, KEY_LEN, output, outputlen);

		int i;
		if( (i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0 ){
			if(i >= MAXKEYRINGS){
				printf("Key rings is full!\n");
			}else{
			strcpy(rc->keybox.keyrings[rc->keybox.nkeys].partner_id, rc->peer_id);
			i = rc->keybox.nkeys;
			rc->keybox.nkeys++;
			}
		}
		memcpy(rc->keybox.keyrings[i].MasterKey, output, sizeof(rc->keybox.keyrings[i].MasterKey));
		SHA256(output+sizeof(rc->keybox.keyrings[i].MasterKey), sizeof(rc->auth_id_next), rc->auth_id_next);
		free(output);
		free(text);

		return TRUE;
}

/* Scene 1 :
 * Key negotiation process
 * (step 7-10 17-20)
 */
// step7: SIP Server - SIP UA(NVR)
// Unicast key negotiation request
int ProcessUnicastKeyNegoRequest(RegisterContext *rc, UnicastKeyNegoRequ *unicast_key_nego_requ_packet)
{
	printf("In ProcessUnicastKeyNegoRequest:\n");

	// fill flag
	unicast_key_nego_requ_packet->flag = 7; // step7

	// fill master key id
	/* MK_ID = HMAC-SHA256(MasterKey, MAC_SIPUA || MAC_SIPServer) */
	unsigned int buflen = sizeof(rc->peer_MACaddr) + sizeof(rc->self_MACaddr);
	unsigned char *tempbuf = malloc(buflen);
	memcpy(tempbuf, rc->peer_MACaddr.macaddr, sizeof(rc->peer_MACaddr.macaddr));
	memcpy(tempbuf+sizeof(rc->peer_MACaddr.macaddr), rc->self_MACaddr.macaddr, sizeof(rc->self_MACaddr.macaddr));
	hmac_sha256(tempbuf, buflen, rc->keybox.keyrings[getKeyRingNum(&rc->keybox, rc->peer_id)].MasterKey,
			KEY_LEN, rc->MK_ID, SHA256_DIGEST_SIZE);
	free(tempbuf);
	memcpy(unicast_key_nego_requ_packet->MK_ID, rc->MK_ID, SHA256_DIGEST_SIZE);

	// fill addid
	memcpy(unicast_key_nego_requ_packet->addid.mac1, rc->peer_MACaddr.macaddr, sizeof(rc->peer_MACaddr.macaddr));
	memcpy(unicast_key_nego_requ_packet->addid.mac2, rc->self_MACaddr.macaddr, sizeof(rc->self_MACaddr.macaddr));

	// fill ae rand number
	gen_randnum(rc->self_randnum_next, sizeof(rc->self_randnum_next));
	memcpy((BYTE *)&unicast_key_nego_requ_packet->aechallenge, rc->self_randnum_next, sizeof(rc->self_randnum_next));

	// fill ae signature
	EVP_PKEY * privKey;
	BYTE sign_value[1024];					//保存签名值的数组
	unsigned int  sign_len;

	privKey = getprivkeyfromprivkeyfile(rc->self_id);
	if(privKey == NULL)	{
		printf("getprivkeyitsself().....failed!\n");
		return FALSE;
	}

	if(!gen_sign((BYTE *)unicast_key_nego_requ_packet,(sizeof(UnicastKeyNegoRequ)-sizeof(unicast_key_nego_requ_packet->aesign)),sign_value, &sign_len,privKey)){
		printf("generate signature failed.\n");
		return FALSE;
	}

	unicast_key_nego_requ_packet->aesign.sign.length = sign_len;
	memcpy(unicast_key_nego_requ_packet->aesign.sign.data,sign_value,sign_len);

	return TRUE;
}

// step8: SIP UA(NVR) - SIP Server
// Unicast key negotiation response
int HandleUnicastKeyNegoRequest(RegisterContext *rc, const UnicastKeyNegoRequ *unicast_key_nego_requ_packet)
{
	printf("In HandleUnicastKeyNegoRequest:\n");

		//verify sign of AE
		//read ae certificate get ae pubkey(公钥)
		EVP_PKEY *aepubKey = NULL;
		BYTE *pTmp = NULL;
		BYTE deraepubkey[1024];
		int aepubkeyLen;
		aepubKey = getpubkeyfromcert(rc->peer_id);
		if(aepubKey == NULL){
			printf("get ae's public key failed.\n");
			return FALSE;
		}
		pTmp = deraepubkey;
		//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
		aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);

		//verify the sign
		if ( verify_sign((BYTE *)unicast_key_nego_requ_packet,
				sizeof(UnicastKeyNegoRequ) - sizeof(sign_attribute),
				(BYTE *)unicast_key_nego_requ_packet->aesign.sign.data,
				unicast_key_nego_requ_packet->aesign.sign.length, aepubKey) )
		{
			EVP_PKEY_free(aepubKey);
		}else{
			printf("ae's sign verify failed.\n");
			return FALSE;
		}

		// verify master key id
		/* MK_ID = HMAC-SHA256(MasterKey, MAC_SIPUA || MAC_SIPServer) */
		unsigned int buflen = sizeof(rc->self_MACaddr) + sizeof(rc->peer_MACaddr);
		unsigned char *tempbuf = malloc(buflen);
		memcpy(tempbuf, rc->self_MACaddr.macaddr, sizeof(rc->self_MACaddr.macaddr));
		memcpy(tempbuf+sizeof(rc->self_MACaddr.macaddr), rc->peer_MACaddr.macaddr, sizeof(rc->peer_MACaddr.macaddr));
		hmac_sha256(tempbuf, buflen, rc->keybox.keyrings[getKeyRingNum(&rc->keybox, rc->peer_id)].MasterKey,
				KEY_LEN, rc->MK_ID, SHA256_DIGEST_SIZE);
		free(tempbuf);
		if(memcmp(unicast_key_nego_requ_packet->MK_ID, rc->MK_ID, SHA256_DIGEST_SIZE)){
			printf("ae's master key id verify failed.\n");
			return FALSE;
		}

		// get ae rand number
		memcpy(rc->peer_randnum_next, unicast_key_nego_requ_packet->aechallenge, sizeof(rc->peer_randnum_next));

		return TRUE;
}

int ProcessUnicastKeyNegoResponse(RegisterContext *rc, UnicastKeyNegoResp *unicast_key_nego_resp_packet)
{
	printf("In ProcessUnicastKeyNegoResponse:\n");

	// fill flag
	unicast_key_nego_resp_packet->flag = 8; // step8

	// fill master key id
	memcpy(unicast_key_nego_resp_packet->MK_ID, rc->MK_ID, SHA256_DIGEST_SIZE);

	// fill addid
	memcpy(unicast_key_nego_resp_packet->addid.mac1, rc->self_MACaddr.macaddr, sizeof(rc->self_MACaddr.macaddr));
	memcpy(unicast_key_nego_resp_packet->addid.mac2, rc->peer_MACaddr.macaddr, sizeof(rc->peer_MACaddr.macaddr));

	// fill asue rand number
	gen_randnum(rc->self_randnum_next, sizeof(rc->self_randnum_next));
	memcpy((BYTE *)&unicast_key_nego_resp_packet->asuechallenge, rc->self_randnum_next, sizeof(rc->self_randnum_next));

	// fill ae rand number
	memcpy(unicast_key_nego_resp_packet->aechallenge, rc->peer_randnum_next, sizeof(rc->peer_randnum_next));

	// compute key block
	/*
	 * KeyBlock = KD-HMAC-SHA256(MasterKey, MAC_SIPUA || MAC_SIPServer ||
	 *     n'_SIPUA || n'_SIPServer || "pairwisekeyexpansionforunicastandadditionalkeysandnonce")
	 */
	char *tempstring = "pairwisekeyexpansionforunicastandadditionalkeysandnonce";
	int outputlen = 3*KEY_LEN + RAND_LEN;
	int textlen = 2*MAC_LEN + 2*RAND_LEN + strlen(tempstring);
	unsigned char *output = malloc(outputlen);
	unsigned char *text = malloc(textlen);
	memcpy(text, rc->self_MACaddr.macaddr, MAC_LEN);
	memcpy(text+MAC_LEN, rc->peer_MACaddr.macaddr, MAC_LEN);
	memcpy(text+2*MAC_LEN, rc->self_randnum_next, RAND_LEN);
	memcpy(text+2*MAC_LEN+RAND_LEN, rc->peer_randnum_next, RAND_LEN);
	memcpy(text+2*MAC_LEN+2*RAND_LEN, tempstring, strlen(tempstring));
	int i;
	if((i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0){
		printf("No such key ring!\n");
		return FALSE;
	}
	kd_hmac_sha256(text, textlen, rc->keybox.keyrings[i].MasterKey,
			KEY_LEN, output, outputlen);

	if( (i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0 ){
		if(i >= MAXKEYRINGS-1){
			printf("Key rings is full!\n");
			return FALSE;
		}else{
			rc->keybox.keyrings[rc->keybox.nkeys].partner_id = malloc(strlen(rc->peer_id));
			strcpy(rc->keybox.keyrings[rc->keybox.nkeys].partner_id, rc->peer_id);
			i = rc->keybox.nkeys;
			rc->keybox.nkeys++;
		}
	}

	memcpy(rc->keybox.keyrings[i].CK, output, KEY_LEN);
	memcpy(rc->keybox.keyrings[i].IK, output+KEY_LEN, KEY_LEN);
	memcpy(rc->keybox.keyrings[i].KEK, output+2*KEY_LEN, KEY_LEN);
	SHA256(output+3*KEY_LEN, RAND_LEN, rc->nonce);
	free(output);
	free(text);

	// fill rtp rtcp info
	/*
	 * for NVR: rtp_send || rtcp_send || rtp_receive || rtcp_receive
	 * for IPC: rtp_send || rtcp_send
	 * for Client: rtp_receive || rtcp_receive
	 */
	// Enc(CK, RTP_send || RTCP_send || RTP_receive || RTCP_receive)
	printf("[wait for sm3] rtp rtcp info is not encrypted !\n");

	// fill digest
	if((i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0){
		printf("No such key ring!\n");
		return FALSE;
	}
	hmac_sha256((BYTE *)unicast_key_nego_resp_packet, sizeof(UnicastKeyNegoResp)-sizeof(unicast_key_nego_resp_packet->digest),
			rc->keybox.keyrings[i].IK, KEY_LEN,
			unicast_key_nego_resp_packet->digest, SHA256_DIGEST_SIZE);

	return TRUE;
}

// step9: SIP Server - SIP UA(NVR)
// Unicast key negotiation confirm
int HandleUnicastKeyNegoResponse(RegisterContext *rc, const UnicastKeyNegoResp *unicast_key_nego_resp_packet)
{
	printf("In HandleUnicastKeyNegoResponse:\n");

	// verify master key id
	/* MK_ID = HMAC-SHA256(MasterKey, MAC_SIPUA || MAC_SIPServer) */
	if(memcmp(unicast_key_nego_resp_packet->MK_ID, rc->MK_ID, SHA256_DIGEST_SIZE)){
		printf("ae's master key id verify failed.\n");
		return FALSE;
	}

	// compute key block
	/*
	 * KeyBlock = KD-HMAC-SHA256(MasterKey, MAC_SIPUA || MAC_SIPServer ||
	 *     n'_SIPUA || n'_SIPServer || "pairwisekeyexpansionforunicastandadditionalkeysandnonce")
	 */
	char *tempstring = "pairwisekeyexpansionforunicastandadditionalkeysandnonce";
	int outputlen = 3*KEY_LEN + RAND_LEN;
	int textlen = 2*MAC_LEN + 2*RAND_LEN + strlen(tempstring);
	unsigned char *output = malloc(outputlen);
	unsigned char *text = malloc(textlen);
	memcpy(text, rc->peer_MACaddr.macaddr, MAC_LEN);
	memcpy(text+MAC_LEN, rc->self_MACaddr.macaddr, MAC_LEN);
	memcpy(text+2*MAC_LEN, rc->peer_randnum_next, RAND_LEN);
	memcpy(text+2*MAC_LEN+RAND_LEN, rc->self_randnum_next, RAND_LEN);
	memcpy(text+2*MAC_LEN+2*RAND_LEN, tempstring, strlen(tempstring));
	int i;
	if((i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0){
		printf("No such key ring!\n");
		return FALSE;
	}
	kd_hmac_sha256(text, textlen, rc->keybox.keyrings[i].MasterKey,
			KEY_LEN, output, outputlen);

	if( (i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0 ){
		if(i >= MAXKEYRINGS-1){
			printf("Key rings is full!\n");
			return FALSE;
		}else{
			rc->keybox.keyrings[rc->keybox.nkeys].partner_id = malloc(strlen(rc->peer_id));
			strcpy(rc->keybox.keyrings[rc->keybox.nkeys].partner_id, rc->peer_id);
			i = rc->keybox.nkeys;
			rc->keybox.nkeys++;
		}
	}

	memcpy(rc->keybox.keyrings[i].CK, output, KEY_LEN);
	memcpy(rc->keybox.keyrings[i].IK, output+KEY_LEN, KEY_LEN);
	memcpy(rc->keybox.keyrings[i].KEK, output+2*KEY_LEN, KEY_LEN);
	SHA256(output+3*KEY_LEN, RAND_LEN, rc->nonce);
	free(output);
	free(text);

	// verify digest
	if((i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0){
		printf("No such key ring!\n");
		return FALSE;
	}
	unsigned char digest[SHA256_DIGEST_SIZE];
	hmac_sha256((BYTE *)unicast_key_nego_resp_packet, sizeof(UnicastKeyNegoResp)-sizeof(unicast_key_nego_resp_packet->digest),
			rc->keybox.keyrings[i].IK, KEY_LEN,
			digest, SHA256_DIGEST_SIZE);
	if(!memcmp(unicast_key_nego_resp_packet->digest, digest, SHA256_DIGEST_SIZE)){
		printf("digest verified failed!\n");
		return FALSE;
	}

	// get rtp rtcp info
	/*
	 * for NVR: rtp_send || rtcp_send || rtp_receive || rtcp_receive
	 * for IPC: rtp_send || rtcp_send
	 * for Client: rtp_receive || rtcp_receive
	 */
	// Dec(CK, RTP_send || RTCP_send || RTP_receive || RTCP_receive)
	printf("[wait for sm3] rtp rtcp info is not decrypted !\n");

	// fill asue rand number
	memcpy(rc->peer_randnum_next, (BYTE *)&unicast_key_nego_resp_packet->asuechallenge, sizeof(rc->self_randnum_next));

	return TRUE;
}

int ProcessUnicastKeyNegoConfirm(RegisterContext *rc, UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet)
{
	printf("In ProcessUnicastKeyNegoConfirm:\n");

	// fill flag
	unicast_key_nego_confirm_packet->flag = 9; // step9

	// fill master key id
	memcpy(unicast_key_nego_confirm_packet->MK_ID, rc->MK_ID, SHA256_DIGEST_SIZE);

	// fill addid
	memcpy(unicast_key_nego_confirm_packet->addid.mac1, rc->self_MACaddr.macaddr, sizeof(rc->self_MACaddr.macaddr));
	memcpy(unicast_key_nego_confirm_packet->addid.mac2, rc->peer_MACaddr.macaddr, sizeof(rc->peer_MACaddr.macaddr));

	// fill asue rand number
	memcpy((BYTE *)&unicast_key_nego_confirm_packet->asuechallenge, rc->peer_randnum_next, sizeof(rc->peer_randnum_next));

	// fill rtp rtcp info
	/*
	 * for NVR: rtp_send || rtcp_send || rtp_receive || rtcp_receive
	 * for IPC: rtp_send || rtcp_send
	 * for Client: rtp_receive || rtcp_receive
	 */
	// Enc(CK, RTP_send || RTCP_send || RTP_receive || RTCP_receive)
	printf("[wait for sm3] rtp rtcp info is not encrypted !\n");

	// fill key negotiation result
	unicast_key_nego_confirm_packet->key_nego_result = rc->key_nego_result;

	// fill digest
	int i;
	if((i=getKeyRingNum(&rc->keybox, rc->peer_id)) < 0){
		printf("No such key ring!\n");
		return FALSE;
	}
	hmac_sha256((BYTE *)unicast_key_nego_confirm_packet, sizeof(UnicastKeyNegoConfirm)-sizeof(unicast_key_nego_confirm_packet->digest),
			rc->keybox.keyrings[i].IK, KEY_LEN,
			unicast_key_nego_confirm_packet->digest, SHA256_DIGEST_SIZE);

	return TRUE;
}

// step9+: SIP UA(NVR) - SIP Server
int HandleUnicastKeyNegoConfirm(RegisterContext *rc, const UnicastKeyNegoConfirm *unicast_key_nego_confirm_packet)
{
	printf("In ProcessUnicastKeyNegoConfirm:\n");
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
//begin interface between IPC and NVR
/*uac Transport between IPC and NVR interface begin*/

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




