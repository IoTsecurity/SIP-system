/*
* 此头文件仅用于同方的USB加密模块设备访问程序，供内部使用；用户不应该直接引用此头文件
*
* 作者：宇浩然
* 时间：2012.04.21
*
*/

#include "tf09usb.h"

#ifndef	_SECMODULE_H_
#define	_SECMODULE_H_

//CBW中的数据方向
#define	TOUSB	0
#define	FROMUSB	0x80

//USB通信过程中的超时限制
#define	TIMEOUT	10000

//可指定的下位机的存储位置
#define	MIN_POS	1
#define	MAX_POS	13
//下位机可使用的最大空间
#define	TF09_MAX_RAM_SIZE	512*(MAX_POS-MIN_POS+1)

//生成密钥结构时，用于存储不同密钥标示的结构，仅在函数tf09_make_keydata使用
typedef struct{
	unsigned char tag;		//密钥标识，依据加密功能不同有不同的标识
	unsigned char high;	//真实密钥的长度高位
	unsigned char low;		//真实密钥的长度低位
	unsigned char key[16];	//存放真实密钥的位置
} key_data;//__attribute__ ((packed));	//存放在keys_data.keys中的密钥结构

//密钥数据的结构，由函数tf09_make_keydata生成，在设置密钥时用到
typedef struct{
	unsigned char high;	//有效长度高位
	unsigned char low;		//有效长度低位
	unsigned char keys[3][19];	//存放密钥结构的位置
} keys_data;//;__attribute__ ((packed));	//用于申请整个密钥数据用到的内存

//SM2
//生成密钥结构时，用于存储不同密钥标示的结构，仅在函数tf09_make_keydata使用
typedef struct{
	unsigned char key[32];	//存放真实密钥的位置
} keysk_data_sm2;

//生成密钥结构时，用于存储不同密钥标示的结构，仅在函数tf09_make_keydata使用
typedef struct{
	unsigned char key[64];	//存放真实密钥的位置
} keypk_data_sm2;

//密钥数据的结构，由函数tf09_make_keydata生成，在设置密钥时用到
typedef struct{
	unsigned char keysk[32];	//存放密钥结构的位置SK
    unsigned char keypk[64];	//存放密钥结构的位置PK
} keys_data_sm2;

//SM4
//生成密钥结构时，用于存储不同密钥标示的结构，仅在函数tf09_make_keydata使用
typedef struct{
	unsigned char key[16];	//存放真实密钥的位置
} key_data_sm4;

//密钥数据的结构，由函数tf09_make_keydata生成，在设置密钥时用到
typedef struct{
	unsigned char keys[16];	//存放密钥结构的位
} keys_data_sm4;

//默认通道名称，仅取其一，不可组合
#define SM1_ENCRYPT		0
#define SM1_DECRYPT		1
#define SM2_ENCRYPT		2
#define SM2_DECRYPT		3
#define SM2_SIGN		4
#define SM2_SIGNVERIFY	5
#define SM2_KEYPAIR		6
#define SM3_DIGEST		7
#define SM4_ENCRYPT		8
#define SM4_DECRYPT		9
#define RSA_ENCRYPT		0x0a
#define RSA_DECRYPT		0x0b
#define RSA_SIGN		0x0c
#define RSA_SIGNVERIFY	0x0d
#define SHA1_DIGEST		0x0e
#define SHA256_DIGEST	0x0f
#define RSA_KEYPAIR		0x10
#define MD5_DIGEST		0x11
#define DES3_ECB_ENCRYPT	0x12
#define DES3_ECB_DECRYPT	0x13
#define DES3_CBC_ENCRYPT	0x14
#define DES3_CBC_DECRYPT	0x15
#define DES_ECB_ENCRYPT		0x16
#define DES_ECB_DECRYPT		0x17
#define DES_CBC_ENCRYPT		0x18
#define DES_CBC_DECRYPT		0x19
#define TF09_MAX_CHANNEL	0x19

//几种摘要算法的结果数值的长度
#define SM3_LENGTH		256>>3
#define	SHA1_LENGTH		160>>3
#define	SHA256_LENGTH	256>>3
#define	MD5_LENGTH		128>>3

//通道模式，是否自动关闭，仅取其一，不可组合
#define AUTOCLOSE	1
#define ALWAYSOPEN	0

//算法标示，仅取其一，不可组合
#define SM1		0
#define SM2		1
#define SM3		2
#define SM4		3
#define DES		4
#define RSA		5
#define SHA1	6
#define MD5		7
#define RESERVE	0x0FF

//二级算法标示，目前仅对DES有效，前两项选其一，后两项选其一
#define SEC_DES		0
#define SEC_3DES	1
#define SEC_EBC		0
#define SEC_CBC		2

//密钥参数，涉及到是否保存密钥、密钥的来源、密钥长度、密钥类型等，有的可组合使用，有的不可
//依不同的算法有不同的设置，详细请参考通信协议
#define KEEPSAVE	0
#define EASYLOSE	0x80
#define OUTERKEY	0
#define INNERKEY	0x40
#define SM1_EK		1
#define SM1_AK		2
#define SM1_SK		4
#define SM1_EXTN	8
#define SM2_192		0
#define SM2_256		1
#define SM2_PK		8
#define SM2_SK		0x10
#define SM4_KEY		1
#define DES_IV		1
#define DES_DAEKIN1R	2
//#define
//#define
#define RSA_192		3
#define RSA_256		4
#define RSA_512		5
#define RSA_1024	6
#define RSA_2048	7

//功能标识，用于标示某项算法的具体功能，仅取其一，不可组合
//ENCRYPT和DECRYPT对SM1、SM2、SM4、DES、RSA有效
#define ENCRYPT		1
#define DECRYPT		0
//SIGN、SIGNVERIFY和KEYPAIR对SM2、RSA有效
#define SIGN		2
#define SIGNVERIFY	3
#define KEYPAIR		4
//DIGEST对SM3、SHA1、MD5、SHA256有效
#define DIGEST		0

//数据标示，仅取其一，不可组合
#define NODATA		0
#define DOWNDATA	1
#define UPDATA		2

//USB私有指令
#define SETCHANNELINFO	0x01
#define GETCHANNELINFO	0x02
#define USECHANNEL		0x03
#define READCHANNELDATA	0x04
#define SETID			0x05
#define GETID			0x06
#define GETVERSION		0x07
#define READRANDOM		0x08
#define OPENCHANNEL		0x09
#define CLOSECHANNEL	0x0A
#define WRITEDATA		0x0B
#define READDATA		0x0C

//完成CBW通信过程的实际实现函数，所有其他需要用到通信的函数都要调用本函数完成
static int tf09_cbw(const tf09_device* dev, void* buffer);

//USB通信协议指令函数
int tf09_set_channel_info(const tf09_device* dev, const void* buffer);
int tf09_get_channel_info(const tf09_device* dev, unsigned char channel_num);
int tf09_use_channel(const tf09_device* dev, void* buffer);
int tf09_read_channel_data(const tf09_device* dev, void* buffer);
int tf09_set_id(const tf09_device* dev,const void* buffer, int size);
int tf09_get_id(const tf09_device* dev, void* buffer);
int tf09_get_version(const tf09_device* dev, void* buffer);
int tf09_read_random(const tf09_device* dev, void* buffer);
int tf09_open_channel(const tf09_device* dev, unsigned char chanNum);
int tf09_close_channel(const tf09_device* dev, unsigned char chanNum);
int tf09_write_data(const tf09_device* dev,const void* buffer,int startaddr,int size);
int tf09_read_data(const tf09_device* dev,void* buffer,int srcaddr,int size);
int tf09_erase_data(const tf09_device* dev,int iregion);

//其他辅助函数
keys_data* tf09_make_keydata(int count, ...);	//生成下发密钥的数据结构
keys_data_sm2* tf09_make_sm2keydata(int count, ...);	//生成下发密钥的数据结构
keys_data_sm4* tf09_make_sm4keydata(int count, ...);	//生成下发密钥的数据结构

#endif	//_SECMODULE_H_
