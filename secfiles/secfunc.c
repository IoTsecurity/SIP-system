/*
* 此文件仅用于同方USB加密模块设备访问程序，供客户使用，不建议客户修改
*
* 作者：宇浩然
* 时间：2012.05.16
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "secfunc.h"

/*******************************************************************************
sm1系列函数，每个函数都可以实现SM1加解密功能
参数：
	dev：设备
	size：操作数据的长度，应该为16的整数倍
	func：功能选择，ENCRYPT(加密)或DECRYPT(解密)
	void * dest：存放操作后数据的缓冲区地址
	void * source：源数据的缓冲区地址
	unsigned char dest：目标数据在下位机中的存放位置
	unsigned char source：源数据在下位机中的存放位置
*******************************************************************************/
/*******************************************************************************
功能：SM1功能与通道号切换
注意：
作者：宇浩然
时间：2012.05.18
参数：请参考本系列函数的头部
返回值： SM1的功能通道号，0xff为无效
*******************************************************************************/
static unsigned char sm1_channel(int func)
{
	return ENCRYPT==func ? SM1_ENCRYPT : (DECRYPT==func ? SM1_DECRYPT : 0xff);
}
/*******************************************************************************
功能：下发数据，读取操作后的数据，没有最大长度限制；下位机不保存信息(下发上传)
注意：
作者：宇浩然
时间：2012.05.17
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际读取数据的字符数
*******************************************************************************/
int sm1(const tf09_device* dev, void* dest, const void* source, int size,int func)
{
//	if (0 != (size & 511) || 1024 > size)
	//	return -1;
	return sms2(dev, dest, source, size, sm1_channel(func));
}

/*******************************************************************************
功能：下发SM1加密和解密通道的密钥
注意：每种密钥的长度均为16字节；密钥缓冲区地址为NULL时，不设置该密钥
作者：宇浩然
时间：2012.06.08
参数：dev：设备；skbuffer：sk密钥缓冲区地址；akbuffer：ak密钥缓冲区地址；ekbuffer：ek密钥缓冲区地址
*		func：指定功能ENCRYPT或DECRYPT功能；keepsave：是否保存密钥KEEPSAVE或EASYLOSE
返回值： <0：失败，其他：实际下发的字节数
*******************************************************************************/
#define SM1_KEY_LENGTH	16
int sm1_key(const tf09_device* dev, const void* skbuffer, const void* ekbuffer, const void* akbuffer, int keepsave)
{
	unsigned char buffer[SM1_KEY_LENGTH], key_para=0;
//	keys_data *pkeys;
 void* pkeys;
	int ret;
	for (ret=0; ret<SM1_KEY_LENGTH; ret++)
		buffer[ret] = 0;
	if (EASYLOSE == keepsave)
		key_para = EASYLOSE;
	if (NULL == skbuffer){	//对SK进行初步处理
		key_para |= SM1_EXTN;
		skbuffer = buffer;
	}else{
		key_para |= SM1_SK;
	}
	if (NULL == akbuffer)	//对AK进行初步处理
		akbuffer = buffer;
	else
		key_para |= SM1_AK;
	if (NULL == ekbuffer)	//对AK进行初步处理
		ekbuffer = buffer;
	else
		key_para |= SM1_EK;

	//将各个密钥连接成必要的数据结构，以用于设置通道信息时的数据下发
	pkeys = tf09_make_keydata(3, SM1_AK, SM1_KEY_LENGTH, akbuffer, SM1_EK, SM1_KEY_LENGTH, ekbuffer, SM1_SK, SM1_KEY_LENGTH, skbuffer);
	if (NULL == pkeys)
		return -1;

	ret = set_keys(dev, SM1_ENCRYPT, key_para, pkeys);	//SM1加密、解密通道的密钥会同时变化，这是下位机的内部实现

	return ret;
}

/*******************************************************************************
功能：SM2功能与通道号切换
注意：
作者：宇浩然
时间：2012.05.18
参数：请参考本系列函数的头部
返回值： SM1的功能通道号，0xff为无效
*******************************************************************************/
static unsigned char sm2_channel(int func)
{
	switch (func)
	{
		case ENCRYPT:
			return SM2_ENCRYPT;	//SM2加密通道
			break;
		case DECRYPT:
			return SM2_DECRYPT;	//SM2解密通道
			break;
		case SIGN:
			return SM2_SIGN;		//SM2签名通道
			break;
		case SIGNVERIFY:
			return SM2_SIGNVERIFY;	//SM2验证签名通道
			break;
	}
	return 0xff;
}
/*******************************************************************************
功能：下发数据，读取操作后的数据，有最大长度限制；下位机不保存信息(下发上传)
注意：
作者：宇浩然
时间：2012.05.18
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际读取数据的字符数
*******************************************************************************/
int sm2(const tf09_device* dev, void* dest, const void* source, int size, int func)
{
	unsigned char channel = sm2_channel(func);
	if (channel > TF09_MAX_CHANNEL)
		return -1;
	int	data_length;

	if (size > TF09_MAX_RAM_SIZE)
		return -1;

	switch (channel)
	{
		case SM2_ENCRYPT:	//SM2加密
			data_length = size + SM2_KEY_LENGTH*3 + 1;
			if (data_length > TF09_MAX_RAM_SIZE)
				return -1;
			break;
		case SM2_DECRYPT:	//SM2解密
			data_length = size - 1 - SM2_KEY_LENGTH*3;

			break;
		case SM2_SIGN:	//SM2签名
			data_length = 2*SM2_KEY_LENGTH;
			break;
		case SM2_SIGNVERIFY:	//SM2验证签名
			data_length = 1;
			break;
	}

	return sms1(dev, dest, source, size, data_length, channel);
}

/*******************************************************************************
功能：从下位机获取密钥对，密钥对的长度为
注意：
作者：宇浩然
时间：2012.05.28
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际上传数据的字符数，无数据上传时为0
*******************************************************************************/
int get_sm2_seckey(const tf09_device* dev, void* dest)
{
	return sms4(dev, dest, 1, 1, 3*SM2_KEY_LENGTH, SM2_KEYPAIR);
}
/*******************************************************************************
功能：下发SM2加密、解密、签名和验证签名通道的密钥
注意：私钥长度为256bits，公钥长度为64字节；
作者：宇浩然
时间：2012.06.08
参数：	dev：设备；skbuffer：私钥密钥缓冲区地址；pkbuffer：公钥密钥缓冲区地址；
* 		keepsave：是否保存密钥KEEPSAVE或EASYLOSE
返回值： <0：失败，其他：实际下发的字节数
*******************************************************************************/
int sm2_key(const tf09_device* dev, const void* skbuffer, const void* pkbuffer, int keepsave)
{
	unsigned char key_para=0, channel;
    keys_data_sm2 *pkeys;
	int ret=0;

	if (NULL == skbuffer && NULL == pkbuffer)
		return -1;

	if (EASYLOSE == keepsave)
		key_para = EASYLOSE;

	key_para |= SM2_256;	//目前仅支持256位

	if ((NULL != skbuffer)&&(NULL == pkbuffer)){
		key_para |= SM2_SK;
		channel = SM2_DECRYPT;	//解密和签名使用私钥
	}
	if ((NULL != pkbuffer)&&(NULL == skbuffer)){
		key_para |= SM2_PK;
		channel = SM2_ENCRYPT;	//加密和签名验证使用公钥
	}
	if((NULL != pkbuffer)&&(NULL != skbuffer)){
			key_para |= SM2_PK;
		channel = SM2_ENCRYPT;	//加密和签名验证使用公钥
	}

	pkeys = tf09_make_sm2keydata(2, SM2_SK, SM2_KEY_LENGTH, skbuffer, SM2_PK, SM2_KEY_LENGTH<<1, pkbuffer);	//公钥长度加倍
	if (NULL == pkeys)
		return -1;
	ret = set_keys(dev, channel, key_para, pkeys);
	free(pkeys);
	return ret;
}

/*******************************************************************************
功能：下发数据，读取操作后的数据，没有最大长度限制；下位机不保存信息(下发上传)
注意：由于SM3杂凑算法的输入输出数据长度不等，无法直接调用sms函数
作者：宇浩然
时间：2012.05.17
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际读取数据的字符数
*******************************************************************************/
int sm3(const tf09_device* dev, void* dest, const void* source, int size)
{
	return sms1(dev, dest, source, size, SM3_LENGTH, SM3_DIGEST);//调用sms1
}

/*******************************************************************************
sm4系列函数，每个函数都可以实现SM4加解密功能
参数：
	dev：设备
	size：操作数据的长度，应该为16的整数倍
	func：功能选择，ENCRYPT(加密)或DECRYPT(解密)
	void * dest：存放操作后数据的缓冲区地址
	void * source：源数据的缓冲区地址
	unsigned char dest：目标数据在下位机中的存放位置
	unsigned char source：源数据在下位机中的存放位置
*******************************************************************************/
/*******************************************************************************
功能：SM4功能与通道号切换
注意：
作者：宇浩然
时间：2012.05.18
参数：请参考本系列函数的头部
返回值： SM4的功能通道号，0xff为无效
*******************************************************************************/
static unsigned char sm4_channel(int func)
{
	return ENCRYPT==func ? SM4_ENCRYPT : (DECRYPT==func ? SM4_DECRYPT : 0xff);
}
/*******************************************************************************
功能：下发数据，读取操作后的数据，没有最大长度限制；下位机不保存信息(下发上传)
注意：
作者：宇浩然
时间：2012.05.17
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际读取数据的字符数
*******************************************************************************/
int sm4(const tf09_device* dev, void* dest, const void* source, int size,int func)
{
//	if (0 != (size & 511) || 1024 > size)
//		return -1;
	return sms2(dev, dest, source, size, sm4_channel(func));
}

/*******************************************************************************
功能：下发SM4加密和解密通道的密钥
注意：密钥的长度为16字节
作者：宇浩然
时间：2012.06.08
参数：dev：设备；buffer：密钥缓冲区地址；keepsave：是否保存密钥KEEPSAVE或EASYLOSE
返回值： <0：失败，其他：实际下发的字节数
*******************************************************************************/
#define SM4_KEY_LENGTH	16
int sm4_key(const tf09_device* dev, const void* buffer, int keepsave)
{
	unsigned char key_para=0;
	void *pkeys;
	int ret;
	if (NULL == buffer)
		return -1;
	if (EASYLOSE == keepsave)
		key_para = EASYLOSE;
	key_para |= SM4_KEY;
	pkeys = tf09_make_sm4keydata(1, SM4_KEY, SM4_KEY_LENGTH, buffer);
	if (NULL == pkeys)
		return -1;
	ret = set_keys(dev, SM4_ENCRYPT, key_para, pkeys);
	free(pkeys);
	return ret;
}

/*******************************************************************************
功能：下位机指定数据为源数据，无操作，直接数据上传
注意：数据最大长度与指定的位置有关，超过最大长度则自动使用最大长度
作者：宇浩然
时间：2012.05.17
参数：dev：设备；dest：存放数据的缓冲区地址；source：数据在下位机中的存放位置
		size：传输数据的长度
返回值： <0：失败，其他：实际上传数据的字符数
*******************************************************************************/
int tf09_read(const tf09_device* dev, void* dest, unsigned char source, int size)
{
	if(NULL == dest || source < MIN_POS || source > MAX_POS || size <= 0)
		return -1;

	int ret = 512*(MAX_POS-source+1);
	if (size > ret)
		size = ret;

	tf09_comm_para* commPara = tf09_get_comm_para(dev);
	tf09_comm_para_init(commPara);

	commPara->dataLow = (unsigned char)size;
	commPara->dataHigh = (unsigned char)(size >> 8);
	commPara->dataAddr = source;
	commPara->dataLength = (unsigned char)(size >> 9);
	if (0 != (size & 511))
		commPara->dataLength++;

	return tf09_read_channel_data(dev, dest);
}

/*******************************************************************************
功能：读取随机数
注意：指定存储位置时有最大长度限制，否则无限制
作者：宇浩然
时间：2012.05.18
参数：dev：设备；dest：存放数据的缓冲区地址，为NULL时不上传；
		dest_pos：数据在下位机中的存放位置，若为0xff则无效；size：传输数据的长度
返回值： <0：失败，其他：实际上传数据的字符数
*******************************************************************************/
int get_random(const tf09_device* dev, void* dest, unsigned char dest_pos, int size)
{
	if (NULL == dest && (dest_pos < MIN_POS || dest_pos > MAX_POS) || size <= 0)
		return -1;

	int ret, totalsize=0, cursize;

	if (dest_pos < MIN_POS || dest_pos > MAX_POS)
		dest_pos = MIN_POS;	//指定的位置无效，通常需上传数据，此时无数据长度限制
	else{
		ret = 512*(MAX_POS-dest_pos+1);
		if (size > ret)
			size = ret;	//指定的位置有效时，有最大长度限制
	}

	tf09_comm_para* commPara = tf09_get_comm_para(dev);
	tf09_comm_para_init(commPara);

	commPara->destAddr = dest_pos;
	commPara->dataTag = (NULL==dest ? NODATA : UPDATA);	//dest为空时，不上传数据

	while (totalsize < size)
	{
		cursize = size-totalsize;
		if (cursize > TF09_MAX_RAM_SIZE)
			cursize = TF09_MAX_RAM_SIZE;
		commPara->destLength = (unsigned char)(cursize >> 9);
		if (0 != (cursize & 511))
			commPara->destLength++;
		commPara->dataHigh = (unsigned char)(cursize >> 8);
		commPara->dataLow = (unsigned char)cursize ;

		ret = tf09_read_random(dev, dest);
		TF09_CHECK(ret, totalsize);
		totalsize += ret;
		dest = (char*)dest + ret;
	}
	return totalsize;
}
//int random(const tf09_device* dev, void* dest, int size)
//{
//	return random(dev, dest, 0xFF, size);
//}

/*******************************************************************************
sms系列函数，针对不同的通道实现一些基本功能
参数：
	dev：设备
	doSize：源数据的长度，通常为16的整数倍，有时有限制
	size：操作后数据的长度，大多数情况下与doSize相同，但对于有的算法两者是不一样的
	channel：通道号
	void * dest：存放操作后数据的缓冲区地址
	void * source：源数据的缓冲区地址
	unsigned char dest：目标数据在下位机中的存放位置(1-13)
	unsigned char source：源数据在下位机中的存放位置(1-13)
*******************************************************************************/
/*******************************************************************************
功能：下发数据，读取操作后的数据，下发数据有最大长度限制；下位机不保存信息(下发上传)
注意：下发数据与返回数据长度不一定相等，不循环处理，仅工作一次
作者：宇浩然
时间：2012.05.18
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际读取数据的字符数
*******************************************************************************/
//sms1

int sms1(const tf09_device* dev, void* dest, const void* source, int doSize, int size, unsigned char channel)
{
	if (NULL == source || NULL == dest || doSize<0 || doSize > TF09_MAX_RAM_SIZE \
						|| size <= 0 || channel > TF09_MAX_CHANNEL)
		return -1;
	int ret;

	if (doSize <= 0)	//下发数据长度为0或负值，则无数据下发；相当于从下位机对0个数据进行操作
		return sms4(dev, dest, MIN_POS, 0, size, channel);//sms4

	ret = sms3(dev, MIN_POS, source, doSize, channel);//sms3	//下发数据并保存在下位机的位置
	if (ret < 0)
		return ret;

	return tf09_read(dev, dest, MIN_POS, size);	//从下位机最初的位置读取数据
}
/*******************************************************************************
功能：下发数据，读取操作后的数据，没有最大长度限制；下位机不保存信息(下发上传)
注意：仅适合于源数据与目的数据长度相等的算法功能
作者：宇浩然
时间：2012.05.18
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际读取数据的字符数
*******************************************************************************/
//sm1直接调用
//sms2

int sms2(const tf09_device* dev, void* dest, const void* source, int size, unsigned char channel)
{
	if (NULL == source || NULL == dest || size <= 0 || channel > TF09_MAX_CHANNEL)
		return -1;
	int ret, totalsize = 0;

	while (totalsize < size)
	{
		ret = sms1(dev, dest, source, size-totalsize, size-totalsize, channel);//sms1
		TF09_CHECK(ret, totalsize);

		totalsize += ret;
		dest = (char *) dest + ret;
		source = (char *) source + ret;
	}

	return totalsize;
}
/*******************************************************************************
功能：下发数据，操作后的数据存放在下位机指定的位置(下发不上传)
注意：数据最大长度与指定的位置有关，超过最大长度则自动使用最大长度
作者：宇浩然
时间：2012.05.17
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际下发数据的字符数
*******************************************************************************/
//sms3

int sms3(const tf09_device* dev, unsigned char dest, const void* source, int size, unsigned char channel)
{
	if (NULL == source || dest < MIN_POS || dest > MAX_POS || channel > TF09_MAX_CHANNEL)
		return -1;

	int ret = 512*(MAX_POS-dest+1);
	if (size > ret)
		size = ret;

	if (size <= 0)	//下发数据长度为0或负值，则无数据下发；相当于从下位机对0个数据进行操作
		return sms4(dev, NULL, dest, 0, 0, channel);//sms4

	tf09_comm_para* commPara = tf09_get_comm_para(dev);
	tf09_comm_para_init(commPara);

	commPara->channelTag = channel;	//设定通道
	commPara->dataLow = (unsigned char)size;	//数据长度设定
	commPara->dataHigh = (unsigned char)(size >> 8);
	commPara->destAddr = dest;
	commPara->destLength = (unsigned char)(size >> 9);
	if (0 != (size & 511))
		commPara->destLength++;
	commPara->dataTag = DOWNDATA;
	commPara->doDataHigh = commPara->dataHigh;
	commPara->doDataLow = commPara->dataLow;


 if(commPara->channelTag== 0x00) //SM1加密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x00;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x02;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x01;
	((unsigned char *)commPara)[7] = (unsigned char)(size >> 8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size >> 8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}

	 if(commPara->channelTag== 0x01) //SM1解密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x01;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x02;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x01;
	((unsigned char *)commPara)[7] = (unsigned char)(size >> 8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size >> 8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}


 if(commPara->channelTag== 0x02) //SM2加密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x02;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size >> 8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size >> 8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}

        if(commPara->channelTag== 0x03)//SM2解密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x03;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}


        if(commPara->channelTag== 0x08) //SM4加密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x08;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size >> 8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

        if(commPara->channelTag== 0x09)//SM4解密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x09;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

        if(commPara->channelTag== 0x0a)//RSA加密
	{

    ((unsigned char *)commPara)[0] = (unsigned char)0x0a;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}

        if(commPara->channelTag== 0x0b)//RSA解密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x0b;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}

	        if(commPara->channelTag== 0x0c)//RSA签名
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x0c;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}

	        if(commPara->channelTag== 0x0d)//RSA验签
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x0d;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);//high
	((unsigned char *)commPara)[8] = (unsigned char)size;//low
	((unsigned char *)commPara)[9] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[10] = (unsigned char)size;
	}

        if(commPara->channelTag== 0x17) //DES-ECB加密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x17;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}


        if(commPara->channelTag== 0x12)//3DES加密
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x12;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

        if(commPara->channelTag== 0x13) //3DES jiemi
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x13;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

        if(commPara->channelTag== 0x14) //3DES-CBC
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x14;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}
        if(commPara->channelTag== 0x15)//3DES-CBC
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x15;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}


        if(commPara->channelTag== 0x18) //DES-CBC jiami
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x18;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

        if(commPara->channelTag== 0x19)//DES-CBC jiemi
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x19;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x02;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}


	return tf09_use_channel(dev, (void*)source);
}
/*******************************************************************************
功能：下位机指定数据为源数据，操作后的数据依然存放在该位置，dest不为空时，数据上传
注意：数据最大长度与指定的位置有关，超过最大长度则自动使用最大长度
作者：宇浩然
时间：2012.05.17
参数：请参考本系列函数的头部
返回值： <0：失败，其他：实际上传数据的字符数，无数据上传时为0
*******************************************************************************/
//sms4
int sms4(const tf09_device* dev, void* dest, unsigned char source, int doSize, int size, unsigned char channel)
{
	if (source < MIN_POS || source > MAX_POS || doSize < 0 || channel > TF09_MAX_CHANNEL)
		return -1;
	if (NULL != dest && size <= 0)
		return -1;

	int ret = 512*(MAX_POS-source+1);
	if (doSize > ret)
		doSize = ret;
	if (size > ret)
		size = ret;
    CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = tf09_get_comm_para(dev);
	tf09_comm_para_init(commPara);

	commPara->channelTag = channel;	//设定通道
	if (NULL != dest){
		commPara->dataLow = (unsigned char)size;	//数据长度设定
		commPara->dataHigh = (unsigned char)(size >> 8);
		commPara->dataTag = UPDATA;	//数据上传
	}else{
		commPara->dataTag = NODATA;
	}
	commPara->destAddr = source;
	commPara->destLength = (unsigned char)(doSize >> 9);
	if (0 != (doSize & 511))
		commPara->destLength++;
	commPara->doDataHigh = (unsigned char)(doSize >> 8);
	commPara->doDataLow = (unsigned char)doSize;

	if(commPara->channelTag ==2)
	{
    cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)doSize;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh =(unsigned char)(doSize>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

    cbw->bmCBWFlag = TOUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
    cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	//cbw->secCommand[3] = (unsigned char)0x03;	//

	((unsigned char *)commPara)[0] = (unsigned char)0x02;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(doSize>>8);
	((unsigned char *)commPara)[8] = (unsigned char)doSize;
    ((unsigned char *)commPara)[9] = (unsigned char)(doSize>>8);
	((unsigned char *)commPara)[10] = (unsigned char)doSize;
	}

		if(commPara->channelTag ==3)
	{
    cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)doSize;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh =(unsigned char)(doSize>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

  //  cbw->bmCBWFlag = FROMUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
    cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	//cbw->secCommand[3] = (unsigned char)0x03;	//

	((unsigned char *)commPara)[0] = (unsigned char)0x03;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(doSize>>8);
	((unsigned char *)commPara)[8] = (unsigned char)doSize;
    ((unsigned char *)commPara)[9] = (unsigned char)(doSize>>8);
	((unsigned char *)commPara)[10] = (unsigned char)doSize;
	}

		if(commPara->channelTag ==4)
	{
    cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)doSize;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh =(unsigned char)(doSize>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

    cbw->bmCBWFlag = TOUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
    cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	//cbw->secCommand[3] = (unsigned char)0x03;	//

   commPara->channelTag=4;
	((unsigned char *)commPara)[0] = (unsigned char)0x04;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x02;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(doSize>>8);
	((unsigned char *)commPara)[8] = (unsigned char)doSize;
    ((unsigned char *)commPara)[9] = (unsigned char)0x16;//doSize>>8);
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}

		if(commPara->channelTag ==5)
	{
    cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)doSize;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh =(unsigned char)(doSize>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

  //  cbw->bmCBWFlag = FROMUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
    cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	//cbw->secCommand[3] = (unsigned char)0x03;	//

	((unsigned char *)commPara)[0] = (unsigned char)0x05;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x01;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(doSize>>8);
	((unsigned char *)commPara)[8] = (unsigned char)doSize;
    ((unsigned char *)commPara)[9] = (unsigned char)(doSize>>8);//(doSize>>8);
	((unsigned char *)commPara)[10] = (unsigned char)doSize;//doSize;
	}

	return tf09_use_channel(dev, (void*)dest);
}

/*******************************************************************************
功能：设置密钥的通用函数，本函数调用设置通道信息指令，被其他需要设置密钥的算法函数调用
注意：
作者：宇浩然
时间：2012.06.11
参数：
返回值： >0 成功；-1则失败
*******************************************************************************/
static int set_keys(const tf09_device* dev, unsigned char channel_num, unsigned char key_para, const void* pkeys)
{
	switch (channel_num)	//并不是每个通道都需要设置密钥的，非法通道将返回错误
	{
		case SM1_ENCRYPT:
		case SM1_DECRYPT:
		case SM2_ENCRYPT:
		case SM2_DECRYPT:
		case SM2_SIGN:
		case SM2_SIGNVERIFY:
		case SM4_ENCRYPT:
		case SM4_DECRYPT:
		case RSA_ENCRYPT:
		case RSA_DECRYPT:
		case RSA_SIGN:
		case RSA_SIGNVERIFY:
		case DES3_ECB_ENCRYPT:
		case DES3_ECB_DECRYPT:
		case DES3_CBC_ENCRYPT:
		case DES3_CBC_DECRYPT:
		case DES_ECB_ENCRYPT:
		case DES_ECB_DECRYPT:
		case DES_CBC_ENCRYPT:
		case DES_CBC_DECRYPT:
			break;
		default:
			return -1;
	}
	if (NULL == pkeys)
		return -1;
    CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = tf09_get_comm_para(dev);	//初始化设置通道基本参数
	tf09_comm_para_init(commPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';

	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)0x00;//
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)0x02;//
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = TOUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
	cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//
	cbw->secCommand[1] = (unsigned char)0x01;	//写入指令标识
	cbw->secCommand[2] = (unsigned char)0x05;	//
	cbw->secCommand[3] = (unsigned char)0x01;	//

	((unsigned char *)commPara)[0] = (unsigned char)channel_num;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x00;
	((unsigned char *)commPara)[3] = (unsigned char)0x00;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;

	if(channel_num==0) //SM1 set key
	{
	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)0x3b;//sm1 ek ak sk 总长度48
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)0x00;//
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

    ((unsigned char *)commPara)[0] = (unsigned char)channel_num;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x00;
	((unsigned char *)commPara)[3] = (unsigned char)0x00;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x01;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;//high SM1 ek ak sk 的总长度为48
	((unsigned char *)commPara)[8] = (unsigned char)0x3b;//low
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

		if(channel_num==2) //SM2 set key pk
	{
	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)0x60;//sm2 pk 长度64
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)0x00;//
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

    ((unsigned char *)commPara)[0] = (unsigned char)channel_num;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x00;
	((unsigned char *)commPara)[3] = (unsigned char)0x00;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;//high SM2 pk 的长度为64
	((unsigned char *)commPara)[8] = (unsigned char)0x60;//low
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

			if(channel_num==3) //SM2 set key sk
	{
	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)0x60;//sm2 sk 长度64
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)0x00;//
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

    ((unsigned char *)commPara)[0] = (unsigned char)channel_num;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x00;
	((unsigned char *)commPara)[3] = (unsigned char)0x00;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;//high SM2 sk 的长度为32
	((unsigned char *)commPara)[8] = (unsigned char)0x60;//low
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}



	if(channel_num==8) //SM4 set key
	{
	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)0x10;//sm4 key 总长度16
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)0x00;//
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

    ((unsigned char *)commPara)[0] = (unsigned char)channel_num;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x00;
	((unsigned char *)commPara)[3] = (unsigned char)0x00;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;//high SM1 ek ak sk 的总长度为48
	((unsigned char *)commPara)[8] = (unsigned char)0x10;//low
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;
	}

	return tf09_set_channel_info(dev, pkeys);
}
