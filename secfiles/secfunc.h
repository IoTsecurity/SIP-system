/*
* 此头文件仅用于同方的USB加密模块设备访问程序，供内部使用；用户不应该直接引用此头文件
*
* 作者：宇浩然
* 时间：2012.05.16
*
*/

#include "secmodule.h"

#ifndef	_SECFUNC_H_
#define	_SECFUNC_H_

//加密算法的密钥长度
#define SM2_KEY_LENGTH	(256/8)


//不同加密算法的不同功能转换到对应的通道号
static unsigned char sm1_channel(int func);
static unsigned char sm2_channel(int func);
static unsigned char sm4_channel(int func);


//通用密钥设置函数
static int set_keys(const tf09_device* dev, unsigned char channel_num, unsigned char key_para, const void* pkeys);

//读取下位机中指定位置的数据
int tf09_read(const tf09_device* dev, void* dest, unsigned char source, int size);
//读取随机数
int get_random(const tf09_device* dev, void* dest, unsigned char dest_pos, int size);
//int random(const tf09_device* dev, void* dest, int size);

/*******************************************************************************
* 具体的功能函数中，每种算法的每个功能都提供了三个函数，以完成不同情形下的操作，分别是：
* 情形a. 下发数据，然后读取处理后的结果数据，此功能通常由两个USB通信指令完成，使用通道和读取数据；
* 	当需要处理的数据长度超过下位机一次能处理的最大值时，根据不同的算法有不同的处理方式，一种程序会
* 	自动分批处理，一种程序仅处理最大长度的数据，还有一种是直接返回错误信息。
* 情形b. 下发数据，处理后的结果数据存放在下位机指定的位置。通常是使用通道指令；当数据长度超过最
* 	大长度时，仅处理最大长度的数据，其他数据忽略；最大长度与指定的位置有关。
* 情形c. 处理下位机中指定位置的数据，处理后的数据存放在原处，可以上传；数据长度与情形2一样。
*
*******************************************************************************/
//SM1系列函数(加密、解密)
int sm1(const tf09_device* dev, void* dest, const void* source, int size,int func);

int sm1_key(const tf09_device* dev, const void* skbuffer, const void* ekbuffer, const void* akbuffer, int keepsave);

//SM2系列函数(加密、解密、签名、签名验证)
int sm2(const tf09_device* dev, void* dest, const void* source, int size,int func);

int sm2_key(const tf09_device* dev, const void* skbuffer, const void* pkbuffer, int keepsave);

//SM2生成密钥对函数
int get_sm2_seckey(const tf09_device* dev, void* dest);

//SM3系列函数(摘要)
int sm3(const tf09_device* dev, void* dest, const void* source, int size);

//SM4系列函数(加密、解密)
int sm4(const tf09_device* dev, void* dest, const void* source, int size,int func);

int sm4_key(const tf09_device* dev, const void* buffer, int keepsave);

//通用的使用通道函数，具体请参考实现文件；用户应该避免直接调用这些函数
int sms1(const tf09_device* dev, void* dest, const void* source, int doSize, int size, unsigned char channel);
int sms2(const tf09_device* dev, void* dest, const void* source, int size, unsigned char channel);
int sms3(const tf09_device* dev, unsigned char dest, const void* source, int size, unsigned char channel);
int sms4(const tf09_device* dev, void* dest, unsigned char source, int doSize, int size, unsigned char channel);

#endif	//_SECFUNC_H_
