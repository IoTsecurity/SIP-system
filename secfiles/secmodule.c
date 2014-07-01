/*
 * 此文件仅用于同方USB加密模块设备访问程序，供客户使用，不建议客户修改
 *
 * 作者：宇浩然
 * 时间：2012.04.21
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>


#include "secmodule.h"

/*******************************************************************************
功能：实现设置通道信息指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；buffer：下发密钥的缓冲区地址
返回值： <0：失败，其他：实际发送数据字符数
*******************************************************************************/
int tf09_set_channel_info(const tf09_device* dev, const void* buffer)
{
	CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = &(cbw->secPara);

	if (0 == (commPara->keyPara & INNERKEY) && NULL == buffer)
		return -1;
	cbw->secCommand[3] = SETCHANNELINFO;	//设置通道信息的指令标识
	cbw->bmCBWFlag = TOUSB;			//本指令可能需要下发数据
	if (0 == (commPara->keyPara & INNERKEY) && NULL != buffer){	//判断是否要下发密钥
		cbw->dCBWDataTransferLength[0] = commPara->dataLow;
		cbw->dCBWDataTransferLength[1] = commPara->dataHigh;
	}else{
		CBW_DATA_LENGTH(cbw) = 0;
	}
	return  tf09_cbw(dev, (void*)buffer);
}

/*******************************************************************************
功能：实现读取通道信息指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；channel_num：通道号
返回值： <0：失败，其他：实际接收数据字符数
*******************************************************************************/
int tf09_get_channel_info(const tf09_device* dev, unsigned char channel_num)
{
	if (channel_num > TF09_MAX_CHANNEL)
		return -1;
	CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	cbw->secCommand[3] = GETCHANNELINFO;	//读取通道信息的指令标识
	cbw->bmCBWFlag = FROMUSB;			//本指令可能需要下发数据
	cbw->dCBWDataTransferLength[0] = 11;
	cbw->dCBWDataTransferLength[1] = 0;
	commPara->channelTag = channel_num;
	commPara->dataLow = 11;	//其实用户不必设置数据大小
	commPara->dataHigh = 0;
	return  tf09_cbw(dev, commPara);
}

/*******************************************************************************
功能：实现使用通道指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；buffer：缓冲区指针
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_use_channel(const tf09_device* dev, void* buffer)
{
	CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = &(cbw->secPara);

	if(NULL == buffer && NODATA != commPara->dataTag)
		return -1;
	cbw->secCommand[3] = USECHANNEL;	//使用通道的指令标识
	//if (UPDATA == commPara->dataTag)
	//	cbw->bmCBWFlag = FROMUSB;
	//else
	//	cbw->bmCBWFlag = TOUSB;
	cbw->bmCBWFlag = (UPDATA == commPara->dataTag) ? FROMUSB : TOUSB;
	if (NODATA == commPara->dataTag){
		CBW_DATA_LENGTH(cbw) = 0;
	}else{
		cbw->dCBWDataTransferLength[0] = commPara->dataLow;
		cbw->dCBWDataTransferLength[1] = commPara->dataHigh;
	}
	if(commPara->channelTag == 2)
	{
	    commPara->sourceAddr=0x01;
	    commPara->sourceLength=0x01;
	}
		if(commPara->channelTag == 3)
	{
	    commPara->sourceAddr=0x01;
	    commPara->sourceLength=0x01;
	}
		if(commPara->channelTag == 4)
	{
	    commPara->sourceAddr=0x01;
	    commPara->sourceLength=0x01;
	}
		if(commPara->channelTag == 5)
	{
	    commPara->sourceAddr=0x01;
	    commPara->sourceLength=0x01;
	}
        if(commPara->channelTag == 0x16)
	{
	    commPara->sourceAddr=0x01;
	    commPara->sourceLength=0x01;
	}
        if(commPara->channelTag == 0x12)
	{
	    commPara->sourceAddr=0x01;
	    commPara->sourceLength=0x01;
	}


	return  tf09_cbw(dev, buffer);
}

/*******************************************************************************
功能：实现读取通道数据指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；buffer：缓冲区指针
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_read_channel_data(const tf09_device* dev, void* buffer)
{
	CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = &(cbw->secPara);

	cbw->dCBWDataTransferLength[0] = commPara->dataLow;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh;
	if (NULL == buffer || 0 == CBW_DATA_LENGTH(cbw))
		return -1;
	cbw->secCommand[3] = READCHANNELDATA;	//使用通道的指令标识
	cbw->bmCBWFlag = FROMUSB;
	return  tf09_cbw(dev, buffer);
}

/*******************************************************************************
功能：实现写入设备ID指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；buffer：缓冲区指针，size：字符数
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_set_id(const tf09_device* dev,const void* buffer, int size)
{
    CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
		return -1;
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';

	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)size;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)(size>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = TOUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
    cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	cbw->secCommand[3] = (unsigned char)0x05;	//

	((unsigned char *)commPara)[0] = (unsigned char)0xFF;
	((unsigned char *)commPara)[1] = (unsigned char)0xFF;
	((unsigned char *)commPara)[2] = (unsigned char)0xFF;
	((unsigned char *)commPara)[3] = (unsigned char)0xFF;
	((unsigned char *)commPara)[4] = (unsigned char)0xFF;
	((unsigned char *)commPara)[5] = (unsigned char)0xFF;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[8] = (unsigned char)size;

	return  tf09_cbw(dev, (void*)buffer);
}

/*******************************************************************************
功能：实现读取设备ID指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；buffer：缓冲区指针
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_get_id(const tf09_device* dev, void* buffer)
{
	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
		return -1;
	tf09_comm_para* commPara = &(cbw->secPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';

	cbw->dCBWDataTransferLength[0] = commPara->dataLow = 0x10;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = 0x00;
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = FROMUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
    cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	cbw->secCommand[3] = (unsigned char)0x06;	//

	((unsigned char *)commPara)[0] = (unsigned char)0xff;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x02;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;
	((unsigned char *)commPara)[8] = (unsigned char)0x10;

	return  tf09_cbw(dev, buffer);
}

/*******************************************************************************
功能：实现读取固件版本号指令。
注意：
作者：宇浩然
时间：2012.04.23
参数：dev：设备；buffer：缓冲区指针
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_get_version(const tf09_device* dev, void* buffer)
{
	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
		return -1;
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';

	cbw->dCBWDataTransferLength[0] = 0x04;
	cbw->dCBWDataTransferLength[1] = 0x00;
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = FROMUSB;
	cbw->secCommand[0] = (unsigned char)0x02;	//写入设备指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	cbw->secCommand[3] = (unsigned char)0x07;	//

	((unsigned char *)commPara)[0] = (unsigned char)0xff;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x02;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;
	((unsigned char *)commPara)[8] = (unsigned char)0x04;
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;

	return  tf09_cbw(dev, buffer);

}

/*******************************************************************************
功能：实现获取随机数指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；buffer：缓冲区指针
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_read_random(const tf09_device* dev, void* buffer)
{
	CBW* cbw = tf09_get_cbw(dev);
	tf09_comm_para* commPara = &(cbw->secPara);

	if (NULL == buffer && NODATA != commPara->dataTag)
		return -1;
	cbw->secCommand[3] = READRANDOM;	//获取随机数的指令标识
	cbw->bmCBWFlag = FROMUSB;
	if (NODATA == commPara->dataTag){
		CBW_DATA_LENGTH(cbw) = 0;
	}else{
		cbw->dCBWDataTransferLength[0] = commPara->dataLow;
		cbw->dCBWDataTransferLength[1] = commPara->dataHigh;
	}

cbw->bmCBWFlag = FROMUSB;

	cbw->dCBWDataTransferLength[0] = 0x00;
	cbw->dCBWDataTransferLength[1] = 0x02;
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->secCommand[0] = (unsigned char)0x02;	//写入设备指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x05;	//
	cbw->secCommand[3] = (unsigned char)0x08;	//

	((unsigned char *)commPara)[0] = (unsigned char)0xff;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)0x01;
	((unsigned char *)commPara)[3] = (unsigned char)0x01;
	((unsigned char *)commPara)[4] = (unsigned char)0x01;
	((unsigned char *)commPara)[5] = (unsigned char)0x02;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x02;//size high
	((unsigned char *)commPara)[8] = (unsigned char)0x00;//size low
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
//	((unsigned char *)commPara)[10] = (unsigned char)0x1b;

	return  tf09_cbw(dev, buffer);
}

/*******************************************************************************
功能：实现开启通道指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；chanNum：通道号
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_open_channel(const tf09_device* dev, unsigned char chanNum)
{
	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
		return -1;
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	commPara->channelTag = chanNum;

	cbw->secCommand[3] = OPENCHANNEL;	//开启通道的指令标识
	CBW_DATA_LENGTH(cbw) = 0;
	cbw->bmCBWFlag = TOUSB;
	if(chanNum == 2)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x02;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}
		if(chanNum == 4)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x04;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}

        if(chanNum == 8)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x08;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}

			if(chanNum == 0x16)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x16;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}
		if(chanNum == 0x12)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x12;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}

			if(chanNum == 0x14)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x14;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}

			if(chanNum == 0x18)
	{
    ((unsigned char *)commPara)[0] = (unsigned char)0x18;
	((unsigned char *)commPara)[1] = (unsigned char)0xff;
	((unsigned char *)commPara)[2] = (unsigned char)0xff;
	((unsigned char *)commPara)[3] = (unsigned char)0xff;
	((unsigned char *)commPara)[4] = (unsigned char)0xff;
	((unsigned char *)commPara)[5] = (unsigned char)0xff;
	((unsigned char *)commPara)[6] = (unsigned char)0xff;
	((unsigned char *)commPara)[7] = (unsigned char)0xff;
	((unsigned char *)commPara)[8] = (unsigned char)0xff;
	((unsigned char *)commPara)[9] = (unsigned char)0x16;
	((unsigned char *)commPara)[10] = (unsigned char)0x1b;
	}
	return  tf09_cbw(dev, NULL);
}

/*******************************************************************************
功能：实现关闭通道指令。
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备；chanNum：通道号
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_close_channel(const tf09_device* dev, unsigned char chanNum)
{
	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
		return -1;
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	commPara->channelTag = chanNum;

	cbw->secCommand[3] = CLOSECHANNEL;	//关闭通道的指令标识
	CBW_DATA_LENGTH(cbw) = 0;
	cbw->bmCBWFlag = TOUSB;
	return  tf09_cbw(dev, NULL);
}

/*******************************************************************************
功能：生成下传密码数据结构
注意：调用程序需要释放返回的指针
作者：宇浩然
时间：2012.04.25
参数：count：需要组织的密钥个数，传递参数顺序：tag,size,key指针
返回值： NULL生成失败；密钥数据的完整结构指针，可以参考协议和keys_data、key_data结构
*******************************************************************************/
keys_data*tf09_make_keydata(int count, ...)
{
    int i;
	va_list ap;
	struct {	//本函数的专用结构，在内部临时定义，临时使用
		unsigned char tag;
		int size;
		void* key;
	}keylist[count];
	int keysize = 0;
	keys_data * keydata;
	key_data *key;

	va_start(ap, count);	//开始不定参数的提取
	for(i=0;i<count;i++){
		keylist[i].tag = (unsigned char)va_arg(ap, int);
		keylist[i].size = va_arg(ap, int);
		keylist[i].key = va_arg(ap, void*);
		if(0 == keylist[i].size || NULL == keylist[i].key)
			keylist[i].tag = 0xff;	//为没有密钥数据的参数设置标志
	}
	va_end(ap);	//不定参数提取结束

	for(i=0;i<count;i++)
{
    	if ( 0xff != keylist[i].tag)
			keysize = keysize + keylist[i].size + sizeof(key_data);	//统计密钥部分的大小
}
		if (0 == keysize)
		return NULL;
	keysize += sizeof(keys_data);	//需要分配内存的总容量
	keydata = (keys_data*)malloc(keysize);
	if (NULL == keydata)	//内存分配失败
		return NULL;
	//开始组织密钥数据的结构
	keydata->high = (unsigned char)((keysize & 0xff00)>>8);
	keydata->low = (unsigned char)(keysize & 0xff);
	key = (key_data*)(&keydata->keys);	//开始组织密钥部分的数据
	for(i=0;i<count;i++)
	{
	    if ( 0xff != keylist[i].tag){
			key->high = (unsigned char)((keylist[i].size & 0xff00)>>8);
			key->low = (unsigned char)(keylist[i].size & 0xff);
			key->tag = keylist[i].tag;
			memcpy(&key->key, keylist[i].key, keylist[i].size);	//复制真实的密钥
			key = key + sizeof(key)/4;	//指向下一个密钥存储位置
		}
	}

	return  keydata;
}


/*******************************************************************************
功能：生成下传密码数据结构
注意：调用程序需要释放返回的指针
作者：nbx
时间：2013.06.18
参数：count：需要组织的密钥个数，传递参数顺序：tag,size,key指针
返回值： NULL生成失败；密钥数据的完整结构指针，可以参考协议和keys_data、key_data结构
*******************************************************************************/
keys_data_sm2*tf09_make_sm2keydata(int count, ...)
{
    int i;
	va_list ap;
	struct {	//本函数的专用结构，在内部临时定义，临时使用
		unsigned char tag;
		int size;
		void* key;
	}keylist[count];
	int keysize = 0;
	keys_data_sm2 * keydata;
	keysk_data_sm2 *keysk;
    keypk_data_sm2 *keypk;

	va_start(ap, count);	//开始不定参数的提取
	for(i=0;i<count;i++){
		keylist[i].tag = (unsigned char)va_arg(ap, int);
		keylist[i].size = va_arg(ap, int);
		keylist[i].key = va_arg(ap, void*);
		if(0 == keylist[i].size || NULL == keylist[i].key)
			keylist[i].tag = 0xff;	//为没有密钥数据的参数设置标志
	}
	va_end(ap);	//不定参数提取结束

			keysize = 120;	//统计密钥部分的大小//96

		if (0 == keysize)
		return NULL;
	keydata = (keys_data_sm2*)malloc(keysize);
	if (NULL == keydata)	//内存分配失败
		return NULL;
	//开始组织密钥数据的结构
	keysk = (keysk_data_sm2*)(&keydata->keysk);	//开始组织密钥部分的数据
    keypk = (keypk_data_sm2*)(&keydata->keypk);	//开始组织密钥部分的数据

	    if ( 0xff != keylist[0].tag){
			memcpy(&keysk->key, keylist[0].key, keylist[0].size);	//复制真实的密钥
		//	keysk = key + sizeof(key)/4;	//指向下一个密钥存储位置
		}
	    if ( 0xff != keylist[1].tag){
			memcpy(&keypk->key, keylist[1].key, keylist[1].size);	//复制真实的密钥
		//	key = key + sizeof(key)/4;	//指向下一个密钥存储位置
		}

	return  keydata;
}

/*******************************************************************************
功能：生成下传密码数据结构
注意：调用程序需要释放返回的指针
作者：nbx
时间：2013.06.18
参数：count：需要组织的密钥个数，传递参数顺序：tag,size,key指针
返回值： NULL生成失败；密钥数据的完整结构指针，可以参考协议和keys_data、key_data结构
*******************************************************************************/
keys_data_sm4*tf09_make_sm4keydata(int count, ...)
{
    int i;
	va_list ap;
	struct {	//本函数的专用结构，在内部临时定义，临时使用
		unsigned char tag;
		int size;
		void* key;
	}keylist[count];
	int keysize = 0;
	keys_data_sm4 * keydata;
	key_data_sm4 *key;

	va_start(ap, count);	//开始不定参数的提取
	for(i=0;i<count;i++){
		keylist[i].tag = (unsigned char)va_arg(ap, int);
		keylist[i].size = va_arg(ap, int);
		keylist[i].key = va_arg(ap, void*);
		if(0 == keylist[i].size || NULL == keylist[i].key)
			keylist[i].tag = 0xff;	//为没有密钥数据的参数设置标志
	}
	va_end(ap);	//不定参数提取结束

			keysize = 120;	//统计密钥部分的大小//96

		if (0 == keysize)
		return NULL;
	keydata = (keys_data_sm4*)malloc(keysize);
	if (NULL == keydata)	//内存分配失败
		return NULL;
	//开始组织密钥数据的结构
	key = (key_data_sm4*)(&keydata->keys);	//开始组织密钥部分的数据

	    if ( 0xff != keylist[0].tag){
			memcpy(&key->key, keylist[0].key, keylist[0].size);	//复制真实的密钥
		}

	return  keydata;
}

/*******************************************************************************
功能：将指令参数复制到CBW结构中，根据CBW指令进行数据通信。CBW中的数据长度和方向已经设置完毕
注意：CBW中的数据长度和方向以及指令标示必须在上层已经填充完毕
作者：宇浩然
时间：2012.04.22
参数：dev：设备；commPara：命令参数结构指针，buffer：缓冲区指针
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
static int tf09_cbw(const tf09_device* dev, void* buffer)
{
	int ret, length,i;
	unsigned char csw[13];	//返回的CSW，有效位是最后一个字节
	CBW* cbw = tf09_get_cbw(dev);

	ret = tf09_bulk_write(dev, cbw, sizeof(CBW), TIMEOUT);	//下发CBW
/*
    printf("CBW:\n");
	for(i=0;i<4;i++)
	{
	    printf("%02x ",cbw->dCBWSignature[i]);
	}
		for(i=0;i<4;i++)
	{
	    printf("%02x ",cbw->dCBWTag[i]);
	}
		for(i=0;i<4;i++)
	{
	    printf("%02x ",cbw->dCBWDataTransferLength[i]);
	}
	printf("%02X %02x %02x %02x ",cbw->bmCBWFlag,cbw->bCBWLUN,cbw->bCBWCBLength,cbw->priCommand);
		for(i=0;i<4;i++)
	{
	    printf("%02x ",cbw->secCommand[i]);
	}
	printf("%02X %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",(cbw->secPara).channelTag,(cbw->secPara).channelModel,cbw->secPara.algorithm,cbw->secPara.secAlgorithm,cbw->secPara.keyPara,cbw->secPara.funcTag,cbw->secPara.reserve,cbw->secPara.dataHigh,cbw->secPara.dataLow,cbw->secPara.doDataHigh,cbw->secPara.doDataLow);
    printf("\n");
*/
	if(ret < 0)
		return ret;

	length = cbw->dCBWDataTransferLength[3];
	length = (length << 8) | cbw->dCBWDataTransferLength[2];
	length = (length << 8) | cbw->dCBWDataTransferLength[1];
	length = (length << 8) | cbw->dCBWDataTransferLength[0];

	if ((length > 0)&&(NULL != buffer)){	//数据大小不为0时才有数据传送
		if(cbw->bmCBWFlag == FROMUSB){	//依数据方向进行数据传输
			ret = tf09_bulk_read(dev, buffer, length, TIMEOUT);
	/*		printf("IN:\n");
			for(i=0;i<length;i++)
			{
			    printf("%02x ",*((unsigned char *)(buffer+i)));
			}
			printf("\n");*/
		}else{
			ret = tf09_bulk_write(dev, buffer, length, TIMEOUT);
	/*		printf("OUT:\n");
			for(i=0;i<length;i++)
			{
			    printf("%02x ",*((unsigned char *)(buffer+i)));
			}
			printf("\n");*/
		}
	}else{
		ret = 0;
	}

	if(ret < 0)
		return ret;

	csw[12] = -1;
	tf09_bulk_read(dev, &csw, sizeof(csw), TIMEOUT);	//读取CSW
/*
	printf("CSW:\n");
	for(i=0;i<sizeof(csw);i++)
	{
	    printf("%02x ", *((unsigned char *)(csw+i)));
	}
	printf("\n");
*/
	if (0 != csw[12])	//依据最后1个字节判断操作是否成功
		ret = -1;

	return ret;
}


/*******************************************************************************
功能：实现写入数据的指令。
注意：
作者：nbx
时间：2013.06.01
参数：dev：设备；buffer：缓冲区指针指向写入的数据，startaddr:写入数据的起始地址 size：写入数据的长度
返回值： <0：失败，其他：实际接收或发送数据字符数
*******************************************************************************/
int tf09_write_data(const tf09_device* dev,const void* buffer,int startaddr, int size)
{
	if ((size > 7) || (size <= 0) || (NULL == buffer))
	{
		return -1;
	}

	if(startaddr > 128*5)
	{
		printf("full the max start addr!\n");
		return -1;
	}

	if((size*1024) > (320*1024 - startaddr*512))
	{
		printf("max size is 7\n");
		return -1;
	}

	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
	{
		printf("cbw error!\n");
		return -1;
	}
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';
    size=size*1024;

	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)size;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh =(unsigned char)(size>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = TOUSB;
	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x09;	//
	cbw->secCommand[3] = (unsigned char)0x01;	//

	((unsigned char *)commPara)[0] = (unsigned char)0x00;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)(startaddr>>8);
	((unsigned char *)commPara)[3] = (unsigned char)startaddr;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[8] = (unsigned char)size;
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;

	return  tf09_cbw(dev, (void*)buffer);
}

/*******************************************************************************
功能：实现读取数据的指令。
注意：
作者：nbx
时间：2013.06.01
参数：dev：设备；buffer：缓冲区指针存储读出的数据; srcaddr :读取数据的起始地址 size:读取的数据长度
返回值： <0：失败
*******************************************************************************/
int tf09_read_data(const tf09_device* dev, void* buffer,int srcaddr,int size)
{
	if ((size > 7) || (size <= 0) || (NULL == buffer))
	{
		return -1;
	}

	if(srcaddr > 128*5)
	{
		printf("full the max start addr!\n");
		return -1;
	}

	if((size*1024) > (320*1024 - srcaddr*512))
	{
		printf("max size is 7\n");
		return -1;
	}

	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
	{
		printf("cbw error!\n");
		return -1;
	}
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';

    size=size*1024;

	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)size;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh =(unsigned char)(size>>8);
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = FROMUSB;
	cbw->secCommand[0] = (unsigned char)0x02;	//写入指令标识
	cbw->secCommand[1] = (unsigned char)0x01;	//
	cbw->secCommand[2] = (unsigned char)0x09;	//
	cbw->secCommand[3] = (unsigned char)0x02;

	((unsigned char *)commPara)[0] = (unsigned char)0x00;
	((unsigned char *)commPara)[1] = (unsigned char)0x01;
	((unsigned char *)commPara)[2] = (unsigned char)(srcaddr>>8);
	((unsigned char *)commPara)[3] = (unsigned char)srcaddr;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)(size>>8);
	((unsigned char *)commPara)[8] = (unsigned char)size;
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;

	return  tf09_cbw(dev, buffer);
}
/*******************************************************************************
功能：实现数据擦除指令。
注意：
作者：nbx
时间：2013.06.01
参数：dev：设备；iregion：擦除区域
返回值： <0：失败
*******************************************************************************/
int tf09_erase_data(const tf09_device* dev,int iregion)
{

	void* buffer;
    if(iregion>5)
    {
        printf("please choise within 0~5!\n");
        return -1;
    }
	CBW* cbw = tf09_get_cbw(dev);
	if (NULL == cbw)
	{
		printf("cbw error!\n");
		return -1;
	}
	tf09_comm_para* commPara = &(cbw->secPara);
	tf09_comm_para_init(commPara);

	cbw->dCBWSignature[0] = 'U';
	cbw->dCBWSignature[1] = 'S';
	cbw->dCBWSignature[2] = 'B';
	cbw->dCBWSignature[3] = 'C';
//	cbw->dCBWTag[0] = 0xc8;
//	cbw->dCBWTag[1] = 0x7a;
//	cbw->dCBWTag[2] = 0xad;
//	cbw->dCBWTag[3] = 0x86;

	cbw->dCBWDataTransferLength[0] = commPara->dataLow = (unsigned char)0x00;
	cbw->dCBWDataTransferLength[1] = commPara->dataHigh = (unsigned char)0x02;
	cbw->dCBWDataTransferLength[2]  =(unsigned char) 0x00;
	cbw->dCBWDataTransferLength[3] =(unsigned char) 0x00;

	cbw->bmCBWFlag = TOUSB;
	cbw->bCBWLUN = (unsigned char)0x00;	//
	cbw->bCBWCBLength = (unsigned char)0x10;	//
	cbw->priCommand = (unsigned char)0xd0;

	cbw->secCommand[0] = (unsigned char)0x02;	//
	cbw->secCommand[1] = (unsigned char)0x01;	//写入指令标识
	cbw->secCommand[2] = (unsigned char)0x09;	//
	cbw->secCommand[3] = (unsigned char)0x03;	//

	((unsigned char *)commPara)[0] = (unsigned char)0x00;
	((unsigned char *)commPara)[1] = (unsigned char)iregion;
	((unsigned char *)commPara)[2] = (unsigned char)0x00;
	((unsigned char *)commPara)[3] = (unsigned char)0x00;
	((unsigned char *)commPara)[4] = (unsigned char)0x00;
	((unsigned char *)commPara)[5] = (unsigned char)0x00;
	((unsigned char *)commPara)[6] = (unsigned char)0x00;
	((unsigned char *)commPara)[7] = (unsigned char)0x00;
	((unsigned char *)commPara)[8] = (unsigned char)0x00;
	((unsigned char *)commPara)[9] = (unsigned char)0x00;
	((unsigned char *)commPara)[10] = (unsigned char)0x00;

	return  tf09_cbw(dev, (void*)buffer);
}
