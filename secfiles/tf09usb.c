/*
* 此文件仅用于同方USB加密模块设备访问程序，供客户使用，不建议客户修改
*
* 作者：宇浩然
* 时间：2012.04.21
*
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/usbdevice_fs.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "tf09usb.h"

//此结构为内部使用，仅在搜索设备时读取pid vid时使用
struct usb_device_descriptor {
        unsigned char bLength;
        unsigned char bDescriptorType;
        unsigned short int bcdUSB;
        unsigned char bDeviceClass;
        unsigned char bDeviceSubClass;
        unsigned char bDeviceProtocol;
        unsigned char bMaxPacketSize0;
        unsigned short int idVendor;
        unsigned short int idProduct;
        unsigned short int bcdDevice;
        unsigned char iManufacturer;
        unsigned char iProduct;
        unsigned char iSerialNumber;
        unsigned char bNumConfigurations;
} __attribute__ ((packed));

const static char * usbpath[] = {"/dev/bus/usb", "/proc/bus/usb"}; //usb devfs可能存在的位置
tf09_device *tf09Device = NULL;
//定义CBW初始化常量，用于不同USB设备初始化时的复制
const CBW cbw_init = {{'U','S','B','C'}, {'T','F','0','9'},	//固定不变，任何时候都不进行读写操作
				{0,0,0,0},	//数据长度，每次使用前都必须设定一次，以小端方式存储的32位整数，目前只用低两位
				0,	//数据方向，每次使用前都必须设定一次，
				0,16, 0xd0,	//固定不变，任何时候都不进行读写操作
				{2, 1, 5, 0},	//与协议相关的指令标识，每次使用前必须设定
				{0,{{0,0,0,0,0}},{{0,0,0}},0,0}	//与协议指令相关的参数信息，每次使用前必须设定一次
			};

/*******************************************************************************
功能：搜索系统中符合参数的所有USB设备，同时完成通信前的所有准备工作。
注意：
作者：宇浩然
时间：2012.04.21
参数：idVendor即设备的VID, idProduct即设备的PID
返回值：NULL失败
*******************************************************************************/

tf09_device * tf09_find_device(short int idVendor, short int idProduct)
{
	DIR * usb_dir, *bus_dir;
	struct dirent *bus, *dev;
	char buspath[TF09_PATH_MAX], devpath[TF09_PATH_MAX];
	struct usb_device_descriptor dev_des;
	int fd, usb_index;	//查找usb设备的总线位置
 	  tf09_close();	//若之前已经查找过设备，则关闭所有设备，此函数可以确保tf09Device=NULL
	//tf09Device->next=NULL;
	for(usb_index=0;usb_index<(sizeof(usbpath)/sizeof(char*));usb_index++)	//搜索并打开总线所在目录
	{
		usb_dir = opendir(usbpath[usb_index]);
		if (NULL != usb_dir)
			break;
	}
	if(NULL == usb_dir)
		return NULL;
	while(NULL != (bus=readdir(usb_dir))) //读取usb devfs下的每一项，即bus
	{
		if(!strchr("1234567890", bus->d_name[0])) //bus肯定以数字开头，其实全部都是数字
			continue;
		snprintf(buspath, TF09_PATH_MAX, "%s/%s", usbpath[usb_index], bus->d_name);
		bus_dir = opendir(buspath);
		if(NULL==bus_dir)
			continue;
		while(NULL!=(dev=readdir(bus_dir))) //读取总线目录下的每一项，即usb设备
		{
			if(!strchr("1234567890", dev->d_name[0]))
				continue;
			snprintf(devpath, TF09_PATH_MAX, "%s/%s", buspath, dev->d_name);
			if((fd = open(devpath, O_RDWR))<0)
				continue;
			if(read(fd, (void *)(&dev_des), sizeof(dev_des)) > 0 &&
				dev_des.idVendor==idVendor && dev_des.idProduct==idProduct) //客户需要的设备
			{
				tf09_device *tmp = (tf09_device*)malloc(sizeof(tf09_device));
				tmp->fd = fd;
				tmp->flag=1;
				if(0 == tf09_init(tmp)){
					tmp->next = tf09Device;
					tf09Device = tmp;	//将新设备添加到tf09Device单向链表中
				}else{
					close(fd);
					free(tmp);	//通信前的初始化工作失败，关闭设备，并释放设备内存
				}
			}else{
				close(fd);
			}
			//已经打开的句柄另行处理，不需要在此关闭
		}
		closedir(bus_dir);
	}
	closedir(usb_dir);
	return tf09Device;
}

//给设备赋值
//ad
int tf09_set_device(const tf09_device * dev)
{
	//tf09Device = NULL;
	tf09Device=dev;
	tf09_init(tf09Device);
}
/*******************************************************************************
功能：在指定的USB设备上进行bulk写操作，无16KB限制
注意：
作者：宇浩然
时间：2012.04.21
参数：dev为设备指针，data为数据缓冲地址，size为缓冲区大小，timeout为时间
返回值： <0失败；其他为实际写入的字符数
*******************************************************************************/
int tf09_bulk_write(const tf09_device * dev,const void *data, int size, int timeout)
{
	if (NULL == dev)
		dev = tf09Device;
	if (NULL == dev || dev->fd <= 0 || NULL == data)
		return -1;

	return usb_bulk(dev->fd, 1, (void *)data, size, timeout);
}

/*******************************************************************************
功能：在指定的USB设备上进行bulk读操作，无16KB限制
注意：
作者：宇浩然
时间：2012.04.21
参数：dev为设备指针，data为数据缓冲地址，size计划读取的字符数，timeout为时间
返回值： <0失败；其他为实际读取的字符数
*******************************************************************************/
int tf09_bulk_read(const tf09_device * dev, void *data, int size, int timeout)
{
	if (NULL == dev)
		dev = tf09Device;
	if (NULL == dev || dev->fd <= 0 || NULL == data)
		return -1;

	return usb_bulk(dev->fd, 129, (void *)data, size, timeout);
}

/*******************************************************************************
功能：关闭所有的USB设备，并将tf09Device置空
注意：关闭设备后，若要再次使用，需要重新执行tf09_finddevice函数
作者：宇浩然
时间：2012.04.21
参数：无
返回值：无
*******************************************************************************/
void tf09_close(void)
{
	int i = 0;
	while( (NULL != tf09Device) && (i < TF09_USB_DEVICE_MAX) )
	{
		tf09_device* devtmp = tf09Device;
		tf09Device = tf09Device->next;
		tf09_release_interface(devtmp);	//释放usb设备的interface
		ioctl(devtmp->fd, USBDEVFS_RESET, NULL);
		close(devtmp->fd);
		free(devtmp);
		i++;
	}
	tf09Device = NULL;
}
//add by lqc
void tf09_releaseDevice(const tf09_device * dev)
{
	if(NULL != tf09Device)
	{
		tf09_release_interface(dev);	//释放usb设备的interface
		ioctl(dev->fd, USBDEVFS_RESET, NULL);
		close(dev->fd);
		free(dev);
	}
}
/*******************************************************************************
功能：初始化指定的USB设备完成通信前的准备工作，该设备已经打开
注意：此函数不需要客户调用
作者：宇浩然
时间：2012.04.21
参数：dev为设备指针
返回值：0成功 -1失败
*******************************************************************************/
static int tf09_init(tf09_device * dev)
{
	if(0==tf09_detach_driver(dev))
		ioctl(dev->fd, USBDEVFS_RESETEP, NULL);	//附加驱动卸载后，将设备重置一次
	unsigned char* pa = (unsigned char*)&(dev->cbw);
	unsigned char* pb = (unsigned char*)&cbw_init;
	int i=0;
	for(i=0;i<sizeof(CBW);i++)
		pa[i] = pb[i];
	return tf09_claim_interface(dev);
}

/*******************************************************************************
功能：从指定的USB设备上卸载内核驱动
注意：固定的卸载附加在interface 0上的驱动；此函数不需要客户调用
作者：宇浩然
时间：2012.04.21
参数：dev为设备指针
返回值：0成功 其他失败
*******************************************************************************/
static int tf09_detach_driver(tf09_device * dev)
{
	struct usbdevfs_ioctl comm = {0, USBDEVFS_DISCONNECT, NULL};
	return ioctl(dev->fd, USBDEVFS_IOCTL, &comm);
}

/*******************************************************************************
功能：在指定的USB设备上进行bulk读写操作；此函数屏蔽了内核16KB的限制
注意：用户不应该直接调用此函数
作者：宇浩然
时间：2011.12.26
参数：fd为设备handl，ep为端点号(1或129)，data为数据缓冲地址，size为缓冲区大小，timeout为时间
返回值：<0失败；其他为实际读或写的字符数
*******************************************************************************/
static int usb_bulk(int fd, int ep, void* data, int size, int timeout)
{
	int ret, currentsize, alreadysize=0;
	struct usbdevfs_bulktransfer bulk;
	bulk.ep = ep;
	bulk.timeout = timeout;

	while (alreadysize < size)
	{
		currentsize = size-alreadysize;
		if (currentsize > TF09_MAX_USB_SIZE)
			currentsize = TF09_MAX_USB_SIZE;
		bulk.len = currentsize;
		bulk.data = data;

		ret = ioctl(fd, USBDEVFS_BULK, &bulk);
		TF09_CHECK(ret, alreadysize);

		alreadysize += ret;
		if( 129 == ep && ret < currentsize)	//读取数据时，实际读取数据未达到指定长度
			break;
		data = (char*)data + ret;
	}
	return alreadysize;
}

/*******************************************************************************
功能：claim指定的USB设备的interface
注意：仅claim interface 0；此函数不需要客户调用
作者：宇浩然
时间：2012.04.21
参数：dev为设备指针
返回值：0为成功，<0失败
*******************************************************************************/
static int tf09_claim_interface(tf09_device * dev)
{
	unsigned int interface = 0;
	return ioctl(dev->fd, USBDEVFS_CLAIMINTERFACE, &interface);
}

/*******************************************************************************
功能：与claim相反的操作
注意：仅interface 0；此函数不需要客户调用
作者：宇浩然
时间：2012.04.21
参数：dev为设备指针
返回值：0为成功，<0失败
*******************************************************************************/
static int tf09_release_interface(tf09_device * dev)
{
	unsigned int interface = 0;
	return ioctl(dev->fd, USBDEVFS_RELEASEINTERFACE, &interface);
}

/*******************************************************************************
功能：返回指定USB设备对应的CBW指针
注意：
作者：宇浩然
时间：2012.05.25
参数：dev：设备，若为空，则使用默认设备；
返回值： CBW指针，若为NULL，则失败
*******************************************************************************/
CBW* tf09_get_cbw(const tf09_device* dev)
{
	return (CBW*)(dev ? &(dev->cbw) : (tf09Device ? &(tf09Device->cbw) : NULL));
}

/*******************************************************************************
功能：返回指定USB设备对应的协议参数指针
注意：
作者：宇浩然
时间：2012.05.25
参数：dev：设备，若为空，则使用默认设备；
返回值： 协议参数指针，若为NULL，则失败
*******************************************************************************/
tf09_comm_para * tf09_get_comm_para(const tf09_device* dev)
{
	CBW* cbw = tf09_get_cbw((tf09_device*)dev);
	return cbw ? &(cbw->secPara) : NULL;
}

/*******************************************************************************
功能：回指定USB设备对应的协议参数指针，同时进行初始化
注意：
作者：宇浩然
时间：2012.04.22
参数：dev：设备，若为空，则使用默认设备；
返回值： 无
*******************************************************************************/
void tf09_comm_para_init(tf09_comm_para* secPara)
{
	unsigned int i;
	for(i=0;i<6;i++)
		((unsigned char *)secPara)[i] = 0xff;
	for(;i<sizeof(tf09_comm_para);i++)
		((unsigned char *)secPara)[i] = 0;
}
