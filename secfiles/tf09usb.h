/*
* 此头文件仅用于同方的USB加密模块设备访问程序，供内部使用；用户不应该直接引用此头文件
*
* 作者：宇浩然
* 时间：2012.04.21
*
*/

#ifndef	_TF09USB_H_
#define	_TF09USB_H_

//Linux内核限制了通过usbdevfs通信的数据长度为16k
#define	TF09_MAX_USB_SIZE	(16*1024)
//设备路径长度
#define	TF09_PATH_MAX	32
//假定最多能同时使用的加密模块数量为32。
#define	TF09_USB_DEVICE_MAX	32

//协议指令参数部分的数据，11个字节，依据不同的指令协议进行设置
typedef struct{
	unsigned char channelTag;	//通道标识
	union{
		struct{
			unsigned char channelModel;	//通道模式
			unsigned char algorithm;		//算法标识
			unsigned char secAlgorithm;	//二级算法
			unsigned char keyPara;			//密钥参数
			unsigned char funcTag;			//功能标识
		};	//适用于设置通道信息和读取通道信息
		struct{
			unsigned char dataAddr;		//数据位置
			unsigned char dataLength;		//数据长度
		};	//适用于读取数据
		struct{
			unsigned char destAddr;		//结果数据地址
			unsigned char destLength;		//结果数据长度
			unsigned char sourceAddr;		//源数据地址
			unsigned char sourceLength;	//源数据长度
			unsigned char dataTag;			//数据方向标识
		};	//适用于使用通道，兼容其他情形
	};	//end of union
	union{
		struct{
			unsigned char reserve;
			unsigned char dataHigh;	//有数据传输时的数据段长度
			unsigned char dataLow;
		};	//适用于读取数据和使用通道，兼容其他情形
		struct{
			unsigned char keySource;	//密钥位于安全模块中时指定其位置和长度
			unsigned char keyHigh;
			unsigned char keyLow;
		};	//适用于设置通道信息
	};	//end of union
	unsigned char doDataHigh;	//进行操作的数据长度，适用于使用通道
	unsigned char doDataLow;
}__attribute__ ((packed))tf09_comm_para;

//用于与USB设备通信的CBW结构，标准结构
typedef struct {
	unsigned char		dCBWSignature[4];	//固定：USBC
	unsigned char		dCBWTag[4];			//固定：TF09
	unsigned char		dCBWDataTransferLength[4];	//传输的数据长度，每次使用前都要指定
	unsigned char		bmCBWFlag;		//数据方向，TOUSB为写数据，FROMUSB为读数据，每次使用前都要指定
	unsigned char		bCBWLUN;			//固定：00
	unsigned char		bCBWCBLength;	//固定：16
	unsigned char		priCommand;		//固定：D0
	unsigned char		secCommand[4];		//协议命令，每次使用前都要指定
	tf09_comm_para		secPara;		//命令参数，依协议命令的不同，参数意义也不同，每次使用前都要指定
} __attribute__ ((packed))CBW;	//供用户自定义CBW命令结构

//引用某个CBW指针中的数据长度，总是以当前的大小端方式引用
//所以只能与0进行比较或者赋值为0，不可做其他操作
#define CBW_DATA_LENGTH(cbw) (*((unsigned int*)&(cbw->dCBWDataTransferLength[0])))

//安全模块设备结构，保存打开的句柄和相应的CBW结构
//每个模块一个CBW互不冲突，以支持多个模块，并且不需要总是拷贝数据
typedef struct _usb_device{
	struct _usb_device * next;
	int fd;
	int flag;
	CBW	cbw;
} __attribute__ ((packed))tf09_device;	//自定义结构，用于保存USB设备的句柄，客户不需要直接存储此结构

extern tf09_device *tf09Device;
extern const CBW cbw_init;

#define	TF09_CHECK(ret, value) do	\
			{	\
				if (ret < 0)	\
					return value>0 ? value : ret;	\
			} while(0)

//下列函数在usb设备初始化、数据通信和关闭usb设备时自动调用
//最终用户除非明确知道这些函数的意义，否则不应该直接调用这些函数
static int tf09_init(tf09_device * dev);
static int tf09_detach_driver(tf09_device * dev);
static int usb_bulk(int fd, int ep, void* data, int size, int timeout);
static int tf09_claim_interface(tf09_device * dev);
static int tf09_release_interface(tf09_device * dev);

//下列函数的说明请直接查看源代码中的函数注释
tf09_device * tf09_find_device(short int idVendor, short int idProduct);
int tf09_bulk_write(const tf09_device * dev,const void *data, int size, int timeout);
int tf09_bulk_read(const tf09_device * dev, void *data, int size, int timeout);
void tf09_close(void);
CBW* tf09_get_cbw(const tf09_device* dev);	//获取与指定设备相关的CBW指针
tf09_comm_para* tf09_get_comm_para(const tf09_device* dev);	//获取指定设备的CBW中的指令参数位置
void tf09_comm_para_init(tf09_comm_para* secPara);	//同上，同时做初始化

#endif	//_TF09USB_H_
