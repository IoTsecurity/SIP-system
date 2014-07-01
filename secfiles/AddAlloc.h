/*
 * addAlloc.h
 *
 *  Created on: 2014年1月13日
 *      Author: tirvideo
 */

#ifndef ADDALLOC_H_
#define ADDALLOC_H_

/*
 * 安全区域的擦除模式
 * 	安全存储区域320KB被分为5个区域
 *  0代表0-63kb，1代表64-127kb，2代表128-191kb
 * 	3代表172-255kb，4代表256-319，5代表全部擦除
 * 	这里BULK 0 用来存储本机公私钥，1-4块用于存储其它设备的公钥
 */
#define BULK 0

/*
 *  ADDRSM2S：私钥存储位置
 * 	ADDRSM2P:公钥存储位置
 * 	这里的单位为512字节
 */
#define ADDRSM2 0



#endif /* ADDALLOC_H_ */
