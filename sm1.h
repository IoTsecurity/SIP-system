/*
 * sm1.h
 *
 *  Created on: 2014年6月5日
 *      Author: tirvideo
 */

#ifndef SM1_H_
#define SM1_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "tf09.h"


#define  KEYADDR 0

#define WRITE_UNIT 1024
#define KEYLEN 16
#define MAXLEN 6
//写密钥,key为要书写的密钥，keylen为密钥长度，type为加密采用的算法，1表示SM1，4表示SM4

void writekey(unsigned char * key,int keylen,int type);
#endif /* SM1_H_ */
