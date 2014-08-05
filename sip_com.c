/*
 * sip_com.c
 *
 *  Created on: 2014年3月20日
 *      Author: jiangzaiwei
 */

#include "sip_com.h"
#include "interface.h"

#include <stdio.h>
#include <fcntl.h>

#include<stdlib.h>
#include<sys/types.h>
#include<fcntl.h>
#include<string.h>
#include<net/if.h>
#include<net/if_arp.h>
#include<sys/ioctl.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

RegisterContext *RegisterCon=NULL;
AuthActive *authactive_data=NULL;
P2PLinkContext * P2PLinkContext_data=NULL;
AccessAuthRequ *auth_request_packet_data=NULL;  	// used by SIPUA
P2PCommContext *p2pcc=NULL;							// used by SIPUA

/*-----------------common function----------------------*/

int get_conf_value( const char *key_name, char *value, const char *filename)
{
	char * file=filename;//device_info.cfgFile;
    int res;
    int fd = open(file,O_RDONLY);
    if(fd > 2){
        res = 0;
        char c;
        char *ptrk=key_name;
        char *ptrv=value;
        while((read(fd,&c,1))==1)
         {
           if(c == (*ptrk)){
             do{
            	 	ptrk ++;
					read(fd,&c,1);
                }while(c == (*ptrk));
				if(c=='='&&(*ptrk)=='\0'){
					while(1)
						{
						read(fd,&c,1);
						if(c != '\n')
							{
								(*ptrv) = c;
								ptrv ++;
							}
						else{
								(*ptrv) = '\0';
								break;
							}
						}
					res = 1;
					break;
				}else{
					do{
					read(fd,&c,1);
					}while(c != '\n');
					ptrk=key_name;
				}
			}
		   else
			{
			do{
				read(fd,&c,1);
			}while(c != '\n');
			ptrk=key_name;
			}
		}
		close(fd);
		}else{
		res = 0;
	}
    return res;
}

int init_Contextconf(const char * file)
{

	if(RegisterCon==NULL)
	{
		printf("malloc error\n");
		return 0;
	}
	int fd=open(file,O_RDONLY);
	if(fd>2)
	{   //确保文件存在

    	char value[CHARLEN];
	    get_conf_value( "radius_id",RegisterCon->radius_id,file);

	    get_conf_value( "self_type", value,file);
	    if(strcmp(value,"SIPserver")==0)
	    {
	    	Self_type=SIPserver;
	    }
	    else if(strcmp(value,"IPC")==0)
	    {
	    	Self_type=IPC;
	    	//user_type=USER_TYPE_IPC;
	    }
	    	else if(strcmp(value,"CLIENT")==0)
	    {
	    	Self_type=Client;
	    	//user_type=USER_TYPE_CLIENT;
	    }
	    	else if(strcmp(value,"NVR")==0)
	    {
	    	Self_type=NVR;

	    	//为了避免register 的一个认证bug，该bug于radius有关，现暂时增加这条语句
	    	//Self_type=IPC;
	    	//user_type=USER_TYPE_NVR;
	    }

	    //value=(char *)malloc(sizeof(char)*20);
	    get_conf_value( "self_id",RegisterCon->self_id,file);
	    //RegisterCon->self_id=value;

	    //value=(char *)malloc(sizeof(char)*20);
	    get_conf_value( "self_password",RegisterCon->self_password,file);
	    //RegisterCon->self_password=value;

	    getNetInfo(NULL,RegisterCon->self_MACaddr.macaddr);
	    Keybox.nkeys=0;

	    if(Self_type!=SIPserver)
	    {
	    	//value=(char *)malloc(sizeof(char)*20);
	    	get_conf_value("server_ip",RegisterCon->peer_ip,file);
	    	//RegisterCon->peer_ip=value;

	    	//value=(char *)malloc(sizeof(char)*20);
	    	get_conf_value("server_id",RegisterCon->peer_id,file);
	    	//RegisterCon->peer_id=value;
	    }

	       close(fd);
	       printf("open config file:%s success\n",file);
	    }
	    else{
	       printf("can not open config file:%s\n",file);
	       return 0;
	    }
	return 1;
	}

int codeToChar(char *data,const int lenth)
{
	int i,j;
	i=lenth-1;
	j=lenth/2-1;
	for(i=lenth-1;i>=0;i=i-2,j--)
	{
		data[i]=(data[j]&0x0f)+0x30;
		data[i-1] = ((data[j]>>4)&0x0f)+0x30;
	}
	return 1;
}

int decodeFromChar(char *data,const int lenth)
{
	int i,j;
	i=1;
	j=0;
	for(j=0;i<lenth ;i=i+2,j++)
	{
		data[j]=(data[i] - 0x30 ) +((data[i-1]-0x30) <<4);
	}
	return 1;
}

int getNetInfo(char* outip,char *outmac)
{
	int i=0;
	int sockfd;
	struct ifconf ifconf;
	char buf[512];
	struct ifreq *ifreq;
	char* ip;
	ifconf.ifc_len = 512;
	ifconf.ifc_buf = buf;

	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0)
	{
		return -1;
	}
	if(!ioctl(sockfd, SIOCGIFCONF, &ifconf))
	{

		ifreq = (struct ifreq*)buf;
		char mac_addr[50];
		//printf("strlen((char*)ether_ntoa(ifreq->ifr_hwaddr.sa_data))):%d\n",strlen((char*)ether_ntoa(ifreq->ifr_hwaddr.sa_data)));
		//memcpy(mac_addr,(char *)ether_ntoa(ifreq->ifr_hwaddr.sa_data),strlen((char*)ether_ntoa(ifreq->ifr_hwaddr.sa_data)));

		for(i=(ifconf.ifc_len/sizeof(struct ifreq)); i>0; i--)
		{
			//printf("name:%s ",ifreq->ifr_ifrn.ifrn_name);
			ip = inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr);
			//printf("mac:%s\n",inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_hwaddr))->sin_addr));
			//printf("ip:%s\n",ip);
			ifreq++;
			/*if(strcmp(ip,"127.0.0.1")==0)
			{
				ifreq++;
				continue;
			}*/
		}
		int num;
		num=1;
		ifreq=(struct ifreq*)buf+num;

		if(outip!=NULL)
		{
			ip = inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr);
			strcpy(outip,ip);
		}

		if(outmac!=NULL)
		{
			struct ifreq struReq;
			strncpy(struReq.ifr_name, ifreq->ifr_ifrn.ifrn_name, sizeof(struReq.ifr_name));
			//printf("struReq.ifr_name:%s",struReq.ifr_name);
			ioctl(sockfd,SIOCGIFHWADDR,&struReq);
			memset(mac_addr,0,50);
			//printf("(char*)ether_ntoa(struReq.ifr_hwaddr.sa_data)):%s",(char*)ether_ntoa(struReq.ifr_hwaddr.sa_data));
			//memcpy(mac_addr,(char *)ether_ntoa(struReq.ifr_hwaddr.sa_data),strlen((char*)ether_ntoa(struReq.ifr_hwaddr.sa_data)));
			//mac_stox(outmac,mac_addr);
			memcpy(outmac,(char *)struReq.ifr_hwaddr.sa_data,MAC_LEN);
		}
		close(sockfd);
	}
	return 1;

}

int mac_stox(char *x, const char * s)
{
	int i,j,k;
	char d[6];
	char hen=0x00;
	char hen_temp=0x00;
	for(i=strlen(s)-1,j=5;i>=0&&j<6;i--)
	{
		k=0;
		while(s[i]!=':')
		{
			if(s[i]>='0'&&s[i]<='9')
			{
				hen_temp=((void*)s[i])-'0';
			}
			else if(s[i]>='a'&&s[i]<'g')
			{
				hen_temp=(((void*)s[i])-'a')+0x0a;
			}
			else
			{
				if(k%2==0)
				{
					hen=hen_temp;
				}
				else
				{
					hen=hen|(hen_temp<<4);
				}
				break;
			}
			if(k%2==0)
			{
				hen=hen_temp;
			}
			else
			{
				hen=hen|(hen_temp<<4);
			}
			k++;i--;
		}
		d[j]=hen;
		j--;
	}
	memcpy(x,d,6);
	return 1;
}

int printfx(const unsigned char *p, const int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		printf("%2x ",p[i]);
	}printf("\n");
	return 1;
	}

int P2PCommContext_Conversion(const P2PLinkContext *lc,P2PCommContext *cc)
{
	memcpy(cc->self_id,lc->self_id,MAXIDSTRING);
	memcpy(&cc->self_MACaddr,&lc->self_MACaddr,sizeof(cc->self_MACaddr));

	memcpy(cc->peer_id,lc->target_id,MAXIDSTRING);
	cc->peer_type=lc->target_type;
	memcpy(&cc->peer_MACaddr,&lc->target_MACaddr,sizeof(cc->peer_MACaddr));

	return 1;
}

int P2PLinkContext_Conversion_C(const RegisterContext *rc, P2PLinkContext *lc, const  enum DeviceType target_type)
{
	memcpy(lc->self_id,rc->self_id,MAXIDSTRING);
	memcpy(lc->self_MACaddr.macaddr,rc->self_MACaddr.macaddr,sizeof(lc->self_MACaddr.macaddr));

	memcpy(lc->peer_id,rc->peer_id,MAXIDSTRING);
	lc->peer_type=SIPserver;
	memcpy(lc->peer_MACaddr.macaddr,rc->peer_MACaddr.macaddr,sizeof(lc->peer_MACaddr.macaddr));
	memcpy(lc->peer_ip,rc->peer_ip,MAXIDSTRING);

	lc->target_ports.rtp_send=0;
	lc->target_ports.rtcp_send=0;
	lc->target_ports.rtp_recv=0;
	lc->target_ports.rtcp_recv=0;

	lc->target_type=target_type;


	/*-------------后续需要修改--------------*/
	if(target_type==NVR)
	{
		memcpy(lc->target_id,"user2",sizeof(lc->target_id));
	}
	else if(target_type==IPC)
	{
		memcpy(lc->target_id,"11111",sizeof(lc->target_id));
	}

	return 1;
	}

int P2PLinkContext_Conversion_S(const RegisterContext *rc_IPC, const RegisterContext *rc_NVR,
		P2PLinkContext *lc_to_IPC, P2PLinkContext *lc_to_NVR)
{
	memcpy(lc_to_IPC->self_id,rc_IPC->self_id,MAXIDSTRING);
	memcpy(lc_to_IPC->self_MACaddr.macaddr,rc_IPC->self_MACaddr.macaddr,sizeof(lc_to_IPC->self_MACaddr.macaddr));

	memcpy(lc_to_IPC->peer_id,rc_IPC->peer_id,MAXIDSTRING);
	lc_to_IPC->peer_type=IPC;
	memcpy(lc_to_IPC->peer_MACaddr.macaddr,rc_IPC->peer_MACaddr.macaddr,sizeof(lc_to_IPC->peer_MACaddr.macaddr));
	memcpy(lc_to_IPC->peer_ip,rc_IPC->peer_ip,MAXIDSTRING);

	memcpy(lc_to_IPC->target_id,rc_NVR->peer_id,MAXIDSTRING);
	lc_to_IPC->target_type=NVR;
	memcpy(lc_to_IPC->target_MACaddr.macaddr,rc_NVR->peer_MACaddr.macaddr,sizeof(lc_to_IPC->target_MACaddr.macaddr));
	memcpy(lc_to_IPC->target_ip,rc_NVR->peer_ip,MAXIDSTRING);
	lc_to_IPC->target_ports.rtp_send=0;
	lc_to_IPC->target_ports.rtcp_send=0;
	lc_to_IPC->target_ports.rtp_recv=0;
	lc_to_IPC->target_ports.rtcp_recv=0;

	memcpy(lc_to_NVR->self_id,rc_NVR->self_id,MAXIDSTRING);
	memcpy(lc_to_NVR->self_MACaddr.macaddr,rc_NVR->self_MACaddr.macaddr,sizeof(lc_to_NVR->self_MACaddr.macaddr));

	memcpy(lc_to_NVR->peer_id,rc_NVR->peer_id,MAXIDSTRING);
	lc_to_NVR->peer_type=NVR;
	memcpy(lc_to_NVR->peer_MACaddr.macaddr,rc_NVR->peer_MACaddr.macaddr,sizeof(lc_to_NVR->peer_MACaddr.macaddr));
	memcpy(lc_to_NVR->peer_ip,rc_NVR->peer_ip,MAXIDSTRING);

	memcpy(lc_to_NVR->target_id,rc_IPC->peer_id,MAXIDSTRING);
	lc_to_NVR->target_type=IPC;
	memcpy(lc_to_NVR->target_MACaddr.macaddr,rc_IPC->peer_MACaddr.macaddr,sizeof(lc_to_NVR->target_MACaddr.macaddr));
	memcpy(lc_to_NVR->target_ip,rc_IPC->peer_ip,MAXIDSTRING);
	lc_to_NVR->target_ports.rtp_send=0;
	lc_to_NVR->target_ports.rtcp_send=0;
	lc_to_NVR->target_ports.rtp_recv=0;
	lc_to_NVR->target_ports.rtcp_recv=0;

	return 1;
	}

