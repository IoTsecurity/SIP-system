#include "sm1.h"


static void disp(const char * str,void * pbuf,int size)
{
	printf("%s",str);
	int i=0;
	for(i=0;i<size;i++)
		printf("%02d ",*((unsigned char *)pbuf+i));
	putchar('\n');
}

int writemessage(  unsigned char *message)
{
	  FILE * outfile, *infile;
	     outfile = fopen("/opt/ipnc/message", "wb");

	     unsigned char buf[MAXLEN];
		int i=0;

		for(i=0;i<MAXLEN;i++)
		{
			 buf[i]=message[i];
		}

	     if( outfile == NULL )
	     {
	         printf(" outfile not exit\n");
	         exit(1);
	     }
	     fwrite( &buf, sizeof( unsigned char ), MAXLEN, outfile);
	     fclose(outfile);
}

int write_ak(unsigned char *ak)
{
	  FILE * outfile, *infile;
	   outfile = fopen("/opt/ipnc/ak", "wb");

	  unsigned char buf[KEYLEN];
		int i=0;

		for(i=0;i<KEYLEN;i++)
		{
			 buf[i]=ak[i];
		}

	     if( outfile == NULL )
	     {
	         printf("not exit\n");
	         exit(1);
	     }
	     fwrite( &buf, sizeof( unsigned char ), KEYLEN, outfile);
	     fclose(outfile);
}

int write_ek(unsigned char *ek)
{
	  FILE * outfile, *infile;
	   outfile = fopen("/opt/ipnc/ek", "wb");

	  unsigned char buf[KEYLEN];
		int i=0;

		for(i=0;i<KEYLEN;i++)
		{
			 buf[i]=ek[i];
		}

	     if( outfile == NULL )
	     {
	         printf("not exit\n");
	         exit(1);
	     }
	     fwrite( &buf, sizeof( unsigned char ), KEYLEN, outfile);
	     fclose(outfile);
}

int write_sk(unsigned char *sk)
{
	  FILE * outfile, *infile;
	   outfile = fopen("/opt/ipnc/sk", "wb");

	  unsigned char buf[KEYLEN];
		int i=0;

		for(i=0;i<KEYLEN;i++)
		{
			 buf[i]=sk[i];
		}

	     if( outfile == NULL )
	     {
	         printf("not exit\n");
	         exit(1);
	     }
	     fwrite( &buf, sizeof( unsigned char ), KEYLEN, outfile);
	     fclose(outfile);
}


int readmessage( unsigned char *message)
{
	     FILE   *infile;
	     infile = fopen("/opt/ipnc/message", "rb");
	     unsigned char buf[MAXLEN];

	     int i=0;
	     if(infile == NULL )
	     {
	         printf("infile not exit\n");
	         exit(1);
	     }

	     int rc;
	     while( (rc = fread(&buf,sizeof(unsigned char), MAXLEN,infile)) != 0 )
	     ;

	     for(i=0;i<MAXLEN;i++)
	     {
	         message[i]=buf[i];
	     }

	     fclose(infile);

}

void writekey(unsigned char * key,int keylen,int type)
{
		unsigned char  message[6];

		message[0]=3;//表示要加密
		message[1]=type;//表示采用SM1算法
		message[2]=keylen;//密钥长度，为16
		message[3]=0;
		message[4]=0;
		message[5]=0;

		writemessage(message);

		write_sk(key);
		write_ek(key);
		write_ak(key);

	    printf("write finished!");


}

