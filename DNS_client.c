#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define TYPE_A 1
#define CLASS_IN 1

//DNS Header Packet structure
struct dnshdr{
	uint16_t id;
	uint8_t rd: 1;
	uint8_t tc: 1;
	uint8_t aa: 1;
	uint8_t opcode: 4;
	uint8_t qr: 1;
	uint8_t rcode: 4;
	uint8_t cd:1;
	uint8_t ad:1;
	uint8_t z:1;
	uint16_t qcount;
	uint16_t ancount;
	uint16_t authcount;
	uint16_t addcount;
};

void encodename(char* src, char* dst){
  int i=0;
  int pos=0;
  while(src[i]!='\0'){
    if(src[i]=='.'){
      dst[pos]=i-pos;
      pos=i+1;
    } else {
    dst[i+1]=src[i];
    }
    ++i;
  }
  dst[pos]=i-pos;
  dst[i+1]=0;
}

int decodename(char* buf, int pos, char* dst){
  int start=pos;
  int ret=0;
  int j=0;
  while(buf[pos]!=0){
    if((buf[pos]&0xC0)==0xC0){ //pointer
      if(ret==0){
	ret=(pos-start)+2;
      }
      pos = (buf[pos]&(~0xC0))<<8+buf[pos];
    } else {
      int len = buf[pos];
      if(j!=0){
	dst[j]='.';
	j++;
      }
      for(int i=0; i<len; i++){
	dst[j+i]=buf[pos+i+1];
      }
      j+=len;
      pos+=len+1;
    }
  }
  dst[j]='\0';
  if(ret==0){
    ret=(pos-start)+1;
  }
  return ret;
}

int printreply(int pos,char* buf){

}

int printquery(int pos,char* buf){
  char name[256];
  int namelen = decodename(buf,pos,name);
  int dnstype = buf[pos+namelen+1];
  int dnsclass = buf[pos+namelen+3];
  printf("Query: %s\t%d\t%d\n",name,dnstype,dnsclass);
  return pos+namelen+4;
}


int main(int argc, char** argv){

	//Create UDP socket
	int mysock = socket(AF_INET, SOCK_DGRAM, 0);
	if(mysock<0){
		printf("There was an error creating the socket\n");
		return 1;
	}

	//Hard Code address of DNS resolver
	int port = htons(53);
	int addr = inet_addr("8.8.8.8");
	struct sockaddr_in dnsserver;
	dnsserver.sin_port = port;
	dnsserver.sin_addr.s_addr = addr;
	dnsserver.sin_family = AF_INET;

	srand(time(NULL));

	//Generate random ID for DNS header
	dnshdr queryheader = {};
	queryheader.id = (uint16_t)rand();			//Random ID for query header
	queryheader.rd = 1;							//Set rd bit
	queryheader.qcount = htons(1);

	//Copy relevant data into buffer and prepare to send to DNS server
	char buf[512] = {};
	memcpy(buf, &queryheader, 12);				//Copies the 12 bytes of struct into array of characters
	char qname[] = "www.google.com";
	int namelength = strlen(qname);
	char *encodedname = (char*)malloc(namelength);
	encodename(qname, encodedname);
	memcpy(&buf[12], encodedname, namelength);	//Copy query name into buffer
	buf[12+namelength+1] = TYPE_A;
	buf[12+namelength+3] = CLASS_IN;

	//Send DNS packet Header to DNS server
	sendto(mysock, buf, 16+namelength, 0, (struct sockaddr*)&dnsserver,sizeof(dnsserver));


	//Recieve Information from DNS server
	char recvbuf[512];
	socklen_t len = sizeof(dnsserver);
	recvfrom(mysock, recvbuf, 512, 0, (struct sockaddr*)&dnsserver, &len);
	
	//Create Reply DNS header and copy data from buffer
	dnshdr replyheader;
	memcpy(&replyheader, recvbuf, 12);

	//Error check reply header
	if(replyheader.rcode != 0){
		printf("Error: rcode vale %d\n", replyheader.rcode);
		return 0;
	}

	uint16_t ancount = ntohs(replyheader.ancount);		//convert the unsigned short integer netshort from network byte
	if(ancount == 0){
		printf("Did not recieve any answers\n");
	}
	int curpos = 12;
	curpos = printquery(curpos, recvbuf);
	for(int i=0 i<ancount; i++){
		printf("Answer %d\n", i);
		curpos = printreply(curpos, recvbuf);
	}



}	
