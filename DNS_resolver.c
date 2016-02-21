#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define BUF_SIZE 512
#define TYPE_A 1
#define CLASS_IN 1

//DNS header
typedef struct dnshdr{
	uint16_t id;	//ID number
	uint8_t rd: 1;	//recursion bit
	uint8_t tc: 1;	//truncation bit
	uint8_t aa: 1;	//authoratative answer
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
}dnshdr;

int decodename(char* buf, int pos, char* dst){
  int start=pos;
  int ret=0;
  int j=0;
  int i=0;
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
      for(i=0; i<len; i++){
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

int printquery(int pos,char* buf){
  char name[256];
  int namelen = decodename(buf,pos,name);
  int dnstype = buf[pos+namelen+1];
  int dnsclass = buf[pos+namelen+3];
  printf("Query: %s\t%d\t%d\n",name,dnstype,dnsclass);
  return pos+namelen+4;
}

int print_reply(char* buf){
	printf("recieved from client: \n" );
	char name[256];
	int namelen = decodename(buf, 12, name);
	int dnstype = buf[12+namelen+1];
	int dnsclass = buf[12+namelen+3];
	printf("Query: %s\t%d\t%d\n", name, dnstype, dnsclass);
	return namelen;
	
}

int main(int argc, char** argv){
	int port = 9875;

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if(sockfd<0){
		  printf("There was an arror creating the socket\n") ;
		  return 1;
		}

	struct sockaddr_in dig_client_addr;
	struct sockaddr_in root_server_addr;

	dig_client_addr.sin_family = AF_INET;
	dig_client_addr.sin_port = htons(port);
	dig_client_addr.sin_addr.s_addr = INADDR_ANY;

	root_server_addr.sin_family = AF_INET;
	root_server_addr.sin_port = htons(port);
	root_server_addr.sin_addr.s_addr  = inet_addr("8.8.8.8");

	bind(sockfd, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));

	int dig_len = sizeof(dig_client_addr);

	char buf[BUF_SIZE];
	//Receive data from dig

	recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr*)&dig_client_addr, &dig_len);
	int i=0;
	
	
	dnshdr recvhdr;
	memcpy(&recvhdr, buf, 12);
	if(recvhdr.rcode!=0){
		printf("error\n");
	}
	printf("rcode status: %d\n", recvhdr.rcode);
	int namelength = print_reply(buf);

	//Unset recursion bit
	//recvhdr.rd = 1;

	//Forward to root server

	bind(sockfd, (struct sockaddr*)&root_server_addr, sizeof(root_server_addr));
	sendto(sockfd, buf, 16+namelength, 0, (struct sockaddr*)&root_server_addr, sizeof(root_server_addr));
	//memset(buf,0,BUF_SIZE);
	char recvbuf [BUF_SIZE];
	socklen_t root_len = sizeof(root_server_addr);
	recvfrom(sockfd, recvbuf, BUF_SIZE, 0, (struct sockaddr*)&root_server_addr, &root_len);
	print_reply(recvbuf);
		
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
	for(int i=0; i<ancount; i++){
		printf("Answer %d\n", i);
		//curpos = printreply(curpos, recvbuf);
	}
}

