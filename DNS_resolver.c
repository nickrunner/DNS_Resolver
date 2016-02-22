#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <iostream>
#include <vector>

#define BUF_SIZE 512
#define TYPE_A 1
#define CLASS_IN 1
#define AUTH_LENGTH 16

using namespace std;

//DNS header
typedef struct dnshdr{
	uint16_t id;	//ID number
	uint8_t rd: 1;	//recursion bit
	uint8_t tc: 1;	//truncation bit
	uint8_t aa: 1;	//authoratative answer
	uint8_t opcode: 4;	//purpose of message
	uint8_t qr: 1;		//query resopnse flag
	uint8_t rcode: 4;	//response code
	uint8_t cd:1;		//checking disabled
	uint8_t ad:1;		//authenticated data
	uint8_t z:1;		
	uint16_t qcount;	//# of question entries
	uint16_t ancount;	//number of answer entries
	uint16_t authcount;
	uint16_t addcount;
}dnshdr;

typedef struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
}R_DATA;

typedef struct RES_RECORD
{
	unsigned char *name;
	//struct *R_DATA;
	unsigned char * fuck;
}RES_RECORD;

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

void get_ip(char* buf, int pos, int len, vector<string>& root_hints){
	int i=0;
	char tmp[5];
	string s;
	for(i=12; i<len; i++){

		sprintf(tmp, "%u", (unsigned char)buf[pos+i]);
		//printf("%s", tmp );
		s += tmp;
		//s += itoa(buf[pos+i]);
		if(i != len-1){
			s += '.';
		}
	}
	root_hints.push_back(s);
	cout << "test: " << s << endl;
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
	root_server_addr.sin_port = htons(53);
	root_server_addr.sin_addr.s_addr  = inet_addr("198.41.0.4");

	bind(sockfd, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));

	socklen_t dig_len = sizeof(dig_client_addr);

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
	//Check type and class
	if(buf[12+namelength+1] != TYPE_A){
		printf("Error: Wrong type\n");
		sendto(sockfd, buf, 16+namelength, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));
		return 0;
	}
	if(buf[12+namelength+3] != CLASS_IN){
		printf("Error: Wrong class\n");
		sendto(sockfd, buf, 16+namelength, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));
		return 0;
	}

	//Unset recursion bit
	recvhdr.rd = 0;
	memcpy(buf, &recvhdr, 12);
	//Forward to root server

	uint16_t answers = 0;

	while(answers == 0){

		sendto(sockfd, buf, 16+namelength, 0, (struct sockaddr*)&root_server_addr, sizeof(root_server_addr));
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
		uint16_t authcount = ntohs(replyheader.authcount);
		uint16_t addcount = ntohs(replyheader.addcount);
		if(ancount == 0){
			printf("Did not recieve any answers\n");
		}
		
		int pos = 12 + namelength + 4;
		
		if(authcount == 0){
			printf("Auth Count = 0\n");
		}
		for(int i=0; i<authcount; i++){
			//printf("\n\n\nauthoratative nameserver: %d \n\n", i);
			//print_buf(recvbuf, pos, AUTH_LENGTH);
			pos += AUTH_LENGTH;
		}
		vector<string> root_hints;
		for(int i=0; i<addcount; i++){
			printf("\n\n\nAdditional Resource: %d\n\n", i);
			get_ip(recvbuf, pos, AUTH_LENGTH, root_hints);
			pos += AUTH_LENGTH;
		}

		answers = ancount;
		if(answers == 0){
			//find better server to ask

			//update server address
			root_server_addr.sin_addr.s_addr  = inet_addr("");
		}

		break;
	}

	return 0;
}

