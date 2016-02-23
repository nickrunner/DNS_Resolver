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
#define ADD_LENGTH 16
#define ipv4Len 4
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


//pos should be the begining of the a resource record
int get_data_length(int namelength, int pos, char* buf){
	uint16_t ret=0;
	//namelength /= 8;
	//where the resource data length is in the buffer
	int rdLenIndex = pos + namelength + 9;
	//memcpy(&ret, &buf[rdLenIndex], );
	ret = buf[rdLenIndex];
	printf("namelength: %d\n",namelength);
	printf("data length: %d\n\n", ret);
	return ret; //+ 2 + 2 + 2 + 4 + namelength;
}

/*
 * pos should be the start of a resource record 
 * l
  * root_hints is a vector of 19 addresses
    returns the position of the next section
 */
int get_ip(char* buf, int pos, int namelength, int original_namelength,
							vector<string>& root_hints,int numRecords){
	int j=0;
	char tmp[5];
	string s;
	int dataLen = get_data_length(namelength, pos, buf);
	printf("Data lengthip: %d\n\n", dataLen);
	printf("Original Name Lengthip: %d\n\n", original_namelength);
    printf("numRecords is %d\n", numRecords);
	//pos should be the start of a resource record
	while(j < numRecords){ 
		s.clear();
		pos = pos + namelength+10 + dataLen;
		dataLen = get_data_length(namelength, pos, buf);
		//found ipv4 answer, or there was no ipv4 answer
		if(dataLen == ipv4Len){ //there was an ipv4 answer, grab and push
		    printf("found ipv4 in additional rescources\n");	
			int startRdata = pos + namelength + 10;
			for(int i=startRdata; i<startRdata+4; i++){
				sprintf(tmp, "%u", (unsigned char)buf[i]);
				s += tmp;
				if(i != startRdata+3){
					s += '.';
				}
			}
			//cout << " it is " << s << endl;
			root_hints.push_back(s); //push ip address to vector
		}
		j = j + 1;
    }
    return pos;
	
}


/*
 * returns an ipv4 answer if there is one, 0 else
*/
string get_answer(char* buf, int original_namelength, int namelength, int numAnswers){
	string s;
	int i;
	char tmp[5];
	int pos = 12+original_namelength+4; //start of answer section
	int dataLen = get_data_length(namelength, pos, buf);
	printf("Data length: %d\n\n", dataLen);
	printf("Original Name Length: %d\n\n", original_namelength);

	//pos should be the start of a resource record
	while(dataLen != ipv4Len && i < numAnswers){ //loop until find ipv4 answer
		pos = pos + namelength+10 + dataLen;
		dataLen = get_data_length(namelength, pos, buf);
		i++;
	}
	//found ipv4 answer, or there was no ipv4 answer
	if(dataLen == ipv4Len){ //there was an ipv4 answer, grab and return it	
		int startRdata = pos + namelength + 10;
		for(i=startRdata; i<startRdata+4; i++){
			sprintf(tmp, "%u", (unsigned char)buf[i]);
			s += tmp;
			if(i != startRdata+3){
				s += '.';
			}
		}
		
		return s;
	}
	else{
		cout << "no IPV4 answers were found" << endl;

	}
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

	int original_namelength = print_reply(buf);
	//Check type and class
	if(buf[12+original_namelength+1] != TYPE_A){
		printf("Error: Wrong type\n");
		sendto(sockfd, buf, 16+original_namelength, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));
		return 0;
	}
	if(buf[12+original_namelength+3] != CLASS_IN){
		printf("Error: Wrong class\n");
		sendto(sockfd, buf, 16+original_namelength, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));
		return 0;
	}

	//Unset recursion bit
	recvhdr.rd = 0;
	memcpy(buf, &recvhdr, 12);
	//Forward to root server

	uint16_t answers = 0;
	char recvbuf [BUF_SIZE];
	int namelength;
	while(answers == 0){

		sendto(sockfd, buf, 16+original_namelength, 0, (struct sockaddr*)&root_server_addr, sizeof(root_server_addr));
		
		socklen_t root_len = sizeof(root_server_addr);
		recvfrom(sockfd, recvbuf, BUF_SIZE, 0, (struct sockaddr*)&root_server_addr, &root_len);
		original_namelength = print_reply(recvbuf);
		namelength = 2;	
		//Create Reply DNS header and copy data from buffer
		dnshdr replyheader;
		
		memcpy(&replyheader, recvbuf, 12);

		//Error check reply header
		if(replyheader.rcode != 0){
			printf("Error: rcode vale %d\n", replyheader.rcode);
			return 0;
		}

		answers = ntohs(replyheader.ancount);		//convert the unsigned short integer netshort from network byte
		uint16_t authcount = ntohs(replyheader.authcount);
		uint16_t addcount = ntohs(replyheader.addcount);
		if(answers == 0){
			printf("Did not recieve any answers\n");
		}
	
		if(answers == 0){
			//find better server to ask
			int pos = 12 + original_namelength + 4;
			//namelength /= 8;
			if(authcount == 0){
				printf("Auth Count = 0\n");
			}
			for(int i=0; i<authcount; i++){
				//printf("\n\n\nauthoratative nameserver: %d \n\n", i);
				//print_buf(recvbuf, pos, AUTH_LENGTH);
				pos += (get_data_length(namelength, pos, recvbuf) + 10 + namelength);
			}
			vector<string> root_hints;
			printf("\n\n\nAdditional Resource:\n\n");
			pos = get_ip(recvbuf, pos, namelength, original_namelength, root_hints, addcount);
            //print ip addresses found  
			for(int i=0; i<root_hints.size(); i++){
				cout << root_hints[i] << endl;
			}

			//update server address
			root_server_addr.sin_addr.s_addr  = inet_addr(root_hints[0].c_str());
			memset(recvbuf, 0, BUF_SIZE);
		}

	}
	printf("\n\n");
	string an = get_answer(recvbuf, original_namelength, namelength, answers);
	cout << "Answer: " << an << endl;

	sendto(sockfd, recvbuf, BUF_SIZE, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));
	
	return 0;
}

