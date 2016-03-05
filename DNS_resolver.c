/***************************************************************
* Nick Schrock and Matt Lukas
* CIS 457 DNS Resolver
* 3/4/2016
*****************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <cstdlib> 


#define BUF_SIZE 512
#define TYPE_A 1
#define CLASS_IN 1
#define ADD_LENGTH 16
#define ipv4Len 4
#define ANSWER 1
#define NAME_SERVER 0
#define NOT_ANSWER 0
#define TYPE_LENGTH 2
#define CLASS_LENGTH 2
#define TTL_LENGTH 4
#define DATA_LENGTH_SIZE 2
#define NAME_LENGTH 2

using namespace std;


//DNS header
typedef struct dnshdr{
	uint16_t id;    //ID number
	uint8_t rd: 1;  //recursion bit
	uint8_t tc: 1;  //truncation bit
	uint8_t aa: 1;  //authoratative answer
	uint8_t opcode: 4;  //purpose of message
	uint8_t qr: 1;      //query resopnse flag
	uint8_t rcode: 4;   //response code
	uint8_t cd:1;       //checking disabled
	uint8_t ad:1;       //authenticated data
	uint8_t z:1;        
	uint16_t qcount;    //# of question entries
	uint16_t ancount;   //number of answer entries
	uint16_t authcount;
	uint16_t addcount;
}dnshdr;


typedef struct res_record{
	int rr_type;
	string name;
	uint16_t _type;
	uint16_t _class;
	unsigned int ttl;
	string ip;
	char resp[BUF_SIZE];
	time_t in_time;
}res_record;

void encodename(const char* src, char* dst){
  int i=0;
  int pos=0;
  while(src[i]!='\0'){
	if(src[i]=='.'){
		dst[pos]=i-pos;
		pos=i+1;
	} 
	else{
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
  //printf("\n\nName bytes: %x %x\n", buf[pos], buf[pos+1]);
  while(buf[pos]!=0){
	if((buf[pos]&0xC0)==0xC0){ //pointer
		//printf("\n\nFOUND POINTER\n\n");
	  if(ret==0){
	ret=(pos-start)+2;
	  }
	  pos = (u_int16_t)((buf[pos]&(~0xC0))<<8)+(u_int8_t)buf[pos+1];
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

string getname(int pos,char* buf){
  char name[256];
  int namelen = decodename(buf,pos,name);
  cout << "returning name " << name << endl;
  return name;
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
	ret = buf[rdLenIndex];

	return ret; //+ 2 + 2 + 2 + 4 + namelength;
}

/*
 * pos should be the start of a resource record 
 * l
  * root_hints is a vector of 19 addresses
	returns the position of the next section
 */



/*
 * returns an ipv4 answer if there is one, 0 else
*/
int get_answer(char* buf, int original_namelength, int numAnswers, vector<struct res_record>& cache, vector<string>& root_hints, int p_pos, int rr_type_p, string auth){
	string s;
	res_record tmp_record;
	int i=0;
	char tmp[5];
	int pos;
	if(p_pos == 0){
		pos = 12+original_namelength+4; //start of answer section
	}
	else{
		pos = p_pos;
	}
	int dataLen;
	printf("Original Name Length: %d\n\n", original_namelength);
	char temp[256];
	//Cache stuff
	if(rr_type_p == NAME_SERVER){
		tmp_record.name = auth;
		//cout << "thinks it's nameserver" << endl;
	}
	else{
		decodename(buf, 12, temp);
		std::string tmp_str(temp);
		tmp_record.name = tmp_str;
		//cout << "tmp_record.name " << tmp_record.name << endl;
		//cout << "thinks it's answer" << endl;
	}
	tmp_record.rr_type = rr_type_p;
	//pos should be the start of a resource record
	while(i < numAnswers){ //loop until find ipv4 answer
		
		dataLen = get_data_length(NAME_LENGTH, pos, buf);
		//Jump to type
		pos += NAME_LENGTH;
		tmp_record._type = buf[pos+1];          //Only using lower byte

		//Jump to Class
		pos += TYPE_LENGTH;
		tmp_record._class = buf[pos+1];

		//Jump to TTL
		pos += CLASS_LENGTH;
		memcpy(&tmp_record.ttl, &buf[pos], TTL_LENGTH);
		tmp_record.ttl = ntohl(tmp_record.ttl);
		pos += TTL_LENGTH;

		//Jump to IP Address
		pos += DATA_LENGTH_SIZE;
		for(int j=pos; j<pos+dataLen; j++){
			sprintf(tmp, "%u", (unsigned char)buf[j]);
			tmp_record.ip += tmp;
			if(j != pos+3){
				tmp_record.ip += '.';
			}
		}
		pos += dataLen;
		//cout << "IP Address: " << tmp_record.ip << endl << endl;

		memcpy(tmp_record.resp, buf, BUF_SIZE);

		if(dataLen == ipv4Len){
			root_hints.push_back(tmp_record.ip);
			time(&tmp_record.in_time); 
			cache.push_back(tmp_record);
		}

		//for(int k=0; k<BUF_SIZE; k++){
			//printf("\n%x   %x", (unsigned int)buf[k], tmp_record.resp[k]);
		//}

		//Reset Struct
		tmp_record.ip = "";
		tmp_record._type = 0;
		tmp_record._class = 0;
		tmp_record.ttl = 0;
		memset(tmp_record.resp, 0, BUF_SIZE);

		i++;
	}
	return pos;
}

void print_cache(vector<struct res_record>& cache){
	for(int i=0; i<cache.size(); i++){
		if(cache[i].rr_type == ANSWER){
			cout << "Cacheing Answer " << i << endl;
		}
		else{
			cout << "Cacheing Nameserver" << i << endl;
		}
		cout << "Name: " << cache[i].name << endl;
		cout << "RR type: " << cache[i].rr_type << endl;
		cout << "Type: " << cache[i]._type << endl;
		cout << "Class: " << cache[i]._class << endl;
		cout << "TTL: " << cache[i].ttl << endl;
		cout << "IP Address: " << cache[i].ip << endl;
		cout << "In Time: " << cache[i].in_time << endl << endl;
	}
}

//Returns true if IPv4 answer exists in cache
//Sets cache_record to record with matching name
//If return is false but cache_record 
bool check_cache(string name, vector<struct res_record>& cache, res_record& cache_record){
	bool answer_found = false;
	cache_record.rr_type = -1;
	for(int i=0; i<cache.size(); i++){
		if(name.compare(cache[i].name) == 0){
			cache_record = cache[i];
			if(cache[i].rr_type == ANSWER){
				answer_found = true;
				break;
			}
		}
	}
	return answer_found;
}


void update_ttl(vector<struct res_record>& cache){
	printf("\n\nUpdating TTL\n\n");
	time_t current_time;
	time(&current_time);
	time_t elapsed_time = 0;
	int pos;
	int ttl;
	vector<int> deletions;
	for(int i=0; i<cache.size(); i++){
		pos = 16 + NAME_LENGTH + TYPE_LENGTH + CLASS_LENGTH;
		elapsed_time = 0;
		elapsed_time = current_time - cache[i].in_time;
		cache[i].ttl = cache[i].ttl - elapsed_time;
		if(cache[i].ttl > current_time){
			cache[i].ttl = 0;
		}
		pos += print_reply(cache[i].resp);
		//printf("\n\nnum Answers: %x\n", cache[i].resp[7]);
		for(int j=0; j<cache[i].resp[7]; j++){
			ttl = ntohl(cache[i].ttl);
			if(cache[i].rr_type = ANSWER){
				if(cache[i]._type == TYPE_A){
					memcpy(&cache[i].resp[pos], &ttl, TTL_LENGTH);
				}
			}
			pos = pos + NAME_LENGTH + TYPE_LENGTH + CLASS_LENGTH +TTL_LENGTH + 4 + DATA_LENGTH_SIZE;
		}
		//cache[i].resp[]
		if(cache[i].ttl <= 0){			
			 deletions.push_back(i);
		}
		time(&cache[i].in_time);
	}
	for(int j=0; j<deletions.size(); j++){
		cache.erase(cache.begin()+deletions[j]);
		for(int k=j; k<deletions.size(); k++){
			deletions[k]--; 
		}
	}
}


int main(int argc, char** argv){

	//map<std::string, struct res_record> answer_cache;

	vector<struct res_record> cache;
	
	int port;
	printf("Please enter a port: ");
	scanf(" %d", &port);
	if ( port < 0 ){
		printf("Invalid port number\n");
	}

	printf("Listening on port %d\n", port);

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
	char auth_name[256];
	//Receive data from dig
	
	while(1){
		//reset variables
		root_server_addr.sin_addr.s_addr = inet_addr("198.41.0.4");
		memset(buf, 0, BUF_SIZE);

		//wait for next query
		printf("Waiting for query...\n");
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
		if(buf[12+original_namelength+1] != TYPE_A || 
			buf[12+original_namelength+3] != CLASS_IN){
			
			printf("Error: Wrong type or class\n");
			recvhdr.qr = 1;
			recvhdr.rcode = 5;
				memcpy(buf, &recvhdr, 12);
			
			sendto(sockfd, buf, 16+original_namelength, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));
		}
		else{

			//Unset recursion bit
			recvhdr.rd = 0;
			memcpy(buf, &recvhdr, 12);
			//Forward to root server

			uint16_t answers = 0;
			char recvbuf [BUF_SIZE];
			bool cache_answers;
			char temp[256];
			res_record cache_record;
			cache_record.rr_type = -1;
			memset(temp, 0, 256);
			decodename(buf, 12, temp);
			std::string tmp_str(temp);
			int prevPeriod = 0;
			update_ttl(cache);
			while(cache_record.rr_type == -1 && prevPeriod != -1){
				prevPeriod = tmp_str.find(".");
				cache_answers = check_cache(tmp_str, cache, cache_record);
				tmp_str = tmp_str.substr(tmp_str.find(".")+1);
			}

			answers = (int)cache_answers;
			cout << endl << endl << "Cache answers: " << answers << endl << endl;
			while(answers == 0){

				//If intermediate server is found change the root server address
				if(cache_record.rr_type == NAME_SERVER){
						printf("\n\n FOUND INTERMEDIATE SERVER!!!\n\n");
						root_server_addr.sin_addr.s_addr  = inet_addr(cache_record.ip.c_str());
						cache_record.ip = "";
						cache_record.rr_type = -1;
				}	
				//If we did NOT find and answer in the cache
				//Would still enter if found an intermediate server

				//Sending to Root Server
				sendto(sockfd, buf, 16+original_namelength, 0, (struct sockaddr*)&root_server_addr, sizeof(root_server_addr));
				

				socklen_t root_len = sizeof(root_server_addr);
				recvfrom(sockfd, recvbuf, BUF_SIZE, 0, (struct sockaddr*)&root_server_addr, &root_len);
				original_namelength = print_reply(recvbuf);
				//NAME_LENGTHNAME_LENGTH = 2;   
				//Create Reply DNS header and copy data from buffer
				dnshdr replyheader;
				
				memcpy(&replyheader, recvbuf, 12);

				//Error check reply header
				if(replyheader.rcode != 0){
					printf("Error: rcode vale %d\n", replyheader.rcode);
					return 0;
				}

				answers = ntohs(replyheader.ancount);       //convert the unsigned short integer netshort from network byte
				uint16_t authcount = ntohs(replyheader.authcount);
				uint16_t addcount = ntohs(replyheader.addcount);
				if(answers == 0){
					printf("Did not recieve any answers\n");
				}
				
				if(answers == 0){
					//find better server to ask
					int pos = 12 + original_namelength + 4;
					//End of Question. Start of Auth Nameservers
					if(authcount == 0){
						printf("Auth Count = 0\n");
					}
					//Grab name 
					int test = decodename(recvbuf, pos, auth_name);
					string auth(auth_name);
					
					printf("\n\nAUTH NAME: %s Length = %d", auth_name, test);
					for(int i=0; i<authcount; i++){
						pos += (get_data_length(NAME_LENGTH, pos, recvbuf) + 10 + NAME_LENGTH);			
					}
					vector<string> root_hints;
					printf("\n\n\nAdditional Record:\n\n");
					pos = get_answer(recvbuf, original_namelength, addcount, cache, root_hints, pos, NAME_SERVER, auth);
					cout << "called nameserver" << endl;
					
					//print ip addresses found  
					for(int i=0; i<root_hints.size(); i++){
						cout << root_hints[i] << endl;
					}

					//update server address
					
					
					root_server_addr.sin_addr.s_addr  = inet_addr(root_hints[0].c_str());
					

					memset(recvbuf, 0, BUF_SIZE);
				}
			}

			if(cache_answers){
				cout << "Got cached answer" << endl;
				cout << "Name: " << cache_record.name << endl;
				cout << "RR type: " << cache_record.rr_type << endl;
				cout << "Type: " << cache_record._type << endl;
				cout << "Class: " << cache_record._class << endl;
				cout << "TTL: " << cache_record.ttl << endl;
				cout << "IP Address: " << cache_record.ip << endl << endl;

				
				memcpy(recvbuf, &cache_record.resp, BUF_SIZE);
				uint16_t id = recvhdr.id;
				memcpy(recvbuf, &id, 2);
				
				printf("Decimal: %d Hex: %x\n", id, id);
				
			}
			else{
				

				printf("\n\n");
				vector<string> server_IP;
				get_answer(recvbuf, original_namelength, answers, cache, server_IP, 0, ANSWER, "");
				
				//cache the answers

				print_cache(cache);

				cout << "called answer" << endl;
				
			}
			
			sendto(sockfd, recvbuf, BUF_SIZE, 0, (struct sockaddr*)&dig_client_addr, sizeof(dig_client_addr));

		}
	}   
	return 0;
}

