#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <fcntl.h>

#include <ctime>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <cstdlib>
#include <queue>
using namespace std;
#include "cs3516sock.h"
#include "trie.h"

//
// Constants and macros
//

#define PAYLOAD_LEN 1000
#define PACKET_LEN sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_LEN

//
// Types
//

typedef enum {
	TTL_EXPIRED = 0,
	MAX_SENDQ_EXCEEDED,
	NO_ROUTE_TO_HOST,
	SENT_OKAY
} logStatusCode;

char g_statusStrings[4][32] = {
	"TTL_EXPIRED",
	"MAX_SENDQ_EXCEEDED",
	"NO_ROUTE_TO_HOST",
	"SENT_OKAY"
};

typedef enum {
	GLOBAL_CONFIG = 0,
	ROUTER_ID,
	HOST_ID,
	ROUTER_ROUTER_LINK,
	ROUTER_HOST_LINK
} configType;


struct router {
	int id; //id of router
	u_int32_t realIp; //real IP address of router (host byte order)
};

struct endhost {
	int id; //id of end host
	u_int32_t realIp; //real IP address of host (host byte order)
	u_int32_t overlayIp; //overlay IP address of host (host byte order)
};

struct routerlink {
	//router IDs of connected routers
	int router1Id;
	int router2Id;
	//send delay times of connected routers
	struct timeval router1SendDelay;
	struct timeval router2SendDelay;
	struct timeval lastSendTime;
};

struct hostlink {
	int routerId;
	struct timeval routerSendDelay;
	u_int32_t overlayPrefix; //overlay IP address prefix (host byte order)
	int significantBits; //significant bits in the overlay IP address prefix
	int endHostId;
	struct timeval hostSendDelay;
	struct timeval lastSendTime;
};

struct packet {
	u_int8_t buffer[PACKET_LEN];
	int length;
};

//
// Function declarations
//

void readConfig();
bool isRouter(void);
void readOverlayHeaders(u_int8_t *buffer, struct iphdr **iphPointer, struct udphdr **udphPointer, u_int8_t payload[PAYLOAD_LEN]);
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen);
int timeval_subtract(struct timeval *result, struct timeval tv1, struct timeval tv0);
void msToTimeval(long int ms, struct timeval *result);
u_int32_t strIPtoBin(const char *strIP);
string binIPtoStr(u_int32_t naddr);
u_int32_t realIPfromID(int id);
void beAHost(void);
void setBlocking(bool block);
int sendPacket(int destID, u_int8_t packetBuffer[PACKET_LEN], int packetLen);
void beARouter(void);
void printPacket(u_int8_t packet[PACKET_LEN], int length);
void logPacket(struct iphdr *overlayIPHdr, logStatusCode code, u_int32_t nextHop = 0);

//
// Globals
//

fstream g_logfile;
u_int8_t g_TTL = 3;
u_int32_t g_IP = 0;  //network byte order
unsigned int g_queueLength = 0;
int g_defaultTTL = 0;
int g_thisID = 0;
bool g_isRouter;
vector<router> g_routers;
vector<endhost> g_endhosts;
vector<routerlink> g_routerlinks;
vector<hostlink> g_hostlinks;
Trie g_routes;
int g_sock;

//
// Function definitions
//

int main(int argc, char *argv[]) {
	readConfig();
	if(isRouter()) {
		beARouter();
	}
	else {
		beAHost();
	}
	return 0;
}

void readConfig() {
	fstream configfile;
	long int tempDelayTime;
	configfile.open("config.txt", fstream::in);
	if(!configfile.is_open()) {
		cerr<<"Unable to open config file."<<endl;
		return;
	}
	
	while(configfile.good()) {
		char temp[128];
		configfile.getline(temp, 127);
		istringstream line(temp);
		int type;
		string ip;
		line >> type;
		switch(type) {
			case GLOBAL_CONFIG:
				line >> g_queueLength;
				line >> g_defaultTTL;
				break;
			case ROUTER_ID:
				router r;
				line >> r.id;
				line >> ip;
				r.realIp = ntohl(strIPtoBin(ip.c_str()));
				g_routers.push_back(r);
				break;
			case HOST_ID:
				endhost h;
				line >> h.id;
				line >> ip;
				h.realIp = ntohl(strIPtoBin(ip.c_str()));
				line >> ip;
				h.overlayIp = ntohl(strIPtoBin(ip.c_str()));
				g_endhosts.push_back(h);
				break;
			case ROUTER_ROUTER_LINK:
				routerlink link;
				line >> link.router1Id;
				line >> tempDelayTime;
				msToTimeval(tempDelayTime, &(link.router1SendDelay));
				line >> link.router2Id;
				line >> tempDelayTime;
				msToTimeval(tempDelayTime, &(link.router2SendDelay));
				g_routerlinks.push_back(link);
				link.lastSendTime.tv_sec = 0;
				link.lastSendTime.tv_usec = 0;
				break;
			case ROUTER_HOST_LINK:
				hostlink hlink;
				string prefix;
				line >> hlink.routerId;
				line >> tempDelayTime;
				msToTimeval(tempDelayTime, &(hlink.routerSendDelay));
				line >> prefix;
				size_t slash = prefix.find_first_of("/");
				hlink.overlayPrefix = ntohl(strIPtoBin(prefix.substr(0, slash).c_str()));
				hlink.significantBits = atoi(prefix.substr(slash+1).c_str());
				line >> hlink.endHostId;
				line >> tempDelayTime;
				msToTimeval(tempDelayTime, &(hlink.hostSendDelay));
				g_hostlinks.push_back(hlink);
				hlink.lastSendTime.tv_sec = 0;
				hlink.lastSendTime.tv_usec = 0;
				//add link to routing trie
				bitset<32> overlayPrefixBits(hlink.overlayPrefix);
				g_routes.insertNode(overlayPrefixBits, hlink.significantBits, hlink.routerId);
				break;
		}
	}
}

bool isRouter(void) {
	vector<router>::iterator routerIt;
	vector<endhost>::iterator hostIt;
	u_int32_t ip;
	struct sockaddr_in *saddr;
	struct ifaddrs *addressList;
	struct ifaddrs *curAddr;
	
	//get IP addresses
	getifaddrs(&addressList);
	curAddr = addressList;
	
	while(curAddr != NULL) {
		saddr = (struct sockaddr_in*)curAddr->ifa_addr;
		ip = ntohl(saddr->sin_addr.s_addr);
		//find the IP address in either the router list or host list
		for(routerIt = g_routers.begin(); routerIt < g_routers.end(); routerIt++) {
			if((*routerIt).realIp == ip) {
				g_thisID = (*routerIt).id;
				g_isRouter = true;
				g_IP = htonl(ip);
				freeifaddrs(addressList);
				return true;
			}
		}
		for(hostIt = g_endhosts.begin(); hostIt < g_endhosts.end(); hostIt++) {
			if((*hostIt).realIp == ip) {
				g_thisID = (*hostIt).id;
				g_isRouter = false;
				g_IP = htonl(ip);
				freeifaddrs(addressList);
				return false;
			}
		}
		curAddr = curAddr->ifa_next;
	}
	cerr<<"Unable to find IP address in configuration file."<<endl;
	throw(0);
}

//read the overlay headers into ip and udp struct, print out info from them
void readOverlayHeaders(u_int8_t *buffer, struct iphdr **iphPointer, struct udphdr **udphPointer, u_int8_t payload[PAYLOAD_LEN]) {
	*iphPointer = (struct iphdr *)buffer;
	struct iphdr *iph = *iphPointer;
	
	//check for UDP
	if(iph->protocol == IPPROTO_UDP) {
		*udphPointer = (udphdr *)(buffer+(iph->ihl)*4);
		struct udphdr *udph = *udphPointer;
		
		cout << "Source port: " << ntohs(udph->source) << endl
		     << "Dest port: " << ntohs(udph->dest) << endl
			 << "Length: " << ntohs(udph->len) << endl;
		//get payload
		memcpy(payload, buffer+28, ntohs(udph->len)-8);
	}
}

//fills in the given buffer with overlay headers and data
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen) {
	struct iphdr iph;
	struct udphdr udph;
	
	bzero(&iph, sizeof(iph));
	iph.version = 4;
	iph.ihl = 5;
	iph.tot_len = htons(sizeof(iph) + sizeof(udph) + payloadLen);
	iph.ttl = g_TTL;
	iph.protocol = IPPROTO_UDP;
	iph.saddr = g_IP;
	iph.daddr = destIP;
	
	bzero(&udph, sizeof(udph));
	udph.source = htons(MYPORT);
	udph.dest = htons(MYPORT);
	udph.len = htons(sizeof(udph) + payloadLen);
	
	memcpy(buffer, &iph, sizeof(iph));
	memcpy(buffer + sizeof(iph), &udph, sizeof(udph));
	memcpy(buffer + sizeof(iph) + sizeof(udph), payload, payloadLen);
}

//subtract tv0 from tv1, store result in result (if not null)
//if tv1 > tv0, return 1
//if tv1 < tv0, return -1
//if tv1 = tv0, return 0
int timeval_subtract(struct timeval *result, struct timeval tv1, struct timeval tv0) {
	long int diffSeconds = (tv1.tv_sec - tv0.tv_sec);
	long int diffMicroSeconds = (tv1.tv_usec - tv0.tv_usec);
	if(diffMicroSeconds < 0) {
		diffSeconds--;
		diffMicroSeconds += 1000000;
	}
	if(result != NULL) {
		result->tv_sec = diffSeconds;
		result->tv_usec = diffMicroSeconds;
	}
	if(diffSeconds > 0) {
		return 1;
	}
	else if(diffSeconds < 0) {
		return -1;
	}
	else if(diffMicroSeconds > 0) {
		return 1;
	}
	else if(diffMicroSeconds < 0) {
		return -1;
	}
	else {
		return 0;
	}
}

void msToTimeval(long int ms, struct timeval *result) {
	result->tv_sec = ms / 1000;
	result->tv_usec = (ms % 1000) * 1000;
}

//converts a string IP address to a network byte order u_int32_t
u_int32_t strIPtoBin(const char *strIP) {
	int octet0, octet1, octet2, octet3;
		
	sscanf(strIP, "%d.%d.%d.%d", &octet0, &octet1, &octet2, &octet3);
	return (octet3&0xFF)<<24 | (octet2&0xFF) << 16 | (octet1&0xFF) << 8 | (octet0&0xFF);
}

//Get an IP address string from a 32-bit integer from the IP header (assume network byte order)
string binIPtoStr(u_int32_t naddr) {
	char ipAddr[16] = "";
	u_int32_t haddr;
	haddr = ntohl(naddr);
	sprintf(ipAddr, "%d.%d.%d.%d", (haddr&0xFF000000)>>24, (haddr&0xFF0000)>>16, (haddr&0xFF00)>>8, haddr&0xFF);
	return string(ipAddr);
}

//network byte order
u_int32_t realIPfromID(int id) {
	vector<router>::iterator routerIt;
	vector<endhost>::iterator hostIt;

	for(routerIt = g_routers.begin(); routerIt < g_routers.end(); routerIt++) {
		if((*routerIt).id == id) {
			return htonl((*routerIt).realIp);
		}
	}
	for(hostIt = g_endhosts.begin(); hostIt < g_endhosts.end(); hostIt++) {
		if((*hostIt).id == id) {
			return htonl((*hostIt).realIp);
		}
	}
	return 0;
}

void beAHost(void) {	
	u_int8_t payload[PAYLOAD_LEN] = "Hello world!";
	u_int8_t rxPayload[PAYLOAD_LEN] = "";
	u_int8_t txBuffer[PACKET_LEN];
	u_int8_t rxBuffer[PACKET_LEN] = "";
	u_int32_t router = strIPtoBin("192.168.0.8");
	u_int32_t destination = strIPtoBin("192.168.0.10");
	int payloadLen = strlen((char *)payload);
	
	g_sock = create_cs3516_socket(true);
	
	createPacket(txBuffer, destination, payload, payloadLen);
	printPacket(txBuffer, 28 + payloadLen);
	cs3516_send(g_sock, (char *)txBuffer, 28 + payloadLen, router);
	
	cs3516_recv(g_sock, (char *)rxBuffer, PACKET_LEN);
	struct iphdr *iph;
	struct udphdr *udph;
	readOverlayHeaders(rxBuffer, &iph, &udph, rxPayload);
	
	cout<<"Message received."<<endl;
	cout<<(char *)rxPayload<<endl;
}

void setBlocking(bool block) {
	int flags = fcntl(g_sock, F_GETFL);
	fcntl(g_sock, F_SETFL, block ? flags & ~O_NONBLOCK : flags | O_NONBLOCK);
}


//tries to send packet to destination ID
//if successful, returns 1
//if delay time has not elapsed, returns 0
//if unable to find host, returns -1
int sendPacket(int destID, u_int8_t packetBuffer[PACKET_LEN], int packetLen) {
	u_int32_t destAddr = 0;
	vector<hostlink>::iterator hlinkIt;
	vector<routerlink>::iterator rlinkIt;
	struct timeval curTime;
	struct timeval difTime;
	struct timeval *lastTime;
	struct timeval delayTime;
	
	if(g_isRouter) {
		//find applicable link
		for(hlinkIt = g_hostlinks.begin(); hlinkIt < g_hostlinks.end(); hlinkIt++) {
			if((*hlinkIt).endHostId == destID && (*hlinkIt).routerId == g_thisID) {
				destAddr = realIPfromID(destID);
				lastTime = &((*hlinkIt).lastSendTime);
				delayTime = (*hlinkIt).routerSendDelay;
			}
		}
		for(rlinkIt = g_routerlinks.begin(); rlinkIt < g_routerlinks.end(); rlinkIt++) {
			if((*rlinkIt).router1Id == destID && (*rlinkIt).router2Id == g_thisID) {
				destAddr = realIPfromID(destID);
				lastTime = &((*rlinkIt).lastSendTime);
				delayTime = (*rlinkIt).router2SendDelay;
			}
			else if((*rlinkIt).router2Id == destID && (*rlinkIt).router1Id == g_thisID) {
				destAddr = realIPfromID(destID);
				lastTime = &((*rlinkIt).lastSendTime);
				delayTime = (*rlinkIt).router1SendDelay;
			}
		}
		if(destAddr == 0) {
			return -1;
		}
		gettimeofday(&curTime, NULL);
		timeval_subtract(&difTime, curTime, *lastTime);
		if(timeval_subtract(NULL, delayTime, difTime) == 1) {
			return 0;
		}
		else {
			//need to make the socket blocking again so it's guaranteed to send when called
			setBlocking(true);
			cs3516_send(g_sock, (char *)packetBuffer, packetLen, destAddr);
			gettimeofday(lastTime, NULL);
			return 1;
		}
	}
	else {
		return 7;
	}
}

void beARouter(void) {
	struct iphdr *iph;
	struct udphdr *udph;
	u_int32_t fwdAddr;
	u_int8_t packetBuffer[PACKET_LEN] = "";
	u_int8_t payload[PAYLOAD_LEN] = "";
	packet *pkt;
	queue<packet*> packetQ;
	int bytesReceived;
	int packetSendResult;
	cout<<"Being a router. Route route!"<<endl;
	
	g_logfile.open("ROUTER_control.txt", fstream::out | fstream::app);
	if(!g_logfile.is_open()) {
		cerr<<"Unable to open logfile."<<endl;
		return;
	}
	
	g_sock = create_cs3516_socket(false);
	
	while(1) {
		setBlocking(false);
		bytesReceived = cs3516_recv(g_sock, (char *)packetBuffer, PACKET_LEN);
		if(bytesReceived > 0) {
			readOverlayHeaders(packetBuffer, &iph, &udph, payload);
			
			//handle ttl
			iph->ttl-=1;
			if(iph->ttl <= 0) {
				//drop packet
				logPacket(iph, TTL_EXPIRED);
				continue;
			}
			
			if(packetQ.size() >= g_queueLength) {
				//drop packet
				logPacket(iph, MAX_SENDQ_EXCEEDED);
				continue;
			}
			
			//add packet to queue
			pkt = (packet*)malloc(sizeof(packet));
			memcpy(pkt->buffer, packetBuffer, PACKET_LEN);
			pkt->length = bytesReceived;
			packetQ.push(pkt);
		}
		
		fwdAddr = strIPtoBin("192.168.0.10"); //todo
		
		//try to send a packet on the queue
		if(packetQ.size() > 0) {
			packetSendResult = sendPacket(4, packetQ.front()->buffer, packetQ.front()->length);
			if(packetSendResult == 1) {
				logPacket(iph, SENT_OKAY, fwdAddr);
				packetQ.pop();
			}
			else if(packetSendResult == -1) {
				logPacket(iph, NO_ROUTE_TO_HOST);
				packetQ.pop();
			}
			else if(packetSendResult == 0) {
				//delay has not passed - wait
			}
		}
	}
}

void printPacket(u_int8_t packet[PACKET_LEN], int length) {
	for(int i = 0; i < length; i++) {
		printf("%02hX ", packet[i]);
		if((i % 4) == 3) {
			printf("\n");
		}
	}
}

//log the packet with the given overlay IP header and status code
//nextHop is only necessary is code == SENT_OKAY
void logPacket(struct iphdr *overlayIPHdr, logStatusCode code, u_int32_t nextHop) {
	time_t timeVal = time(NULL);
	g_logfile<<timeVal<<" "
		<<binIPtoStr(overlayIPHdr->saddr)<<" " //source address
		<<binIPtoStr(overlayIPHdr->daddr)<<" " //destination address
		<<ntohs(overlayIPHdr->id)<<" " //IP_IDENT
		<<g_statusStrings[code]; //status code
	if(code == SENT_OKAY) {
		g_logfile<<" "<<binIPtoStr(nextHop); //next hop
	}
	g_logfile<<endl;
	return;
}