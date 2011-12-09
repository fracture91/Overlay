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
#include <map>
using namespace std;
#include "cs3516sock.h"
#include "trie.h"

//
// Constants and macros
//

#define PAYLOAD_LEN 1000
#define HEADERS_LEN (sizeof(struct iphdr) + sizeof(struct udphdr))
#define PACKET_LEN (HEADERS_LEN + PAYLOAD_LEN)

#define DEBUG 0

#if DEBUG
#define DEBUGF(format, ...) printf(format, ##__VA_ARGS__)
#else
#define DEBUGF(format, ...)
#endif

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
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen, u_int16_t sport, u_int16_t dport, u_int16_t seq);
int timeval_subtract(struct timeval *result, struct timeval tv1, struct timeval tv0);
void msToTimeval(long int ms, struct timeval *result);
u_int32_t strIPtoBin(const char *strIP);
string binIPtoStr(u_int32_t naddr);
u_int32_t realIPfromID(int id);
u_int32_t getLinkedRouter(struct hostlink **retLink);
void beAHost(void);
void hostTryToReceive(void);
int hostRecvPacket(struct packet* toRecv);
void hostTryToSend(void);
int hostSendPacket(u_int8_t payload[PAYLOAD_LEN], int payloadLen, u_int32_t destAddr, u_int16_t sourcePort, u_int16_t destPort, u_int16_t seq);
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
u_int32_t g_overlayIP = 0; //network byte order
u_int32_t g_realIP = 0;  //network byte order
u_int32_t g_defaultRouterIp = 0;  //IP of default router the host sends to
struct hostlink *g_defaultHostLink = NULL;  //hostlink to default router
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
				routerlink rlink;
				line >> rlink.router1Id;
				line >> tempDelayTime;
				msToTimeval(tempDelayTime, &(rlink.router1SendDelay));
				line >> rlink.router2Id;
				line >> tempDelayTime;
				msToTimeval(tempDelayTime, &(rlink.router2SendDelay));
				g_routerlinks.push_back(rlink);
				rlink.lastSendTime.tv_sec = 0;
				rlink.lastSendTime.tv_usec = 0;
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
				g_realIP = htonl(ip);
				freeifaddrs(addressList);
				return true;
			}
		}
		for(hostIt = g_endhosts.begin(); hostIt < g_endhosts.end(); hostIt++) {
			if((*hostIt).realIp == ip) {
				g_thisID = (*hostIt).id;
				g_isRouter = false;
				g_realIP = htonl(ip);
				g_overlayIP = htonl((*hostIt).overlayIp);
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
		
		DEBUGF("Source addr: %s\nDest addr: %s\n", binIPtoStr(iph->saddr).c_str(), binIPtoStr(iph->daddr).c_str());
		DEBUGF("Source port: %hu\nDest port: %hu\nLength: %hu\n", ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len)-8);
		//get payload
		memcpy(payload, buffer+HEADERS_LEN, ntohs(udph->len)-8);
	}
}

//fills in the given buffer with overlay headers and data
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen, u_int16_t sport, u_int16_t dport, u_int16_t seq) {
	struct iphdr iph;
	struct udphdr udph;
	
	bzero(&iph, sizeof(iph));
	iph.version = 4;
	iph.ihl = 5;
	iph.tot_len = htons(sizeof(iph) + sizeof(udph) + payloadLen);
	iph.id = seq;
	iph.ttl = g_TTL;
	iph.protocol = IPPROTO_UDP;
	iph.saddr = g_overlayIP;
	iph.daddr = destIP;
	
	bzero(&udph, sizeof(udph));
	udph.source = sport;
	udph.dest = dport;
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

//returns router IP address of router linked to this host (host byte order)
//retLink assigned to the hostlink involving this host
u_int32_t getLinkedRouter(struct hostlink **retLink) {
	vector<hostlink>::iterator hlinkIt;
	vector<router>::iterator routerIt;
	bool routerFound = false;
	for(hlinkIt = g_hostlinks.begin(); hlinkIt < g_hostlinks.end(); hlinkIt++) {
		if((*hlinkIt).endHostId == g_thisID) {
			*retLink = &(*hlinkIt);
			routerFound = true;
			break;
		}
	}
	if(routerFound) {
		for(routerIt = g_routers.begin(); routerIt < g_routers.end(); routerIt++) {
			if((*routerIt).id == (*retLink)->routerId) {
				return (*routerIt).realIp;
			}
		}
	}
	return 0;
}

void beAHost(void) {
	DEBUGF("Being a host. Mmm, hosty!\n");
	g_sock = create_cs3516_socket(false);
	
	//get information on router linked to this host-router
	g_defaultRouterIp = getLinkedRouter(&g_defaultHostLink);
	if(g_defaultRouterIp == 0 || g_defaultHostLink == NULL) {
		cerr << "Host has no link to a router" << endl;
		throw(0);
	}
	
	setBlocking(false);
	while(1) {
		hostTryToReceive();		
		hostTryToSend();
	}
}

//When called in a loop, implements end-host receive file functionality
void hostTryToReceive(void) {
	static fstream outFile("recv.txt", fstream::out | fstream::app);
	static struct packet toRecv;
	static u_int8_t payload[PAYLOAD_LEN];
	struct iphdr *iph;
	struct udphdr *udph;
	int rcvStatus;
	int payloadLen;
	static int totalSize = 0;
	static u_int16_t lastSeqReceived = 0;
	static int packetCount = 0;
	
	if(!outFile.is_open()) {
		cerr<<"Unable to open output file."<<endl;
		throw(0);
	}
	
	memset(toRecv.buffer, 0, PACKET_LEN);
	rcvStatus = hostRecvPacket(&toRecv);
	if(rcvStatus == 1) {
		memset(payload, 0, PAYLOAD_LEN);
		readOverlayHeaders(toRecv.buffer, &iph, &udph, payload);
		payloadLen = toRecv.length - HEADERS_LEN;
		if(ntohs(iph->id) > lastSeqReceived + 1) {
			for(u_int16_t missingIdx = lastSeqReceived+1; missingIdx < ntohs(iph->id); missingIdx++) {
				cout<<"Missing packet ID: "<<missingIdx<<endl;
			}
		}
		lastSeqReceived = ntohs(iph->id);
		outFile <<"Source address: "<<binIPtoStr(iph->saddr)<<endl
				<<"Destination address: "<<binIPtoStr(iph->daddr)<<endl
				<<"Source port: "<<ntohs(udph->source)<<endl
				<<"Destination port: "<<ntohs(udph->dest)<<endl;
		outFile.write((char*)payload, payloadLen);
		outFile<<endl<<endl;
		totalSize += payloadLen;
		packetCount++;
		//end of file - will fail if last payloadLen is exactly PAYLOAD_LEN (file is multiple of PAYLOAD_LEN)
		if(payloadLen < PAYLOAD_LEN) {
			cout<<"File received:"<<endl
				<<"Length: "<<totalSize<<endl
				<<"Packets received: "<<packetCount<<endl;
		}
	}
}

//receive a packet
//returns -1 on error, 1 on successful receive, and 0 if nothing to receive
int hostRecvPacket(struct packet* toRecv) {
	u_int8_t rxBuffer[PACKET_LEN];
	int bytesReceived;
	
	bytesReceived = cs3516_recv(g_sock, (char *)rxBuffer, PACKET_LEN);
	if(bytesReceived > 0) {
		memcpy(toRecv->buffer, rxBuffer, bytesReceived);
		toRecv->length = bytesReceived;
		return 1;
	}
	else {
		return 0;
	}
}

//When called in a loop, implements end-host send file functionality
void hostTryToSend(void) {
	static enum {
		STATE_LOOKFORFILE,
		STATE_FOUNDFILE,
		STATE_SENDPACKET,
		STATE_TRYAGAIN,
		STATE_FINISHED,
		STATE_IDLE
	} state = STATE_LOOKFORFILE;
	static fstream sendFile;
	static u_int32_t destIP;
	static u_int16_t srcPort, destPort;
	static u_int8_t buffer[PAYLOAD_LEN] = "";
	static int bufLen;
	static u_int16_t sequence = 0; //host byte order
	static int totalBytes = 0;
	char tempDestIP[32] = "";
	int sendResult;
	
	switch(state) {
		case STATE_LOOKFORFILE:
			sendFile.open("send.txt", fstream::in);
			if(sendFile.is_open()) {
				state = STATE_FOUNDFILE;
			}
			else {
				break;
			}
		case STATE_FOUNDFILE:
			sendFile.getline((char*)buffer, PAYLOAD_LEN-1);
			sscanf((char*)buffer, "%s %hu %hu", tempDestIP, &srcPort, &destPort);
			destIP = strIPtoBin(tempDestIP);
			srcPort = htons(srcPort);
			destPort = htons(destPort);
			state = STATE_SENDPACKET;
		case STATE_SENDPACKET:
			if(sendFile.good()) {
				bufLen = 0;
				memset(buffer, 0, PAYLOAD_LEN);
				
				sendFile.read((char*)buffer, PAYLOAD_LEN);
				bufLen = sendFile.gcount();
				sendResult = hostSendPacket(buffer, bufLen, destIP, srcPort, destPort, htons(sequence));
				if(sendResult == 0) {
					state = STATE_TRYAGAIN;
				}
				else {
					totalBytes += bufLen;
					sequence++;
				}
			}
			else {
				state = STATE_FINISHED;
			}
			break;
		case STATE_TRYAGAIN:
			sendResult = hostSendPacket(buffer, bufLen, destIP, srcPort, destPort, htons(sequence));
			if(sendResult == 1) {
				sequence++;
				totalBytes += bufLen;
				state = STATE_SENDPACKET;
			}
			break;
		case STATE_FINISHED:
			cout<<"File transmitted."<<endl
				<<"Size: "<<totalBytes<<" bytes."<<endl
				<<"Packets trasmitted: "<<sequence<<endl;
			state = STATE_IDLE;
			break;
		case STATE_IDLE:
			break;
	}
}

//send a packet
//returns -1 on error, 1 on successful send, and 0 if delay time has not happened yet
int hostSendPacket(u_int8_t payload[PAYLOAD_LEN], int payloadLen,
					u_int32_t destAddr, //network order
					u_int16_t sourcePort, //network order
					u_int16_t destPort, //network order
					u_int16_t seq) { //network order
	
	u_int8_t packetBuffer[PACKET_LEN];
	int packetLen = HEADERS_LEN + payloadLen;
	struct timeval difTime;
	struct timeval curTime;
	
	//check delay
	gettimeofday(&curTime, NULL);
	timeval_subtract(&difTime, curTime, g_defaultHostLink->lastSendTime);
	if(timeval_subtract(NULL, difTime, g_defaultHostLink->hostSendDelay) == 1) {
		//send the packet
		createPacket(packetBuffer, destAddr, payload, payloadLen, sourcePort, destPort, seq);
		cs3516_send(g_sock, (char *)packetBuffer, packetLen, htonl(g_defaultRouterIp));
		g_defaultHostLink->lastSendTime = curTime;
		return 1;
	}
	else {
		return 0;
	}
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
		DEBUGF("Unable to find destination address for destID %d\n", destID);
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

void getLinkQueues(map<int, queue<packet*> > &linkQueues) {
	vector<hostlink>::iterator hlinkIt;
	vector<routerlink>::iterator rlinkIt;
	
	DEBUGF("Populating link queues...\n");

	for(hlinkIt = g_hostlinks.begin(); hlinkIt < g_hostlinks.end(); hlinkIt++) {
		if((*hlinkIt).routerId == g_thisID) {
			int endhost = (*hlinkIt).endHostId;
			if(linkQueues.find(endhost) == linkQueues.end()) {
				linkQueues.insert(pair<int, queue<packet*> >(endhost, queue<packet*>()));
			}
		}
	}
	for(rlinkIt = g_routerlinks.begin(); rlinkIt < g_routerlinks.end(); rlinkIt++) {
		bool related = false;
		int other = 0;
		DEBUGF("Current link: router1Id: %d router2Id: %d thisID: %d\n", (*rlinkIt).router1Id, (*rlinkIt).router2Id, g_thisID);
		if((*rlinkIt).router2Id == g_thisID) {
			related = true;
			other = (*rlinkIt).router1Id;
		}
		else if((*rlinkIt).router1Id == g_thisID) {
			related = true;
			other = (*rlinkIt).router2Id;
		}
		if(related) {
			DEBUGF("Link is related.\n");
			if(linkQueues.find(other) == linkQueues.end()) {
				DEBUGF("Link queue inserted.\n");
				linkQueues.insert(pair<int, queue<packet*> >(other, queue<packet*>()));
			}
		}
	}
}

//network byte order
//return the id of the host with the given overlay IP, 0 if one doesn't exist
int getHostIDfromOverlayIP(u_int32_t overlayIp) {
	vector<endhost>::iterator hostIt;
	
	for(hostIt = g_endhosts.begin(); hostIt < g_endhosts.end(); hostIt++) {
		if((*hostIt).overlayIp == ntohl(overlayIp)) {
			return (*hostIt).id;
		}
	}
	return 0;
}

//network byte order
//returns the endhost id of the endhost linked directly to this router, if it exists
//otherwise, returns next router id to send it to
//returns -1 if it can't figure out where to send it
int getNextIDfromOverlayIP(u_int32_t overlayIp) {
	vector<hostlink>::iterator hlinkIt;
	int hostId = getHostIDfromOverlayIP(overlayIp);
	
	for(hlinkIt = g_hostlinks.begin(); hlinkIt < g_hostlinks.end(); hlinkIt++) {
		if((*hlinkIt).routerId == g_thisID && (*hlinkIt).endHostId == hostId) {
			return (*hlinkIt).endHostId;
		}
	}
	
	return g_routes.getRouterID(ntohl(overlayIp));
}

void beARouter(void) {
	struct iphdr *iph;
	struct udphdr *udph;
	u_int32_t fwdAddr;
	u_int8_t packetBuffer[PACKET_LEN] = "";
	u_int8_t payload[PAYLOAD_LEN] = "";
	packet *pkt = NULL;
	map<int, queue<packet*> > linkQueues;
	map<int, queue<packet*> >::iterator mapIt;
	int bytesReceived;
	int packetSendResult;
	int destID;
	DEBUGF("Being a router. Route route!\n");
	
	g_logfile.open("ROUTER_control.txt", fstream::out | fstream::app);
	if(!g_logfile.is_open()) {
		cerr<<"Unable to open logfile."<<endl;
		return;
	}
	
	g_sock = create_cs3516_socket(false);
	
	getLinkQueues(linkQueues);
	
	while(1) {
		setBlocking(false);
		bytesReceived = cs3516_recv(g_sock, (char *)packetBuffer, PACKET_LEN);
		if(bytesReceived > 0) {
			readOverlayHeaders(packetBuffer, &iph, &udph, payload);
			
			//handle ttl
			iph->ttl-=1;
			if(iph->ttl <= 0) {
				DEBUGF("Dropping packet: TTL Expired.\n");
				//drop packet
				logPacket(iph, TTL_EXPIRED);
				continue;
			}
			
			destID = getNextIDfromOverlayIP(iph->daddr);
			DEBUGF("destID is %d\n", destID);
			
			if(linkQueues.find(destID) != linkQueues.end()) {
				queue<packet*> & relevantQueue = linkQueues.find(destID)->second;
				//todo: this will only work for host-router-host paths.
				//		Make work for host-router...router-host. 
				
				if(relevantQueue.size() >= g_queueLength) {
					//drop packet
					logPacket(iph, MAX_SENDQ_EXCEEDED);
					continue;
				}
				
				//add packet to queue
				pkt = (packet*)malloc(sizeof(packet));
				memcpy(pkt->buffer, packetBuffer, PACKET_LEN);
				pkt->length = bytesReceived;
				relevantQueue.push(pkt);
			}
			else {
				DEBUGF("Unable to find queue to add packet to.\n");
				logPacket(iph, NO_ROUTE_TO_HOST);
			}
		}
		
		fwdAddr = realIPfromID(destID);
		
		for(mapIt = linkQueues.begin(); mapIt != linkQueues.end(); mapIt++) {
			queue<packet*> & relevantQueue = (*mapIt).second;
			//try to send a packet on the queue
			if(relevantQueue.size() > 0) {
				packetSendResult = sendPacket((*mapIt).first, relevantQueue.front()->buffer, relevantQueue.front()->length);
				if(packetSendResult == 1) {
					DEBUGF("Packet sent.\n");
					logPacket(iph, SENT_OKAY, fwdAddr);
					free(relevantQueue.front());
					relevantQueue.pop();
				}
				else if(packetSendResult == -1) {
					logPacket(iph, NO_ROUTE_TO_HOST);
					free(relevantQueue.front());
					relevantQueue.pop();
				}
				else if(packetSendResult == 0) {
					//delay has not passed - wait
				}
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