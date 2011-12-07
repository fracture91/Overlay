#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <ctime>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <sstream>
#include <cstdlib>
using namespace std;
#include "cs3516sock.h"

#define PAYLOAD_LEN 1000
#define PACKET_LEN sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_LEN

fstream g_logfile;

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
	int id;
	u_int32_t realIp;
};

struct endhost {
	int id;
	u_int32_t realIp;
	u_int32_t overlayIp;
};

struct routerlink {
	int router1Id;
	int router2Id;
	int router1SendDelay;
	int router2SendDelay;
};

struct hostlink {
	int routerId;
	int routerSendDelay;
	u_int32_t overlayPrefix;
	int significantBits;
	int endHostId;
	int hostSendDelay;
};


void readConfig();
void readArgs(int argc, char *argv[]);
void readOverlayHeaders(u_int8_t *buffer, struct iphdr **iphPointer, struct udphdr **udphPointer, u_int8_t payload[PAYLOAD_LEN]);
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen);
u_int32_t strIPtoBin(const char *strIP);
string binIPtoStr(u_int32_t naddr);
void beAHost(void);
void beARouter(void);
void printPacket(u_int8_t packet[PACKET_LEN], int length);
void logPacket(struct iphdr *overlayIPHdr, logStatusCode code, u_int32_t nextHop);

u_int8_t g_TTL = 3;
u_int32_t g_IP = strIPtoBin("192.168.0.10");
int g_queueLength = 0;
int g_defaultTTL = 0;
vector<router> g_routers;
vector<endhost> g_endhosts;
vector<routerlink> g_routerlinks;
vector<hostlink> g_hostlinks;



int main(int argc, char *argv[]) {
	readConfig();
	readArgs(argc, argv);
	return 0;
}


void readArgs(int argc, char *argv[]) {
	if(argc > 1) {
		if(!strcmp(argv[1], "host")) {
			beAHost();
		}
		else if(!strcmp(argv[1], "router")) {
			beARouter();
		}
	}
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

void readConfig() {
	fstream configfile;
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
				r.realIp = strIPtoBin(ip.c_str());
				g_routers.push_back(r);
				break;
			case HOST_ID:
				endhost h;
				line >> h.id;
				line >> ip;
				h.realIp = strIPtoBin(ip.c_str());
				line >> ip;
				h.overlayIp = strIPtoBin(ip.c_str());
				g_endhosts.push_back(h);
				break;
			case ROUTER_ROUTER_LINK:
				routerlink link;
				line >> link.router1Id;
				line >> link.router1SendDelay;
				line >> link.router2Id;
				line >> link.router2SendDelay;
				g_routerlinks.push_back(link);
				break;
			case ROUTER_HOST_LINK:
				hostlink hlink;
				line >> hlink.routerId;
				line >> hlink.routerSendDelay;
				string prefix;
				line >> prefix;
				size_t slash = prefix.find_first_of("/");
				hlink.overlayPrefix = strIPtoBin(prefix.substr(0, slash).c_str());
				hlink.significantBits = atoi(prefix.substr(slash+1).c_str());
				line >> hlink.endHostId;
				line >> hlink.hostSendDelay;
				g_hostlinks.push_back(hlink);
				break;
		}
		
	}
}

void beAHost(void) {
	int sock;
	
	u_int8_t payload[PAYLOAD_LEN] = "Hello world!";
	u_int8_t rxPayload[PAYLOAD_LEN] = "";
	u_int8_t txBuffer[PACKET_LEN];
	u_int8_t rxBuffer[PACKET_LEN] = "";
	u_int32_t router = strIPtoBin("192.168.0.8");
	u_int32_t destination = strIPtoBin("192.168.0.10");
	int payloadLen = strlen((char *)payload);
	int bytesSent;
	int bytesReceived;
	sock = create_cs3516_socket();
	cout<<"Socket created."<<endl;
	
	createPacket(txBuffer, destination, payload, payloadLen);
	printPacket(txBuffer, 28 + payloadLen);
	bytesSent = cs3516_send(sock, (char *)txBuffer, 28 + payloadLen, router);
	
	bytesReceived = cs3516_recv(sock, (char *)rxBuffer, PACKET_LEN);
	struct iphdr *iph;
	struct udphdr *udph;
	readOverlayHeaders(rxBuffer, &iph, &udph, rxPayload);
	
	cout<<"Message received."<<endl;
	cout<<(char *)rxPayload<<endl;
}

void beARouter(void) {
	int sock;
	struct iphdr *iph;
	struct udphdr *udph;
	u_int32_t fwdAddr;
	u_int8_t packetBuffer[PACKET_LEN] = "";
	u_int8_t payload[PAYLOAD_LEN] = "";
	int bytesReceived;
	cout<<"Being a router. Route route!"<<endl;
	
	sock = create_cs3516_socket();
	
	g_logfile.open("ROUTER_control.txt", fstream::out | fstream::app);
	if(!g_logfile.is_open()) {
		cerr<<"Unable to open logfile."<<endl;
		return;
	}
	
	while(1) {
		bytesReceived = cs3516_recv(sock, (char *)packetBuffer, PACKET_LEN);
		readOverlayHeaders(packetBuffer, &iph, &udph, payload);
		
		//handle ttl
		iph->ttl-=1;
		if(iph->ttl <= 0) {
			//drop packet
			logPacket(iph, TTL_EXPIRED, 0);
			continue;
		}
		
		//forward packet
		fwdAddr = strIPtoBin("192.168.0.10");
		cs3516_send(sock, (char *)packetBuffer, bytesReceived, fwdAddr);
		logPacket(iph, SENT_OKAY, fwdAddr);
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