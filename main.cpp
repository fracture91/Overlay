#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <iostream>
using namespace std;
#include "cs3516sock.h"

#define PAYLOAD_LEN 1000
#define PACKET_LEN sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_LEN

void readArgs(int argc, char *argv[]);
void readOverlayHeaders(u_int8_t *buffer, struct iphdr **iphPointer, struct udphdr **udphPointer);
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen);
u_int32_t strIPtoBin(const char *strIP);
void beAHost(void);
void beARouter(void);

u_int8_t g_TTL = 3;
u_int32_t g_IP = strIPtoBin("127.0.0.1");


int main(int argc, char *argv[]) {
	beAHost();
	return 0;
}


void readArgs(int argc, char *argv[]);

//read the overlay headers into ip and udp struct, print out info from them
void readOverlayHeaders(u_int8_t *buffer, struct iphdr **iphPointer, struct udphdr **udphPointer) {
	*iphPointer = (struct iphdr *)buffer;
	struct iphdr *iph = *iphPointer;
	
	cout << "Source address: " << ntohl(iph->saddr) << endl
	     << "Dest address: " << ntohl(iph->daddr) << endl;
	
	//check for UDP
	if(iph->protocol == IPPROTO_UDP) {
		*udphPointer = (udphdr *)(iph+(iph->ihl)*4);
		struct udphdr *udph = *udphPointer;
		
		cout << "Source port: " << ntohs(udph->source) << endl
		     << "Dest port: " << ntohs(udph->dest) << endl
			 << "Length: " << ntohs(udph->len) << endl;
	}
}

//fills in the given buffer with overlay headers and data
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen) {
	struct iphdr iph;
	struct udphdr udph;
	
	bzero(&iph, sizeof(iph));
	iph.ihl = 5;
	iph.tot_len = sizeof(iph) + sizeof(udph) + payloadLen;
	iph.ttl = g_TTL;
	iph.protocol = IPPROTO_UDP;
	iph.saddr = g_IP;
	iph.daddr = htonl(destIP);
	
	bzero(&udph, sizeof(udph));
	udph.source = htons(MYPORT);
	udph.dest = htons(MYPORT);
	udph.len = sizeof(udph) + payloadLen;
	
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

void beAHost(void) {
	int sock;
	
	u_int8_t payload[PAYLOAD_LEN] = "Hello world!";
	u_int8_t txBuffer[PACKET_LEN];
	u_int8_t rxBuffer[PACKET_LEN] = "";
	u_int32_t localhost = strIPtoBin("127.0.0.1");
	int payloadLen = strlen((char *)payload);
	sock = create_cs3516_socket();
	cout<<"Socket created."<<endl;
	
	createPacket(txBuffer, localhost, payload, payloadLen);
	cs3516_send(sock, (char *)txBuffer, 28 + payloadLen, localhost);
	cout<<"Message sent."<<endl;
	
	cs3516_recv(sock, (char *)rxBuffer, PACKET_LEN);
	struct iphdr *iph;
	struct udphdr *udph;
	readOverlayHeaders(rxBuffer, &iph, &udph);
	
	cout<<"Message received."<<endl;
	cout<<rxBuffer<<endl;
}

void beARouter(void) {
}