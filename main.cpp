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
void readOverlayHeaders(u_int8_t *buffer, struct iphdr **iphPointer, struct udphdr **udphPointer, u_int8_t payload[PAYLOAD_LEN]);
void createPacket(u_int8_t *buffer, u_int32_t destIP, u_int8_t *payload, int payloadLen);
u_int32_t strIPtoBin(const char *strIP);
void beAHost(void);
void beARouter(void);
void printPacket(u_int8_t packet[PACKET_LEN], int length);

u_int8_t g_TTL = 3;
u_int32_t g_IP = strIPtoBin("127.0.0.1");


int main(int argc, char *argv[]) {
	beAHost();
	return 0;
}


void readArgs(int argc, char *argv[]);

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

void beAHost(void) {
	int sock;
	
	u_int8_t payload[PAYLOAD_LEN] = "Hello world!";
	u_int8_t rxPayload[PAYLOAD_LEN] = "";
	u_int8_t txBuffer[PACKET_LEN];
	u_int8_t rxBuffer[PACKET_LEN] = "";
	u_int32_t localhost = strIPtoBin("127.0.0.1");
	int payloadLen = strlen((char *)payload);
	int bytesSent;
	int bytesReceived;
	sock = create_cs3516_socket();
	cout<<"Socket created."<<endl;
	
	createPacket(txBuffer, localhost, payload, payloadLen);
	printPacket(txBuffer, 28 + payloadLen);
	bytesSent = cs3516_send(sock, (char *)txBuffer, 28 + payloadLen, localhost);
	
	bytesReceived = cs3516_recv(sock, (char *)rxBuffer, PACKET_LEN);
	struct iphdr *iph;
	struct udphdr *udph;
	readOverlayHeaders(rxBuffer, &iph, &udph, rxPayload);
	
	cout<<"Message received."<<endl;
	cout<<(char *)rxPayload<<endl;
}

void beARouter(void) {
}

void printPacket(u_int8_t packet[PACKET_LEN], int length) {
	for(int i = 0; i < length; i++) {
		printf("%02hX ", packet[i]);
		if((i % 4) == 3) {
			printf("\n");
		}
	}
}