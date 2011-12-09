Author:				Eric Finn, Andrew Hurle
Date:				12/8/2011
Version:			1
Project ID:			3
CS Class:			CS 3516
Programming Language:		C++
OS/Hardware dependencies:	GNU/Linux, network interface
Problem Description:		Create a program that sends a file across an overlay network

Program Assumptions and Restrictions:
	File size must not be a multiple of 1000 bytes
	Config file must be valid
	Routers and end hosts must be running to transmit files

Interfaces:	 Command line interface

Implementation Details:
	Hosts and routers use busy waiting to wait for packets
	Maximum payload length for an individual packet is 1000, not including overlay headers
	
How to build the program:  make


Results:

In this example, the overlay network was configured to intentionally drop a packet.

---Sending host---

> ./overlay
File transmitted.
Size: 3883 bytes.
Packets trasmitted: 4

---Receiving host---

> ./overlay
Missing packet ID: 2
File received:
Length: 2883
Packets received: 3

When not configured to drop a packet:

---Receiving Host---

> ./overlay
File received:
Length: 3883
Packets received: 4




References:
cplusplus.com - STL documentation
linux.die.net - Linux function documentation
wikipedia.org - IPv4 and UDP header documentation
