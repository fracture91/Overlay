#pragma once
#include <bitset>
using namespace std;

#define BITCOUNT 32

class Trie {
	private:
		Trie **children;
		int destRouterID;
	public:
		Trie() {
			children = (Trie**)calloc(2, sizeof(Trie*));
			destRouterID = -1; //no path
		}
		~Trie() {
			if(children[0] != NULL) {
				free(children[0]);
			}
			if(children[1] != NULL) {
				free(children[1]);
			}
			free(children);
		}
		//note: bits needs to be in host byte order
		void insertNode(bitset<BITCOUNT> &bits, int sigBits, int newDestRouterID, int curBit = 0) {
			if(curBit > sigBits || curBit < 0 || sigBits >= BITCOUNT || sigBits < 1) {
				//error
				return;
			}
			//haven't reached end of sigBits yet
			else if(curBit < sigBits) {
				if(children[bits[BITCOUNT-curBit]] == NULL) {
					children[bits[BITCOUNT-curBit]] = new Trie;
				}
				children[bits[BITCOUNT-curBit]]->insertNode(bits, sigBits, newDestRouterID, curBit+1);
				return;
			}
			//end of sigBits
			else if(curBit == sigBits) {
				destRouterID = newDestRouterID;
				return;
			}
		}
		//note: overlayIP needs to be in host byte order
		int getRouterID(u_int32_t overlayIP, int curBit = 0) {
			int thisBit;
			int tempDestID;
			if(curBit == BITCOUNT) {
				return destRouterID;
			}
			else if(curBit > BITCOUNT || curBit < 0) {
				//error
				return -2;
			}
			//get the bit associated with curBit to use as index into children array
			thisBit = (overlayIP&(1<<(BITCOUNT-curBit)))>>(BITCOUNT-curBit);
			//no child; return this node's route
			if(children[thisBit] == NULL) {
				return destRouterID;
			}
			//return the child's route (if it exists, otherwise, return this node's route)
			else {
				tempDestID = children[thisBit]->getRouterID(overlayIP, curBit+1);
				//if child returned no route, return this node's route
				if(tempDestID == -1) {
					return destRouterID;
				}
				else {
					return tempDestID;
				}
			}
		}
};