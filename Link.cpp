#pragma once
#include <pcap.h>

#include <iostream>
#include <string>
#include<map>
#include<fstream>
#include "Link.h"

using namespace std;

bool Link::VLAN_Protocol(const u_char* packet, ofstream & Parse_File, bool & Is_VLAN, unsigned short* CheckVLAN) {
	if (ntohs(*CheckVLAN) == 0x8100)             // checking for the VLAN tag  
	{
		Parse_File << "VLAN" << endl;
		CheckVLAN += 2;                          //if there is the VLAN tag, mooving the VLAN pointer for the 4 bytes to determinate the beginning of the ether type 
		ether_type = *CheckVLAN;
		Is_VLAN = true;
		return Is_VLAN;
	}
}

void Link::Write_MAC_Addr(ofstream& Parse_File) {
	Parse_File << "Ethernet II, Src: " << ntohs(ether_shost[0]) << ":" << ntohs(ether_shost[1]) << ":" << ntohs(ether_shost[2]) << "_"   //the source MAC adress 
		<< ntohs(ether_shost[3]) << ":" << ntohs(ether_shost[4]) << ":" << ntohs(ether_shost[5]);

	Parse_File << ", Dst: " << ntohs(ether_dhost[0]) << ":" << ntohs(ether_dhost[1]) << ":" << ntohs(ether_dhost[2]) << "_"              //the destination MAC adress
		<< ntohs(ether_dhost[3]) << ":" << ntohs(ether_dhost[4]) << ":" << ntohs(ether_dhost[5]) << endl;

}

void Link::Check_IP_Protocol(bool& To_Continue, ofstream& Parse_File) {
	if (ntohs(ether_type) == 0x0800)   //if the internet layer protocol is the Internet Protocol Verion 4
	{
		Parse_File << "Internet Protocol Verion 4, " << endl;
	}
	else                                             //if it's not the IPv4 protocol
	{
		Eth_type Obj;
		Obj.Check_IL_Protocol(Parse_File, this);
		To_Continue = true;                    //mooving to the next packet
	}
}



void Eth_type::fill_mp()
{                            // заполнение map парами "тип протокола- строка с названием"   filling the map with the pairs "type of protocol - name"
    mp.insert({ 0x0806 ,"Address Resolution Protocol/n" });
    mp.insert({ 0x22F0 ,"Audio Video Transport Protocol/n" });
    mp.insert({ 0x8102 ,"Simple Loop Prevention Protocol/n" });
    mp.insert({ 0x22EA ,"Multiple Stream Registration Protocol/n" });
    mp.insert({ 0x88F7 ,"Precision Time Protocol/n" });
	mp.insert({ 0x86DD ,"Internet Protocol Verion 6/n" });


}

void Eth_type::Check_IL_Protocol(ofstream& Parse_File, Link* ethernet) {
	map<unsigned short, string>::iterator it;
	if (mp.find(ntohs(ethernet->ether_type)) != mp.end())
	{
		Parse_File << mp.find(ntohs(ethernet->ether_type))->second;
	}
	else
	{
		Parse_File << "Unknown Protocol" << endl;
	}

}
