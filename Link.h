#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<map>
#include<fstream>

using namespace std;


class Link          //��������� ��������� Ethernet    Ethernet header struct
{
	unsigned char ether_dhost[6];  //MAC ����� ����������           MAC dest address
	unsigned char ether_shost[6];  //MAC ����� �����������          MAC source address
	unsigned short ether_type;     //��� ��������� �������� ������  next level protocol
public:
	Link() {};
	bool VLAN_Protocol(const u_char* packet, ofstream & Parse_File, bool & Is_VLAN, unsigned short* CheckVLAN);
	void Write_MAC_Addr(ofstream& Parse_File);
	void Check_IP_Protocol(bool& To_Continue, ofstream& Parse_File);
	~Link() {};
	friend class Eth_type;
};

class Eth_type {                    //����� ���� �������� ���������        checking the Internet level protocol
	map<unsigned short, string> mp;
	void fill_mp();        //���������� ����������, ����������� � �����������       filling the map

public:
	Eth_type() {
		fill_mp();
	}
    
	void Check_IL_Protocol(ofstream& Parse_File, Link* ethernet);
	~Eth_type() {};
};





