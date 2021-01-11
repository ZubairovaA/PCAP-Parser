#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<map>

using namespace std;


struct Link          //��������� ��������� Ethernet    Ethernet header struct
{
	unsigned char ether_dhost[6];  //MAC ����� ����������           MAC dest address
	unsigned char ether_shost[6];  //MAC ����� �����������          MAC source address
	unsigned short ether_type;     //��� ��������� �������� ������  next level protocol


};

class Eth_type {                    //����� ���� �������� ���������        checking the Internet level protocol
public:
	map<unsigned short, string> mp;
	void fill_mp();        //���������� ����������, ����������� � �����������       filling the map
	Eth_type() {
		fill_mp();
	}
	~Eth_type() {};
};





