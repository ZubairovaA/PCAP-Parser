#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<map>

using namespace std;


struct Link          //структура заголовка Ethernet    Ethernet header struct
{
	unsigned char ether_dhost[6];  //MAC адрес получателя           MAC dest address
	unsigned char ether_shost[6];  //MAC адрес отправителя          MAC source address
	unsigned short ether_type;     //тип протокола сетевого уровня  next level protocol


};

class Eth_type {                    //поиск типа сетевого протокола        checking the Internet level protocol
public:
	map<unsigned short, string> mp;
	void fill_mp();        //заполнение контейнера, запускается в кострукторе       filling the map
	Eth_type() {
		fill_mp();
	}
	~Eth_type() {};
};





