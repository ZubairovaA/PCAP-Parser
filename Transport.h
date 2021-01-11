#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<map>

using namespace std;


struct Transport_tcp {
	unsigned short src_port;	// номер порта отправител€                 source port
	unsigned short dst_port;	// номер порта получател€                  destination port
	 unsigned long th_seq;		// номер пакета в последовательности       sequence number
	 unsigned long th_ack;		// номер подтверждени€                     acknowledgement number
	unsigned char th_offx2;	    // длина заголовка (4 бита) TCP_Length = (tcp->th_offx2) >>4     data offset
	unsigned char th_flags;     //флаги    flags
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	unsigned short th_win;		//окно                      window
	unsigned short sum;		    //чексумма                  checksum
	unsigned short th_urp;		//экстренный указатель      urgent pointer

};

struct Transport_udp {
	unsigned short   src_port;       // номер порта отправител€ 
	unsigned short   dst_port;       // номер порта получател€ 
	unsigned short   udp_length;     // длина датаграммы 
	unsigned short   sum;            //чексумма

};

struct Transport_ICMP
{
	unsigned char   ICMP_type;           // тип ICMP- пакета
	unsigned char   ICMP_code;           // код ICMP- пакета 
	unsigned short  sum;                 //чексумма
	union {
		struct { unsigned char  uc1, uc2, uc3, uc4; } s_uc;  //переменна€ часть заголовка
		struct { unsigned short us1, us2; } s_us;
		unsigned long s_ul;
	} s_icmp;

};

class Port_type {               //контейнер дл€ поиска типа протокола прикладного уровн€
public:
	map<unsigned short, string> mp_port;
	void fill_port();
	Port_type() {
		fill_port();
	}
	~Port_type() {};
};