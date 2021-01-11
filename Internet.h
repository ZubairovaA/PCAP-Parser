#pragma once
#include <pcap.h>
#include <iostream>
#include <string>

using namespace std;

struct Internet_ip {
	unsigned char ip_vhl;		   // Версия ip протокола и длина заголовка(*4)  ip protocol version
	unsigned char ip_tos;		   // тип обслуживания   type of service
	unsigned short ip_len;		   // общий размер всего пакета   the size of the packet
	unsigned short ip_id;		   // идентификационный номер пакета при разбивке файла на части   identification
	unsigned short ip_off;		   // fragment offset field   
#define IP_RF 0x8000		       // флаг- зарезервированный фрагмент    reserved fragment flag 
#define IP_DF 0x4000		       // флаг- можно ли фрагментировать      don't fragment flag
#define IP_MF 0x2000		       // флаг- будут и еще фрагменты         more fragments flag
#define IP_OFFMASK 0x1fff	       // маска для фрагментирования битов    mask for fragmenting bits
	unsigned char ip_ttl;		   // time to live
	unsigned char ip_p;		       // протокол след уровня                next level protocol
	unsigned short ip_sum;		   // чексумма                            checksum
	unsigned char ip_src[4];       //                                     source address
	unsigned char ip_dst[4];       //                                     dest address
};




