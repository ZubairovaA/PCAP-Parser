#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<fstream>
#include<map>
#include<typeinfo>
#include"Transport.h"

using namespace std;
class Base_TL;

class Internet_ip {
public:
	unsigned char ip_vhl;		   // Версия ip протокола и длина заголовка(*4)  ip protocol version
	unsigned char ip_tos;		   // тип обслуживания   type of service
	unsigned short ip_len;		   // общий размер всего пакета   the size of the packet
	unsigned short ip_id;		   // идентификационный номер пакета при разбивке файла на части   identification
	unsigned short ip_off;		   // fragment offset field   
#define IP_RF 0x8000		           // флаг- зарезервированный фрагмент    reserved fragment flag 
#define IP_DF 0x4000		           // флаг- можно ли фрагментировать      don't fragment flag
#define IP_MF 0x2000		           // флаг- будут и еще фрагменты         more fragments flag
#define IP_OFFMASK 0x1fff	           // маска для фрагментирования битов    mask for fragmenting bits
	unsigned char ip_ttl;		   // time to live
	unsigned char ip_p;		   // протокол след уровня                next level protocol
	unsigned short ip_sum;		   // чексумма                            checksum
	unsigned char ip_src[4];           // source address
	unsigned char ip_dst[4];           // dest address

	Internet_ip() {};
	~Internet_ip() {};
	void Write_IP_Addr(ofstream& Parse_File);
	int ip_size();   //the size of the internet layer header
        void Check_TL(ofstream& Parse_File, const unsigned char *TP_Hdr, const char* payload,  unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue);
};


class  TL_ptoto_type{               
public:
    struct Base    // the base class to keep the pointer to the derived template class in the map
    {  virtual ~Base() {}
       virtual void build(const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue) =0;
    };

    template <class T> struct Builder : public Base   //the class to create the object of the transport layer protocol class
    {
        void build(const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue)
	{
            T* p= new T();
            p = (T*)(TP_Hdr);    //initialize the pointer to the new class with the pointer to the beginning of the transoprt layer header in the packet.  
            p->Show_TL( TP_Hdr,  payload,  Parse_File,  ip,  AppProtocol, Is_FIX, To_Continue); // all the work with the transport layer header.
        };   
    };

    map<unsigned char, Base*> keys = {};   // the dependencies between the type of the transp layer protocol and the class with its' headers' realization

    template <class T>
    void add(const string& name);   // addind new transoprt layers protocols to map

    void fill_TL();  // filling the map

    TL_ptoto_type() {
        fill_TL();
    }
    
    void build(unsigned char ip_p, const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue);
};




