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
	unsigned char ip_vhl;		   // ������ ip ��������� � ����� ���������(*4)  ip protocol version
	unsigned char ip_tos;		   // ��� ������������   type of service
	unsigned short ip_len;		   // ����� ������ ����� ������   the size of the packet
	unsigned short ip_id;		   // ����������������� ����� ������ ��� �������� ����� �� �����   identification
	unsigned short ip_off;		   // fragment offset field   
#define IP_RF 0x8000		       // ����- ����������������� ��������    reserved fragment flag 
#define IP_DF 0x4000		       // ����- ����� �� ���������������      don't fragment flag
#define IP_MF 0x2000		       // ����- ����� � ��� ���������         more fragments flag
#define IP_OFFMASK 0x1fff	       // ����� ��� ���������������� �����    mask for fragmenting bits
	unsigned char ip_ttl;		   // time to live
	unsigned char ip_p;		       // �������� ���� ������                next level protocol
	unsigned short ip_sum;		   // ��������                            checksum
	unsigned char ip_src[4];       //                                     source address
	unsigned char ip_dst[4];       //                                     dest address

	Internet_ip() {};
	~Internet_ip() {};
	void Write_IP_Addr(ofstream& Parse_File);
	int ip_size();   //the size of the internet layer header

   /* template <typename T>
    Base_TL <T>* Check_TL(ofstream& Parse_File);*/

};

/*
class  TL_ptoto_type{               //��������� ��� ������ ���� ��������� ����������� ������
public:
    struct Base
    {
        virtual ~Base() {}
        
        virtual void* get() {};
       // virtual Base_TL* build() =0;
         

    };

    template <class T> struct Builder : public Base
    {
        
        Base_TL <T>* build() {
            return new T();
        };
        void* get() { build(); };
        
    };

    map<unsigned char, Base*> keys = {};

    template <class T>
    void add(const string& name);

   
    void fill_TL();

    TL_ptoto_type() {
        fill_TL();
    }
    

    template <typename T>
    Base_TL <T>* build(unsigned char ip_p, ofstream& Parse_File);
};

*/


