#include "Internet.h"
#include "Transport.h"
#include <pcap.h>
#include <iostream>
#include <string>
#include<fstream>
#include<memory>
#include <typeinfo>

using namespace std;


void Internet_ip::Write_IP_Addr(ofstream& Parse_File) {
	Parse_File << "Dst ip adress: " << (int)(ip_dst[0]) << '.' << (int)(ip_dst[1]) << '.' << (int)(ip_dst[2]) << '.' << (int)(ip_dst[3]) << endl;
	Parse_File << "Src ip adress: " << (int)(ip_src[0]) << '.' << (int)(ip_src[1]) << '.' << (int)(ip_src[2]) << '.' << (int)(ip_src[3]) << endl;

}

int Internet_ip::ip_size() {
	return 4 * (ip_vhl & 0x0F);
}


/*
template <typename T>
Base_TL <T>* Internet_ip::Check_TL(ofstream& Parse_File) {
     TL_ptoto_type Obj_TL;
	 template <typename T>
	 Base_TL <T>* p= Obj_TL.build(this->ip_p, Parse_File);
	 return p;
   
 }


  void TL_ptoto_type::fill_TL()
  {
		  keys.insert({ IPPROTO_TCP, new Builder <Transport_tcp>() });
		  keys.insert({ IPPROTO_UDP, new Builder <Transport_udp>() });
		  keys.insert({ IPPROTO_ICMP, new Builder <Transport_ICMP>() });
		 
  }

 
  template <typename T>
  Base_TL <T>* TL_ptoto_type::build(unsigned char ip_p, ofstream& Parse_File)
  {
	  const auto found = keys.find(ip_p);
	  if (found == keys.cend())
	  {  
	  Parse_File << "Transport Layer Protocol: Unknown" << endl;
	  return nullptr;
       }
	return found->second->get();
}

  template <class T>
  void TL_ptoto_type:: add(const string& name)
  {
	  keys.insert({ name, new Builder<T>() });
  }
 */