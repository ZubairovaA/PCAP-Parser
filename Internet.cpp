#include "Internet.h"
#include "Transport.h"
#include <pcap.h>
#include <iostream>
#include <string>
#include<fstream>
#include<memory>
#include <typeinfo>

using namespace std;


void Internet_ip::Write_IP_Addr(ofstream& Parse_File)
{
	Parse_File << "Dst ip adress: " << (int)(ip_dst[0]) << '.' << (int)(ip_dst[1]) << '.' << (int)(ip_dst[2]) << '.' << (int)(ip_dst[3]) << endl;
	Parse_File << "Src ip adress: " << (int)(ip_src[0]) << '.' << (int)(ip_src[1]) << '.' << (int)(ip_src[2]) << '.' << (int)(ip_src[3]) << endl;
}

int Internet_ip::ip_size() 
{
	return 4 * (ip_vhl & 0x0F);
}




void Internet_ip::Check_TL(ofstream& Parse_File , const unsigned char* TP_Hdr, const char* payload, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue) 
{
     TL_ptoto_type Obj_TL;
	  Obj_TL.build(this->ip_p, TP_Hdr, payload, Parse_File, this,  AppProtocol,Is_FIX, To_Continue);	  
}


  void TL_ptoto_type::fill_TL()
  {
	  keys.insert({ IPPROTO_TCP, new Builder <Transport_tcp>() });
	  keys.insert({ IPPROTO_UDP, new Builder <Transport_udp>() });
	  keys.insert({ IPPROTO_ICMP, new Builder <Transport_ICMP>() });
  }

 
 
  void TL_ptoto_type::build(unsigned char ip_p, const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue)
  {
	  const auto found = keys.find(ip_p);
	  if (found == keys.cend())
	  {  
	  Parse_File << "Transport Layer Protocol: Unknown" << endl;
      }
	 found->second->build(TP_Hdr, payload, Parse_File, ip, AppProtocol, Is_FIX, To_Continue);
	 
}

  template <class T>
  void TL_ptoto_type:: add(const string& name)
  {
	  keys.insert({ name, new Builder<T>() });
  }
