#include "Transport.h"
#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<map>
#include<fstream>

void Port_type::fill_port()
{       //пары номер порта- строка с названием протокола прикладного уровня    filling the map with the pairs "number of the port - name of the application layer protocol "
    mp_port.insert({ 25 ,"Simple Mail Transfer Protocol" });
    mp_port.insert({ 53 ,"Domain Name Server" });
    mp_port.insert({ 33,"Display Support Protocol" });
    mp_port.insert({ 80,"HyperText Transfer Protocol" });
    mp_port.insert({ 110,"Post Office Protocol - Version 3 " });
    mp_port.insert({ 143,"Internet Message Access Protocol" });
    mp_port.insert({ 161,"Simple Network Management Protocol" });
    mp_port.insert({ 179,"Border Gateway Protocol" });
}

void  Port_type::Check_App_Protocol(ofstream& Parse_File, unsigned short AppProtocol) 
{
    map<unsigned short, string>::iterator it;
    if (mp_port.find(ntohs(AppProtocol)) != mp_port.end())
    {
        Parse_File << mp_port.find(ntohs(AppProtocol))->second;
    }
    else
    {
        Parse_File << "Unknown Application Layer Protocol";
    }
}

void Transport_tcp::Show_TL(const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX,  bool& To_Continue) const {
    
    int count = 1, sum = 0, tag10 = 0, FIX_Length = 0;   //tag10= the checksum of the FIX protocol in the tag 10
    int TCP_Length, Payload_Length;
    TCP_Length = (th_offx2) >> 4;      //the TCP header length
    Payload_Length = ntohs(ip->ip_len) - ip->ip_size() - (TCP_Length * 4);    // the payload length

    payload = (const char*)(TP_Hdr + TCP_Length * 4);
    AppProtocol = dst_port;                                               //determinate the dst port

    Parse_File << "TCP, Src port: " << ntohs(src_port) << ", Dst port: " << ntohs(dst_port)
        << " Seq: " << ntohl(th_seq) << " Ack: " << ntohl(th_ack) << " Len: " << Payload_Length << endl;


    if ((Payload_Length != 0) && (*payload == '8') && (*(payload + 1) == '=') && (*(payload + 2) == 'F') && (*(payload + 3) == 'I') && (*(payload + 4) == 'X')) //checking the FIX
    {
       
        Parse_File << "Financial Information Exchange Protocol: ";
        Is_FIX = true;
        while (count <= (Payload_Length - 7))     //sum the bytes till the tag 10
        {
            sum += (*payload);
            payload++;
            count++;
        }
        char x = (* (payload+3));
        tag10 += (x - '0') * 100;
        x= (* (payload + 4));
        tag10 += (x - '0') * 10;
        x = (* (payload + 5));
        tag10 += (x - '0');
        
        ((sum % 256) != tag10) ? Parse_File << "The FIX checksum is incorrect" << endl : Parse_File << "The FIX checksum is correct" << endl;
    }

	
}


void Transport_udp::Show_TL(const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue)  const {
	payload = (const char*)(TP_Hdr + 8);
	AppProtocol = dst_port;      //determinate the dst port
	Parse_File << "UDP, Src port: " << ntohs(src_port) << ", Dst port: " << ntohs(dst_port) << ", Len:" << ntohs(udp_length) << endl;
}

void Transport_ICMP::Show_TL(const unsigned char* TP_Hdr, const char* payload, ofstream& Parse_File, Internet_ip* ip, unsigned short& AppProtocol, bool& Is_FIX, bool& To_Continue) const {
	Parse_File << "Protocol: ICMP" << endl;
	payload = (const char*)(TP_Hdr + 4);
	To_Continue = true;
}
