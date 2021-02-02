#ifdef _WIN32
#include<pcap.h>
#include <iostream>
#include <string>
#include<fstream>
#include<map>
#include<stdexcept>
#include<thread>
#include<memory>
#include <typeinfo>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

#include<Winsock2.h> //константы протоколов Windows, для Linux netinet/in.h
#include"Link.h"
#include"Internet.h"
#include"Transport.h"

#else
#include<netinet/in.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<pcap.h>
#include <string>
#include<fstream>
#include<map>
#include<stdexcept>
#include<thread>
#include"Link.h"
#include"Internet.h"
#include"Transport.h"
#endif


using namespace std;



void Parse()     //parsing the dumped packets
{
    pcap_t* Handle;                        //the pointer to the session of reading packets from the file 
    Link* ethernet = nullptr;              //the pointer to the Ethernet header                              
    Internet_ip* ip = nullptr;;            //the pointer to the IP header
    unsigned short AppProtocol = 0;        //the destination port to determinate the application layer protocol 
    const char* payload = nullptr;;        //the pointer to the begining of the data
    char errbuf[PCAP_ERRBUF_SIZE];         //the buffer for the exception information
    unsigned short* CheckVLAN = nullptr;   //the pointer to the beginning of the VLAN tag if there is one
    int count = 0;                         //the number of the packet
    pcap_pkthdr* header = nullptr;;         //the pointer to the packet header
    const u_char* packet = nullptr;;       //the pointer to the beginning of the Ethernet header
    bool Is_FIX = false, Is_VLAN = false, To_Continue = false;    //if there is the VLAN or the FIX protocol
    const char* fname = "local_fix_sample.pcap";


    if ((Handle = pcap_open_offline(fname, errbuf)) == NULL)        //openig the file for reading the packets
    {
        cout << "Can't open the file";
        pcap_close(Handle);
        return;              //closing the session
    }

    ofstream Parse_File;                                  //creating the ofstream object 
    Parse_File.open("Parsing.txt", ios::out | ios::app);  //opening the file for writing
    if (!Parse_File)
    {
        cout << "Can't open the writing file";
        pcap_close(Handle);   //closing the session
        return;
    }


    int Read_Packet = 1;

    while ((Read_Packet = pcap_next_ex(Handle, &header, &packet)) == 1)    //while a packet is read sucessfully 
    {
        count++;               //incrementing the packet counter

        Parse_File << endl << endl << "Frame # " << count << ", on wire: " << header->caplen << " bytes, captured: " << header->len << " bytes." << endl; //the packet length and how many bytes are captured

        ethernet = (Link*)(packet);
        ethernet->Write_MAC_Addr(Parse_File);        // write the MAC adresses in the file
        CheckVLAN = (unsigned short*)(packet + 12);  // pointing the CheckVLAN to the beginning of the potential VLAN protocol
        ethernet->VLAN_Protocol(packet, Parse_File, Is_VLAN, CheckVLAN);  //Checking if there is the VLAN protocol
        ethernet->Check_IP_Protocol(To_Continue, Parse_File);  //Checking the Internet Layer Protocol

        if (To_Continue == true)      //if the IP layer is not the IPv4 - continue
        {
            To_Continue = !To_Continue;
            continue;
        }
        const unsigned char* IP_Hdr = (Is_VLAN == true ? (packet + 18) : (packet + 14));   //determinate the beginning of the IP header
        ip = (Internet_ip*)(IP_Hdr);
        ip->Write_IP_Addr(Parse_File);
        const unsigned char* TP_Hdr = (Is_VLAN == true ? (packet + 18 + ip->ip_size()) : (packet + 14 + ip->ip_size()));   //determinate the beginning of the Transport layer header
        unsigned short IP_Len = ntohs(ip->ip_len);
        int IP_Size = ip->ip_size();
        ip->Check_TL(Parse_File, TP_Hdr, payload, AppProtocol, Is_FIX, To_Continue);

       
        if (To_Continue == true)          //if the Transport Layer protocol is unknown or the dst port can't be determinated - continue
        {
            To_Continue = !To_Continue;
            continue;
        }

        if (Is_FIX == false)        //determinate the application layer protocol
        {
            Parse_File << "Application Layer Protocol: ";
            Port_type Obj_Port;
            Obj_Port.Check_App_Protocol(Parse_File, AppProtocol);
        }

        Is_FIX = false;
        Is_VLAN = false;


    }



    if (Read_Packet == PCAP_ERROR_BREAK)    //handle exceptions
    {
        cout << endl << "End of file ";
        Parse_File << endl << "End of file ";
        pcap_close(Handle);
        return;

    }
    else if (Read_Packet == PCAP_ERROR)    //handle exceptions
    {
        cout << "Error reading file";
        Parse_File << endl << "Error reading file";
        pcap_close(Handle);
        return;
    }



}




int main()
{

    Parse();



    return 0;
}
