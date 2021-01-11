#ifdef _WIN32
#include<pcap.h>
#include <iostream>
#include <string>
#include<fstream>
#include<map>
#include<stdexcept>
#include<thread>
#include<memory>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib , "wpcap.lib")
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


void Parse( )     //parsing the dumped packets
{
    pcap_t* Handle;                        //the pointer to the session of reading packets from the file 
    Link* ethernet = nullptr;                        //the pointer to the Ethernet header                              
    Internet_ip* ip = nullptr;;                       //the pointer to the IP header
    unsigned short AppProtocol = 0;        //the destination port to determinate the application layer protocol 
    const char* payload = nullptr;;                   //the pointer to the begining of the data
    unsigned int size_ip = 0;              //the size of the internet layer header
    char errbuf[PCAP_ERRBUF_SIZE];         //the buffer for the exception information
    unsigned short* CheckVLAN = nullptr;   //the pointer to the beginning of the VLAN tag if there is one
    int count = 0;                         //the number of the packet
    pcap_pkthdr* header= nullptr;;            //the pointer to the packet header
    const u_char* packet = nullptr;;                  //the pointer to the beginning of the Ethernet header
    bool Is_VLAN = false, Is_FIX=false;    //if there is the VLAN or the FIX protocol
    const char* fname = "local_fix_sample.pcap";
   
    
        if ((Handle = pcap_open_offline(fname, errbuf)) == NULL)        //openig the file for reading the packets
        {  cout << "Can't open the file";
            pcap_close(Handle);                                         //closing the session
        }

        
        
        ofstream Parse_File;                                  //creating the ofstream object 
        Parse_File.open("Parsing.txt", ios::out | ios::app);  //opening the file for writing
        if (!Parse_File) 
        {
            cout << "Can't open the writing file";
            pcap_close(Handle);                               //closing the session
        }
    

    int Read_Packet = 1;
    
        while ((Read_Packet = pcap_next_ex(Handle, &header, &packet)) ==1)    //while a packet is read sucessfully 
        {
            count++;               //incrementing the packet counter
            
            Parse_File << endl << endl <<"Frame # " << count << ", on wire: " << header->caplen << " bytes, captured: " << header->len << " bytes."<<endl; //the packet length and how many bytes are captured
            
            ethernet = (Link*)(packet);    
            Parse_File << "Ethernet II, Src: " << ntohs(ethernet->ether_shost[0]) << ":" << ntohs(ethernet->ether_shost[1]) << ":" << ntohs(ethernet->ether_shost[2]) << "_"   //the source MAC adress 
                << ntohs(ethernet->ether_shost[3]) << ":" << ntohs(ethernet->ether_shost[4]) << ":" << ntohs(ethernet->ether_shost[5]);

            Parse_File << ", Dst: " << ntohs(ethernet->ether_dhost[0]) << ":" << ntohs(ethernet->ether_dhost[1]) << ":" << ntohs(ethernet->ether_dhost[2]) << "_"              //the destination MAC adress
                << ntohs(ethernet->ether_dhost[3]) << ":" << ntohs( ethernet->ether_dhost[4]) << ":" << ntohs(ethernet->ether_dhost[5]) << endl;

            CheckVLAN = (unsigned short*)(packet + 12);   // 
            if (ntohs(*CheckVLAN) == 0x8100)             // checking for the VLAN tag  
            {
                Parse_File << "VLAN" << endl;
                CheckVLAN +=2;                          //if there is the VLAN tag, mooving the VLAN pointer for the 4 bytes to determinate the beginning of the ether type 
                ethernet->ether_type = *CheckVLAN;
                Is_VLAN = true;
            }

            if (ntohs(ethernet->ether_type) == 0x0800)   //if the internet layer protocol is the Internet Protocol Verion 4
            {
                Parse_File << "Internet Protocol Verion 4, "<<endl;
            }
            else if (ntohs(ethernet->ether_type) == 0x86DD)   //if the internet layer protocol is the Internet Protocol Verion 6
            {
                Parse_File << "Internet Protocol Verion 6, ";
                continue;
            }
            else                                             //if it's not the IPv4 or IPv6 protocol
            {
                Eth_type Obj;
                map<unsigned short, string>::iterator it;
                if (Obj.mp.find(ntohs(ethernet->ether_type)) != Obj.mp.end())
                {
                    Parse_File << Obj.mp.find(ntohs(ethernet->ether_type))->second;
                }
                else
                {
                    Parse_File << "Unknown Protocol"<<endl;
                }
                continue;                     //mooving to the next packet
            }

           const unsigned char* IP_Hdr = (Is_VLAN==true? (packet + 18):(packet + 14));   //determinate the beginning of the IP header
           ip = (Internet_ip*)(IP_Hdr);  

           
           Parse_File << "Dst ip adress: " << (int)(ip->ip_dst[0]) << '.' << (int)(ip->ip_dst[1]) << '.' << (int)(ip->ip_dst[2]) << '.' << (int)(ip->ip_dst[3]) << endl;
           Parse_File << "Src ip adress: " <<(int) (ip->ip_src[0]) << '.' << (int)(ip->ip_src[1]) << '.' << (int)(ip->ip_src[2]) << '.' << (int)(ip->ip_src[3]) << endl;

           int ip_size = 4 * (ip->ip_vhl & 0x0F);      //the size of the internet layer header
           const unsigned char* TP_Hdr = (Is_VLAN == true ? (packet + 18 + ip_size) : (packet + 14 + ip_size));   //determinate the beginning of the Transport layer header
           int count = 1, sum = 0, tag10 = 0, FIX_Length = 0;   //tag10= the checksum of the FIX protocol in the tag 10
  
            switch (ip->ip_p)           //determinate the the Transport layer protocol
            {
            case IPPROTO_TCP:
                Transport_tcp* tcp;         //if the Transport layer protocol is TCP
                tcp = (Transport_tcp*)(TP_Hdr);     
                int TCP_Length, Payload_Length;
                TCP_Length = (tcp->th_offx2) >>4;      //the TCP header length
                Payload_Length = ntohs(ip->ip_len) - ip_size - (TCP_Length*4);    // the payload length
                
                payload =(const char*)(TP_Hdr + TCP_Length*4);   
                AppProtocol = tcp->dst_port;                                               //determinate the dst port
                
                Parse_File << "TCP, Src port: " << ntohs(tcp->src_port) << ", Dst port: " << ntohs(tcp->dst_port)
                    << " Seq: " << ntohl(tcp->th_seq) << " Ack: " << ntohl(tcp->th_ack) << " Len: " << Payload_Length << endl;
               
                 
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

                    count = 1;
                    while (count <= Payload_Length)    //determinate the checksum in the tag 10
                    {
                        if (count == 4) 
                        {
                            char x = (*payload);
                            tag10 += (x - '0') * 100;
                        }
                        if (count == 5) 
                        {
                            char x = (*payload);
                            tag10 += (x - '0') * 10;
                        }
                        if (count == 6) 
                        {
                            char x = (*payload);
                            tag10 += (x - '0');
                        }
                        count++;
                        payload++;
                    }

                    ((sum % 256) != tag10) ? Parse_File << "The FIX checksum is incorrect" << endl : Parse_File << "The FIX checksum is correct" << endl;
                }
                   
                break;

            case IPPROTO_UDP:   //if the Transport layer protocol is UDP
                const Transport_udp* udp;
                udp = (Transport_udp*)(TP_Hdr);             
                payload = (const char*)(TP_Hdr + 8);    
                AppProtocol = udp->dst_port;      //determinate the dst port
                Parse_File << "UDP, Src port: " << ntohs(udp->src_port) << ", Dst port: " << ntohs(udp->dst_port) << ", Len:" << ntohs(udp->udp_length) << endl;
                break;


            case IPPROTO_ICMP:       //if the Transport layer protocol is ICMP
                const Transport_ICMP* icmp;
                Parse_File << "Protocol: ICMP"<<endl;
                icmp = ( Transport_ICMP*)(TP_Hdr);    
                payload = (const char*)(TP_Hdr + 4);   
                break;

            default:       // if the Transport layer protocol is unknown
                Parse_File << "Transport Layer Protocol: Unknown"<<endl;
               
            }

            if (Is_FIX == false)
            {
                Parse_File << "Application Layer Protocol: ";       //determinate the application layer protocol
                Port_type Obj_Port;
                map<unsigned short, string>::iterator it;
                if (Obj_Port.mp_port.find(ntohs(AppProtocol)) != Obj_Port.mp_port.end())
                {
                    Parse_File << Obj_Port.mp_port.find(ntohs(AppProtocol))->second;
                }
                else
                {
                    Parse_File << "Unknown Application Layer Protocol";
                }
            }

          
            
        }


    
        if (Read_Packet == PCAP_ERROR_BREAK )    //handle exceptions
        {
            cout << "End of file ";
            Parse_File << "End of file ";
            pcap_close(Handle);
       
        }
        else if ( Read_Packet == PCAP_ERROR)    //handle exceptions
        {
            cout << "Error reading file";
            Parse_File << "Error reading file";
            pcap_close(Handle);
        }
      
        
        
}




int main()
{
 
   Parse();
  
  

    return 0;
}
