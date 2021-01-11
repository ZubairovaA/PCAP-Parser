#pragma once
#include <pcap.h>

#include <iostream>
#include <string>
#include<map>
#include "Link.h"

using namespace std;


void Eth_type::fill_mp()
{                            // заполнение map парами "тип протокола- строка с названием"   filling the map with the pairs "type of protocol - name"
    mp.insert({ 0x0806 ,"Address Resolution Protocol/n" });
    mp.insert({ 0x22F0 ,"Audio Video Transport Protocol/n" });
    mp.insert({ 0x8102 ,"Simple Loop Prevention Protocol/n" });
    mp.insert({ 0x22EA ,"Multiple Stream Registration Protocol/n" });
    mp.insert({ 0x88F7 ,"Precision Time Protocol/n" });


}

