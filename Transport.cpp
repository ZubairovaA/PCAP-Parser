#include "Transport.h"
#pragma once
#include <pcap.h>
#include <iostream>
#include <string>
#include<map>

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
