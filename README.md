# QuickFilt
a stateless firewall system for ubuntu based on  the netfilter framework and scapy library
# Usage
First run the command 
iptables -A INPUT -j NFQUEUE --queue-num 1


This command forces all the packets to go to queue 1 of the netfilter queue rather than the network stack,we bind a python program to the netfilter queue to process the packet and make the decision

Input:A json file which acts as a blacklist and packets
Output:Accept or drop the packet based in accordance to the json file

Features:Filtering can be done based on a) ip address b)port number c)based on prefix(ip address ex: 171. ,192.168. etc)


