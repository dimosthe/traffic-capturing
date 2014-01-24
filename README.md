# traffic-capturing

A python tool for capturing incoming and outgoing traffic from a network device in Linux

## Requirements

* Python 2.7
* pcapy module
* impacket module

## How to run

sudo python tcapture.py <network device name> <time in seconds> [-v],
insert -v in order to get the src and dest of each packet

