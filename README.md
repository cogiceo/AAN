# Access All Networks

Access All Networks is a multitool for passive, quiet and offensive methods against 802.1X.

It is intented to run with python3 on a linux device between 2 tapped interfaces.



## Installation

See `INSTALL.md`


## Physical setup

### Red Team
- Plug in the LAN ( `eth0` interface for XE300) to the victim's computer.
- Plug in the WAN (`eth1` interface for XE300) into the authenticating switch.

## Python script
Launch the script:

```
usage: aan.py [-h] [-f SCAPY_FILTER] [-i IFACE] [-s SPOOF_IFACE] [-v]

        AAN - A multitool for passive and offensive methods against 802.1X

        Example usage:
        python3 aan.py -f '!llc' -vv -i eth0.1 -s eth1


options:
  -h, --help            show this help message and exit
  -f SCAPY_FILTER, --filter SCAPY_FILTER
                        Scapy filter (BPF format), useful to filter out packets you don't want to analyse or see in trace mode (-vv)
  -i IFACE, --iface IFACE
                        Set tapped interface name (LAN) defaults to eth0.1
  -s SPOOF_IFACE, --spoof SPOOF_IFACE
                        Set spoof/switch interface name (WAN), defaults to eth1
  -v, --verbose         Add verbose level, default is 0, -v is debug, -vv for scapy trace
```

> Launching the script as a superuser is **mandatory**, otherwise scapy won't be able to access interfaces.


### Scapy sniff

Each mode start with a scapy analysis (scapy logs are visible with `-vv` ).

For each packet, scapy will check that:

- The packet contains an ethernet layer
- The packet MAC source isn't our interface's
- The packet contains an EAPOL or EAP layer

After this filtering, it will try to find the following:

- Port status by looking at the EAP Code.
- Authentication protocol by looking at an EAP/Request or EAP/Response type value.
- The connected supplicant's MAC address by looking at an EAPoL/Start or EAPoL/Logoff source, or an EAPoL/EAP/Response source.
- The authenticator's (switch) MAC address by looking at a EAP/Failure, EAP/Success or EAP/Request source.
- Find EAP identities over the network by looking at EAP/Response/Identity.


### Exploit with hostapd-wpe ! (Coming soon)

## Author

Louis Delahaye & Clovis Carlier