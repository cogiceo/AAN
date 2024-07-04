# 802.1X Multicast MAC address assigned by the IEEE
IEEE802_1X_MAC_BROADCAST = "01:80:c2:00:00:03"

HISTORY_BUFFER = 10000000  # 10MB

LOGFILE = "aan.log"

# Default config for glinet xe300
default_config_d = {
    "iface": "eth0.1",
    "spoof_iface": "eth1",
    "request_timeout": 5,
    "scapy_filter": "",
}

default_ana_d = {
    "NAC": {
        "auth_status": "",
        "auth_protocol": "",
        "switch_mac": "",
        "switch_ip": "",
        "client_ip": "",
        "client_mac": "",
        "identity": "",
    },
    "ARP": {},
    "MAC": [],
}
