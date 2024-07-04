## Configurations

```bash
# (Optional)
vi implant/const.py #  edit to you liking, default iface
```

### Gl-inet

These have been tested on a Gl-Inet XE300 running  OpenWrt 22.03.4, r20123-38ccc47687.

- Install packages needed for AAN:

```bash
opkg update
opkg install python3 scapy
```


### Development Linux

```bash
sudo python3 -m pip install -r requirements.txt
# (Sudo is required since the program will require root to launch because of scapy's usage of sockets)
```

