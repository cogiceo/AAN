from enum import Enum


class EthernetType(Enum):
    AUTH_802_1x = 34958


class EAPOLType(Enum):
    EAP_PACKET = 0
    START = 1
    LOGOFF = 2
    KEY = 3


class EAPCode(Enum):
    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    INITIATE = 5
    FINISH = 6


class EAPType(Enum):
    IDENTITY = 1
    NOTIFICATION = 2
    EAP_MD5 = 4
    EAP_TLS = 13
    LEAP = 17
    EAP_TTLS = 21
    EAP_PEAP = 25
    EAP_MS_AUTH = 26
    EAP_FAST = 43
