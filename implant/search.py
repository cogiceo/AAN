from typing import Optional
from scapy.layers.inet import Ether  # type: ignore
from scapy.layers.eap import EAP, EAPOL  # type: ignore
from scapy.packet import Packet  # type: ignore
from implant.type import EAPCode, EAPOLType, EAPType


def search_eap_code(
    packet: Packet,
    cfg,
) -> Optional[EAPCode]:
    """Extract the connected switch port status from packet"""

    if EAP in packet and packet[EAP].code in [
        member.value for member in EAPCode.__members__.values()
    ]:
        return EAPCode(packet[EAP].code)

    # By default return None
    return None


def search_auth_protocol(
    packet: Packet,
    cfg,
) -> Optional[EAPType]:
    """Extract the EAP auth protocol from packet"""

    # Non EAP Request
    # packet[EAP].code is an int
    if EAP in packet and packet[EAP].code != EAPCode.REQUEST.value:
        return None

    # 802.1x Request Protocol
    # packet[EAP].type is an int
    if (
        EAP in packet
        and packet[EAP].type
        and packet[EAP].type
        in [member.value for member in EAPType.__members__.values()]
    ):
        return EAPType(packet[EAP].type)

    # By default return None
    return None


def search_client_mac(
    packet: Packet,
    cfg,
    switch_mac: Optional[str],
) -> Optional[str]:
    """Extract the supplicant MAC from the packet"""

    # Packet from the switch
    if switch_mac is not None and packet[Ether].src == switch_mac:
        return None

    # Non 802.1x packet
    if EAPOL not in packet:
        # return packet[Ether].src
        return None

    # 802.1x EAPOL Start or Logoff
    if packet[EAPOL].type in [
        EAPOLType.START.value,
        EAPOLType.LOGOFF.value,
    ]:
        return packet[Ether].src

    # Client is the 802.1x EAP Response source
    if (
        packet[EAPOL].type == EAPOLType.EAP_PACKET.value
        and EAP in packet
        and packet[EAP].code == EAPCode.RESPONSE.value
    ):
        return packet[Ether].src

    # By default return None
    return None


def search_switch_mac(
    packet: Packet,
    cfg,
) -> Optional[str]:
    """Extract the switch MAC from the packet"""

    # 802.1x EAP Failure, Success or Request
    if EAP in packet and packet[EAP].code in [
        EAPCode.FAILURE.value,
        EAPCode.SUCCESS.value,
        EAPCode.REQUEST.value,
    ]:
        return packet[Ether].src

    # By default return None
    return None


def search_identity(
    packet: Packet,
    cfg,
) -> Optional[str]:
    """Extract identity (as a string) from the packet"""

    # Non 802.1x Identity Response
    if (
        EAP in packet
        and packet[EAP].code == EAPCode.RESPONSE.value
        and packet[EAP].type == EAPType.IDENTITY.value
    ):
        return packet[EAP].identity.decode("utf-8")

    return None
