from scapy.sendrecv import sniff  # type: ignore
from scapy.layers.eap import EAP, EAPOL  # type: ignore
from scapy.layers.inet import Ether, IP  # type: ignore
from scapy.packet import Packet  # type: ignore
from json import dump
from implant.const import IEEE802_1X_MAC_BROADCAST
from implant.search import (
    search_eap_code,
    search_client_mac,
    search_identity,
    search_auth_protocol,
    search_switch_mac,
)


def analysis_wrapper(packet: Packet, cfg, logger, ana, supplicant_only_iface):
    """Logs the packets"""
    ana_modified = False
    pckt_summary = packet.summary()
    if Ether in packet:
        pckt_summary = f"({packet[Ether].src} > {packet[Ether].dst}) " + pckt_summary

        if supplicant_only_iface:
            logger.success(f"Found client mac: {packet[Ether].src}")
            if packet[Ether].src != ana["NAC"]["client_mac"]:
                ana["NAC"]["client_mac"] = packet[Ether].src
                ana_modified = True

        if IP in packet:
            if (
                packet[IP].src not in ana["ARP"]
                or ana["ARP"][packet[IP].src] != packet[Ether].src
            ):
                ana["ARP"][packet[IP].src] = packet[Ether].src
                ana_modified = True
            if (
                packet[IP].dst not in ana["ARP"]
                or ana["ARP"][packet[IP].dst] != packet[Ether].dst
            ):
                ana["ARP"][packet[IP].dst] = packet[Ether].dst
                ana_modified = True
            if (
                packet[Ether].src == ana["NAC"]["client_mac"]
                and packet[IP].src != ana["NAC"]["client_ip"]
            ):
                ana["NAC"]["client_ip"] = packet[IP].src
                ana_modified = True
            if (
                packet[Ether].dst == ana["NAC"]["client_mac"]
                and packet[IP].dst != ana["NAC"]["client_ip"]
            ):
                ana["NAC"]["client_ip"] = packet[IP].dst
                ana_modified = True
            if (
                packet[Ether].src == ana["NAC"]["switch_mac"]
                and packet[IP].src != ana["NAC"]["switch_ip"]
            ):
                ana["NAC"]["switch_ip"] = packet[IP].src
                ana_modified = True
            if (
                packet[Ether].dst == ana["NAC"]["switch_mac"]
                and packet[IP].dst != ana["NAC"]["switch_ip"]
            ):
                ana["NAC"]["switch_ip"] = packet[IP].dst
                ana_modified = True

        if packet[Ether].src not in ana["MAC"]:
            ana["MAC"].append(packet[Ether].src)
            ana_modified = True
        if packet[Ether].dst not in ana["MAC"]:
            ana["MAC"].append(packet[Ether].dst)
            ana_modified = True

    logger.trace(pckt_summary)

    # Searching for specific NAC data
    # TODO : factoriser le code?
    if interesting_pkt(packet=packet, cfg=cfg):
        pckt_summary = repr(packet).split("<Padding")[0]
        logger.success(f"Found EAP packet: {pckt_summary}")

        if authentication := search_eap_code(packet, cfg):
            logger.success(f"Found authentication status: {authentication}")
            if authentication != ana["NAC"]["auth_status"]:
                ana["NAC"]["auth_status"] = authentication.name
                ana_modified = True

        if protocol := search_auth_protocol(packet, cfg):
            logger.success(f"Found authentication protocol: {protocol}")
            if protocol.name != ana["NAC"]["auth_protocol"]:
                ana["NAC"]["auth_protocol"] = protocol.name
                ana_modified = True

        if switch_mac := search_switch_mac(packet, cfg):
            logger.success(f"Found switch mac: {switch_mac}")
            if switch_mac != ana["NAC"]["switch_mac"]:
                ana["NAC"]["switch_mac"] = switch_mac
                ana_modified = True

        if identity := search_identity(packet, cfg):
            logger.success(f"Found client identity: {identity}")
            if identity != ana["NAC"]["identity"]:
                ana["NAC"]["identity"] = identity
                ana_modified = True

        if client_mac := search_client_mac(packet, cfg, switch_mac):
            logger.success(f"Found client mac: {client_mac}")
            if client_mac != ana["NAC"]["client_mac"]:
                ana["NAC"]["client_mac"] = client_mac
                ana_modified = True
        logger.success("")  # To distinguish success packets easily

    if ana_modified:
        with open("analysis.json", "w") as f:
            dump(ana, f, indent=4)
        logger.debug("Wrote to analysis.json file.")


def nac_sniffer(cfg, logger, ana) -> None:
    sniff(
        iface=cfg["iface"],
        filter=cfg["scapy_filter"],
        prn=lambda packet: analysis_wrapper(
            packet, cfg, logger, ana, supplicant_only_iface=False
        ),
        store=False,
    )


def supplicant_sniffer(cfg, logger, ana) -> None:
    """Function wrapper for supplicant info sniff job
    Runs a sniffer on LAN/Supplicant interface, stops as soon as a MAC address
    is obtained."""

    sniff(
        iface=cfg["iface"],
        filter=cfg["scapy_filter"] if cfg["scapy_filter"] else "",
        prn=lambda packet: analysis_wrapper(
            packet, cfg, logger, ana, supplicant_only_iface=True
        ),
        stop_filter=lambda packet: Ether in packet,
        store=False,
    )


def interesting_pkt(packet: Packet, cfg) -> bool:
    """Check if a packet:
    - Has an ether layer
    - Is not from our own MAC address
    - Has an EAP layer, EAPoL layer or MAC dest is the 802.1X Multicast MAC"""
    # Packet with unknown source or Packet from our own device
    # iface_mac correspond à l'adresse MAC de l'interface WAN
    if Ether not in packet or packet[Ether].src == cfg["iface_mac"]:
        return False

    # Any 802.1x packet
    if (
        EAPOL in packet
        or EAP in packet
        or packet[Ether].dst == IEEE802_1X_MAC_BROADCAST
    ):
        return True

    return False
