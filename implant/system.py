from subprocess import call, DEVNULL


def get_mac(logger, interface: str = "") -> str:
    """Find the mac address linked to the provided interface"""
    # In case we didn't set interface
    if not interface:
        logger.critical("No interface were provided")
        exit(1)

    # We could have checked with interface_status, however i'm sure Linux
    # can find another way to make this fail
    try:
        return open(f"/sys/class/net/{interface}/address").readline().strip()
    except Exception:
        logger.critical(
            f"Error while trying to find MAC address of interface: {interface}"
        )
        exit(1)


def interface_status(logger, interface: str) -> str:
    """Return interface status as a string "up" or "down" """
    try:
        with open(f"/sys/class/net/{interface}/operstate", "r") as file:
            return file.read().strip()
    except Exception:
        logger.error(f"Could not get interface {interface} status")
        return "down"


def tc_mirror_up(cfg, logger) -> None:
    """Bridge cfg["iface"] and cfg["spoof_iface"] with traffic control utility"""

    if not (cfg["iface"] and cfg["spoof_iface"]):
        logger.critical(f"Could not find both interface to mirror in config: {cfg}")
        exit(1)

    # Remove potential old ingress queuing disciplines
    call(["tc", "qdisc", "del", "dev", cfg["iface"], "ingress"], stderr=DEVNULL)
    call(["tc", "qdisc", "del", "dev", cfg["spoof_iface"], "ingress"], stderr=DEVNULL)

    #  Create new ones
    if call(["tc", "qdisc", "add", "dev", cfg["iface"], "ingress"]) != 0 or \
            call(["tc", "qdisc", "add", "dev", cfg["spoof_iface"], "ingress"]) != 0:
        logger.critical("Unable to create new qdisc disciplines")
        exit(1)

    # Add a mirror filter
    if call(
        [
            "tc", "filter", "add", "dev", cfg["iface"], "parent", "ffff:",
            "protocol", "all", "u32", "match", "u32", "0", "0", "action",
            "mirred", "egress", "mirror", "dev", cfg["spoof_iface"],
        ]
    ) != 0 or call(
        [
            "tc", "filter", "add", "dev", cfg["spoof_iface"], "parent",
            "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0",
            "action", "mirred", "egress", "mirror", "dev", cfg["iface"],
        ]
    ) != 0:
        logger.critical("Unable to create new qdisc mirror")
        exit(1)

    logger.success("Mirror tc filter is up!")


def tc_mirror_down(cfg, logger) -> None:
    """Remove traffic control utility mirror between cfg["iface"] and cfg["spoof_iface"]"""
    if not (cfg["iface"] and cfg["spoof_iface"]):
        logger.critical(f"Could not find both interface to mirror in config: {cfg}")
        exit(1)

    # Remove ingress queuing disciplines
    call(["tc", "qdisc", "del", "dev", cfg["iface"], "ingress"], stderr=DEVNULL)
    call(["tc", "qdisc", "del", "dev", cfg["spoof_iface"], "ingress"], stderr=DEVNULL)

    logger.success("Mirror tc filter is down!")
