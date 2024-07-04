from implant.const import (
    LOGFILE,
    HISTORY_BUFFER,
    default_config_d,
)
from implant.system import get_mac, interface_status
import argparse
import logging
import logging.handlers

# Add custom log levels
logging.TRACE = 5
logging.addLevelName(5, "TRACE")

logging.SUCCESS = 25
logging.addLevelName(25, "SUCCESS")


""" Class used by the logger to use colors """


class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    bold_yellow = "\033[33;49;1m"
    bold_blue = "\033[34;49;1m"
    bold_cyan = "\033[36;49;1m"
    bold_red = "\033[31;49;1m"
    critical_red = "\033[30;41;1m"
    bold_green = "\033[32;49;1m"
    reset = "\033[0m"

    format = "%(asctime)s - %(levelname)s - %(message)s"  # (%(filename)s:%(lineno)d) for debug

    FORMATS = {
        logging.TRACE: grey + format + reset,
        logging.SUCCESS: bold_green + format + reset,
        logging.DEBUG: bold_blue + format + reset,
        logging.INFO: bold_cyan + format + reset,
        logging.WARNING: bold_yellow + format + reset,
        logging.ERROR: critical_red + format + reset,
        logging.CRITICAL: critical_red + format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


def load_config(logger, args):
    """Loads config dict from default configuration, overwrites with args."""

    cfg = default_config_d

    try:
        if args.iface:
            cfg["iface"] = args.iface
        else:
            logger.info(
                f"No interface provided, defaulting to {default_config_d['iface']}"
            )
        if interface_status(logger, cfg["iface"]) != "up":
            logger.error(f"Down network interface ({cfg['iface']}), exiting...")
            exit(1)
        else:
            cfg["iface_mac"] = get_mac(logger, cfg["iface"])

        if args.spoof_iface:
            cfg["spoof_iface"] = args.spoof_iface
        else:
            logger.info(
                f"No spoof interface provided, defaulting to {default_config_d['spoof_iface']}"
            )
        if interface_status(logger, cfg["spoof_iface"]) != "up":
            logger.error(f"Down spoof interface ({cfg['spoof_iface']}), exiting...")
            exit(1)
        else:
            cfg["spoof_iface_mac"] = get_mac(logger, cfg["spoof_iface"])

        if args.scapy_filter:
            cfg["scapy_filter"] = args.scapy_filter

        return cfg
    except Exception as e:
        logging.exception(e)


def logger_setup(verbose_value: int):
    """Setup logging logger"""

    stdout_log = logging.StreamHandler()
    stdout_log.setLevel([logging.INFO, logging.DEBUG, logging.TRACE][verbose_value])
    stdout_log.setFormatter(CustomFormatter())

    file_log = logging.handlers.RotatingFileHandler(
        LOGFILE, maxBytes=HISTORY_BUFFER, backupCount=10
    )
    file_log.setLevel(logging.TRACE)
    file_log.setFormatter(CustomFormatter())

    logging.basicConfig(
        level=logging.TRACE,
        format="[%(asctime)s] %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
        handlers=[file_log, stdout_log],
    )

    logger = logging.getLogger()
    logger.trace = lambda *args: logger.log(logging.TRACE, *args)
    logger.success = lambda *args: logger.log(logging.SUCCESS, *args)
    return logger


def getargs():
    """Argparse declaration and parsing"""

    parser = argparse.ArgumentParser(
        description="""
        AAN - A multitool for passive and offensive methods against 802.1X

        Example usage:
        python3 aan.py -f '!llc' -vv -i eth0.1 -s eth1
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="Scapy filter (BPF format), useful to filter out packets you don't want\
 to analyse or see in trace mode (-vv)",
        default="",
        dest="scapy_filter",
    )
    parser.add_argument(
        "-i",
        "--iface",
        help=f"Set tapped interface name (LAN) defaults to {default_config_d['iface']}",
        dest="iface",
    )
    parser.add_argument(
        "-s",
        "--spoof",
        help=f"Set spoof/switch interface name (WAN), defaults to {default_config_d['spoof_iface']}",
        dest="spoof_iface",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Add verbose level, default is 0, -v is debug, -vv for scapy trace",
        action="count",
        default=0,
    )
    return parser.parse_args()
