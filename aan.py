#!/usr/bin/python3
try:
    from implant.setup import (
        load_config,
        logger_setup,
        getargs,
    )
    from implant.const import default_ana_d
    from implant.traffic import nac_sniffer, supplicant_sniffer
    from implant.system import tc_mirror_up, tc_mirror_down


except Exception as e:
    print("You are missing a package, please follow installation steps")
    raise (e)

ana = default_ana_d


def main(args: dict[str:]):
    logger = logger_setup(args.verbose)
    cfg = load_config(logger=logger, args=args)

    logger.debug(f"Loaded config: {cfg}")

    # Forward all 802.1X packets
    logger.info("AAN starting...")

    # Supplicant only pre-analysis to fetch client mac
    # Needed only if we don't have it yet
    if cfg["iface"] and cfg["spoof_iface"]:
        logger.debug("Starting supplicant-only pre-analysis... (Ctrl+C to skip)")
        tc_mirror_down(cfg=cfg, logger=logger)
        supplicant_sniffer(cfg, logger, ana)
        tc_mirror_up(cfg=cfg, logger=logger)
    else:
        logger.error(
            f"Could not perform supplicant-only pre-analysis,\
 missing interface in config: {cfg}"
        )
        exit()
    logger.debug(f"Starting NAC analysis on {cfg['iface']}...")
    nac_sniffer(cfg, logger, ana)


if __name__ == "__main__":
    main(getargs())
