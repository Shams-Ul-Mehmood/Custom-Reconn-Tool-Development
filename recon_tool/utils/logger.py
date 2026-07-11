import logging

def setup_logger(verbosity):
    level = logging.INFO
    if verbosity >= 1:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger("recon_tool")
