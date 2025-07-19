import logging

logger = logging.getLogger("pwnc")


def require(cmd: str):
    logger.error(f"{cmd} is required for this functionality.")


def info(msg: str):
    logger.info(msg)


def warn(msg: str):
    logger.warn(msg)


def fatal(msg: str):
    logger.error(msg)
    raise RuntimeError("fatal error")
