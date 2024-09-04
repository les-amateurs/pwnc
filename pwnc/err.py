import logging

def require(cmd: str):
    logging.error(f"{cmd} is required for this functionality.")

def info(msg: str):
    logging.info(msg)

def warn(msg: str):
    logging.warn(msg)

def fatal(msg: str):
    logging.error(msg)
    raise RuntimeError("fatal error")