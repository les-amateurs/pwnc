import logging
import colorama

logger = logging.getLogger("pwnc")
logger.setLevel(logging.INFO)
channel = logging.StreamHandler()

class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    ERROR = (
        colorama.Fore.WHITE
        + colorama.Back.RED
        + "ERROR"
        + colorama.Fore.RESET
        + colorama.Back.RESET
    )
    WARNING = colorama.Fore.YELLOW + "!" + colorama.Fore.RESET
    INFO = colorama.Fore.BLUE + "*" + colorama.Fore.RESET
    DEBUG = colorama.Fore.GREEN + "+" + colorama.Fore.RESET

    FORMATS = {
        logging.ERROR: f"[{ERROR}] %(msg)s",
        logging.WARNING: f"[{WARNING}] %(msg)s",
        logging.INFO: f"[{INFO}] %(msg)s",
        logging.DEBUG: f"[{DEBUG}] %(msg)s",
        "DEFAULT": "%(msg)s",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


channel.setFormatter(CustomFormatter())
logger.addHandler(channel)


def require(cmd: str):
    logger.error(f"{cmd} is required for this functionality.")


def info(msg: str):
    logger.info(msg)


def warn(msg: str):
    logger.warn(msg)


def fatal(msg: str):
    logger.error(msg)
    raise RuntimeError("fatal error")
