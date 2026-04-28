import logging
import os
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)


def setup_logger(target: str, log_dir: str = "logs") -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
    log_filename = os.path.join(log_dir, f"scan_{safe_target}_{timestamp}.log")

    # Create Logger instance
    logger = logging.getLogger(f"VulnScanner_{timestamp}")
    logger.setLevel(logging.DEBUG)

    # File handler — All Details are inserted
    file_handler = logging.FileHandler(log_filename, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)

    # Console handler
    console_handler = ColoredConsoleHandler()
    console_handler.setLevel(logging.INFO)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info(f"Log file created: {log_filename}")
    return logger


class ColoredConsoleHandler(logging.StreamHandler):
    COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    }

    def emit(self, record):
        color = self.COLORS.get(record.levelno, "")
        msg = self.format(record)
        print(f"{color}{msg}{Style.RESET_ALL}")
