from .config import *
from pathlib import Path
from time import sleep
from socket import (socket, AF_UNIX, SOCK_STREAM)
import os

def claim_server_listener(name: str):
    sock = socket(AF_UNIX, SOCK_STREAM)
    path = UNIX_SOCK_DIR / name.strip(os.sep)
    if path.exists():
        raise FileExistsError(f"{str(path)} already exists, refusing to connect")
    
    sock.bind(path)
    return path

