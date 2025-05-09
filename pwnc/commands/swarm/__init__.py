from traceback import StackSummary
from ...util import *
from dataclasses import dataclass
import json
import signal
from time import sleep

@dataclass
class State:
    running: bool
    kids: list[int]
    pids: list[int]

@dataclass
class Worker:
    kid: int
    pid: int | None

state_path = Path(__file__).parent / "state.json"
swarm_sock = Path(__file__).parent / "swarm.unix"
unix = f"unix:{str(swarm_sock)}"
ALLOWED_SIGNALS = ["SIGINT", "SIGTERM", "SIGKILL"]

def load_state():
    try:
        with open(state_path, "r") as fp:
            return State(**json.load(fp))
    except:
        pass
    return State(False, [], [])
    
def save_state(state: State):
    with open(state_path, "w+") as fp:
        json.dump(state.__dict__, fp)

def kitten(command: list[str]):
    return subprocess.check_output(["kitten", "@", "--to", unix] + command)

def start_worker(root: bool = False, options: list[str] = []):
    if root:
        pipe = subprocess.Popen(["kitty"] + options)
        kid = 1
        pid = pipe.pid
    else:
        output = kitten(["launch"] + options)
        kid = int(output)
        pid = None
    
    return Worker(kid, pid)

def focus_worker(kid: int):
    kitten(["focus-window", "--match", f"id:{kid}"])

def swarm_start(args: Args, state: State):
    if state.running:
        err.fatal("swarm already running")
    
    swarm_sock.unlink(missing_ok=True)

    root = start_worker(root=True, options=["-o", "allow_remote_control=yes", "--listen-on", unix])
    kids = [root.kid]
    pids = [root.pid]

    while not swarm_sock.exists(follow_symlinks=False):
        sleep(0.1)

    for i in range(args.count):
        split = "hsplit" if i % 2 == 0 else "vsplit"

        new = []
        for kid in kids:
            focus_worker(kid)
            worker = start_worker(options=[f"--location={split}"])
            new.append(worker.kid)

        kids += new

    state.running = True
    state.kids = kids
    state.pids = pids

def swarm_kill(args: Args, state: State):
    for pid in state.pids:
        if pid is None:
            continue
        
        kitten(["close-window", "--match", "all", "--no-response"])

    state.running = False
    state.kids = []
    state.pids = []

def swarm_config(args: Args, state: State):
    if not state.running:
        err.fatal("swarm is not running")
    
    if args.font_size:
        kitten(["set-font-size", str(args.font_size)])

def swarm_exec(args: Args, state: State):
    if not state.running:
        err.fatal("swarm is not running")
    
    kitten(["send-text", "--all", args.command.strip() + "\n"])

def swarm_signal(args: Args, state: State):
    if not state.running:
        err.fatal("swarm is not running")

    if args.signal:
        if args.signal.upper() not in ALLOWED_SIGNALS:
            err.fatal(f"invalid signal {args.signal}")
        signal = args.signal
    else:
        signal = "SIGINT"

    kitten(["signal-child", "--match", "all", signal])

def command(args: Args):
    state = load_state()    

    sub = dict(args._get_kwargs())
    match sub.get("subcommand.swarm"):
        case "start":
            swarm_start(args, state)
        case "kill":
            swarm_kill(args, state)
        case "config":
            swarm_config(args, state)
        case "exec":
            swarm_exec(args, state)
        case "signal":
            swarm_signal(args, state)

    save_state(state)