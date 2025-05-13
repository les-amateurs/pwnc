import atexit
import os
import json

FONT_SIZE = 8
match SPLIT_MODE:
    case "PWNDBG":
        from pwndbg.commands.context import contextoutput
        def _redirect(pane: str, pty: str):
            contextoutput(pane, pty(id), True)
    case "BATA24":
        class Pane:
            def __init__(self, pane: str, pty: str):
                self.fd = open(pty, "w")
                self.old_print = print
                self.old_pane = GCI["context"].layout_mapping[pane]
                self.old_title = GCI["context"].context_title

                GCI["context"].layout_mapping[pane] = self.context

            def print(self, x, *args, **kwargs):
                self.old_print(x, *args, **kwargs, file=self.fd)

            def title(self, *args, **kwargs):
                pass

            def context(self):
                globals()["print"] = self.print
                TIOCGWINSZ = 0x5413
                tty_rows, tty_columns = struct.unpack("hh", fcntl.ioctl(self.fd, TIOCGWINSZ, "1234"))
                old_tty_rows, old_tty_columns = GCI["context"].tty_rows, GCI["context"].tty_columns
                GCI["context"].tty_rows, GCI["context"].tty_columns = tty_rows, tty_columns
                GCI["context"].context_title = self.title

                try:
                    self.old_pane()
                finally:
                    GCI["context"].context_title = self.old_title
                    GCI["context"].tty_rows, GCI["context"].tty_columns = old_tty_rows, old_tty_columns
                    globals()["print"] = self.old_print

        def _redirect(pane: str, pty: str):
            Pane(pane, pty)
    

class Id:
    def __init__(self, kid: str, bid: str):
        self.kid = kid
        self.bid = bid

def ex(cmd: str, read: bool = True):
    pipe = os.popen(cmd)
    if read:
       return pipe.read().strip()
    return pipe

def ls(jq_filter: str):
    data = ex(f"kitten @ ls | jq '{jq_filter}'")
    return json.loads(data)

def window_for_kid(id: Id):
    return ls(f".[] | .tabs | .[] | .windows | .[] | select(.id == {id.kid})")

def pty(id: Id):
    pid = window_for_kid(id)["pid"]
    return "/dev/" + ex(f"ps -p {pid} -o tty=")

def focused_kid():
    return ex(f"kitten @ select-window --match 'state:active'")

def focused_bid():
    return ex(f"bspc query -N -n")

class UselessTiler:
    def __init__(self):
        self.id = Id(focused_kid(), focused_bid())
        self.ids = []
        atexit.register(lambda: self.cleanup())

    def cleanup(self):
        for id in self.ids:
            ex(f"kitten @ close-window --match 'id:{id.kid}'")

    """
    sets font size for currently focused window
    """
    def set_font_size(self, size: int):
        ex("kitten @ set-font-size 8")

    """
    Launches a new kitty window.
    Automatically focuses newly created window.
    """
    def launch(self, options: str, direction: str = "south", ratio: float = 0.5) -> Id:
        ex(f"bspc node -p {direction} -o {ratio}")
        kid = ex(f"kitten @ launch {options}")
        self.set_font_size(FONT_SIZE)
        bid = focused_bid()
        new = Id(kid, bid)
        self.ids.append(new)
        return new
  
    """
    Redirect context output 'pane' to window 'id'.
    """
    def redirect(self, id: Id, pane: str):
        _redirect(pane, pty(id))
  
    """
    Focus on window 'id'.
    """
    def focus(self, id: Id):
        ex(f"bspc node {id.bid} -f")

t = UselessTiler()
t.set_font_size(FONT_SIZE)

regs = t.launch("--type=os-window cat", direction="north", ratio=0.30)
t.redirect(regs, "regs")

t.focus(t.id)
stack = t.launch("--type=os-window cat", direction="east", ratio=0.50)
t.redirect(stack, "stack")

# backtrace = t.launch("--type=os-window cat", direction="south", ratio=0.70)
# t.redirect(backtrace, "trace")

t.focus(t.id)
