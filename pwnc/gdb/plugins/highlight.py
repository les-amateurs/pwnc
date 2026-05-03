def init():
    global gef_print
    import re

    old_gef_print = gef_print

    def gef_print_highlight(msg, *args, **kwargs):
        # "\x1b]8;;copy://\1\x1b\\\1\x1b]8;;\x1b\\"
        msg = re.sub(r"(0x[0-9a-fA-F]{2,})", "\x1b]8;;copy://\\1\x1b\\\\\\1\x1b]8;;\x1b\\\\", msg)
        return old_gef_print(msg, *args, **kwargs)
    
    gef_print = gef_print_highlight

init()