import gdb
import rpyc
import atexit

class GdbService(rpyc.core.service.Service):
    exposed_gdb = gdb

server = rpyc.utils.server.ThreadedServer(
    GdbService(),
    hostname="0.0.0.0",
    port=1337,
    protocol_config={ "allow_all_attrs": True, }
)
atexit.register(lambda: server.close())
rpyc.lib.spawn(server.start)