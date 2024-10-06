from pwnc import config
from pwnc.commands import kernel
from pwnc.util import expanduser
import pwnc
import sys
import importlib
import pickle

try:
    bata24_gef_py_path = config.load(config.Key("gdb") / "plugins" / "bata24" / "gef-py-path")
except KeyError as e:
    pwnc.err.fatal(f"unable to locate bata24 gef.py file. set {str(e)} in pwnc.toml")

def load_module(module_name, module_path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return module

load_module("bata24", expanduser(bata24_gef_py_path))

from bata24 import *

__kallsyms_cache__ = None
__kbase_symbol__ = "_stext"

def read_msr(name: str):
    return GCI["msr"].read_msr(GCI["msr"].lookup_name2const(name))

""" Resolve kernel base without having to load entire kernel memory map.
    Falls back to bata24 if a fast path cannot be used.
"""
@Cache.cache_this_session
def find_kernel_base():
    kbase = None

    if is_x86_64():
        # TODO: check cpuid for MSR_LSTAR support
        msrs = config.Key("kernel") / "x86-64" / "msrs"
        lstar_offset = msrs / "lstar"
        lstar = read_msr("MSR_LSTAR")
        
        if config.exists(lstar_offset):
            offset = config.load(lstar_offset)
            kbase = lstar - offset
        else:
            kbase = original_get_ksymaddr(__kbase_symbol__)
            config.save(lstar_offset, lstar - kbase)

    if kbase is None:
        kbase = original_get_ksymaddr(__kbase_symbol__)

    return kbase

@Cache.cache_this_session
def load_ksymaddr_cache():
    global __kallsyms_cache__

    kallsyms = config.Key("kernel") / "kallsyms"
    ksymaddr_remote = GCI["ksymaddr-remote"]
    kbase = find_kernel_base()

    if config.exists(kallsyms):
        ksymaddr_path = pwnc.util.Path(config.load(kallsyms))
        if ksymaddr_path.exists():
            info("loading kallsyms cache")
            with open(ksymaddr_path, "rb") as fp:
                relativesyms = pickle.load(fp)

            __kallsyms_cache__ = {}
            ksymaddr_remote.kallsyms = []
            for name, (offset, type) in relativesyms.items():
                __kallsyms_cache__[name] = offset + kbase
                ksymaddr_remote.kallsyms.append((name, offset + kbase, type))

            return

    original_get_ksymaddr(__kbase_symbol__)
    relativesyms = dict((sym[1], (sym[0] - kbase, sym[2])) for sym in ksymaddr_remote.kallsyms)
    cached_kallsyms = pwnc.cache.locate_local_cache() / "kallsyms.pkl"
    cached_kallsyms.parent.mkdir(exist_ok=True)
    with open(cached_kallsyms, "wb+") as fp:
        pickle.dump(relativesyms, fp)
    config.save(kallsyms, str(cached_kallsyms))

@Cache.cache_this_session
def fast_get_ksymaddr(sym):
    load_ksymaddr_cache()
    if __kallsyms_cache__ is not None and sym in __kallsyms_cache__:
        return __kallsyms_cache__[sym]
    
    res = original_get_ksymaddr(sym)
    return res

@Cache.cache_this_session
def fast_kernel_version():
    info("trying kernel version fast path")
    version = config.Key("kernel") / "version"
    kbase = find_kernel_base()

    try:
        if config.exists(version):
            verstr = config.load(version / "version-string")
            major = config.load(version / "major")
            minor = config.load(version / "minor")
            patch = config.load(version / "patch")
            offset = config.load(version / "offset")
            return Kernel.KernelVersion(kbase + offset, verstr, major, minor, patch)
    except KeyError as e:
        pass
    info("failed kernel version fast path.")

    kversion =  original_kernel_version()
    if kversion is not None:
        config.save(version / "version-string", kversion.version_string)
        config.save(version / "major", kversion.major)
        config.save(version / "minor", kversion.minor)
        config.save(version / "patch", kversion.patch)
        config.save(version / "offset", kversion.address - kbase)
        return kversion

original_get_ksymaddr = Symbol.get_ksymaddr
original_kernel_version = Kernel.kernel_version

Kernel.kernel_version = fast_kernel_version
Symbol.get_ksymaddr = fast_get_ksymaddr

try:
    Gef.main()
except:
    pwnc.err.fatal("failed to start bata24 gef")