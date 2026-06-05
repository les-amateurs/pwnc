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

bata24 = load_module("bata24", expanduser(bata24_gef_py_path))
import bata24

__kallsyms_cache__ = None
__kbase_symbol__ = "_stext"

def read_msr(name: str):
    return bata24.GCI["msr"].read_msr(bata24.GCI["msr"].lookup_name2const(name))

""" Resolve kernel base without having to load entire kernel memory map.
    Falls back to bata24 if a fast path cannot be used.
"""

@bata24.Cache.cache_this_session
def find_kernel_base():
    kbase = None

    if bata24.is_x86_64():
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

@bata24.Cache.cache_this_session
def load_ksymaddr_cache():
    global __kallsyms_cache__

    kallsyms = config.Key("kernel") / "kallsyms"
    ksymaddr_remote = bata24.GCI["ksymaddr-remote"]
    kbase = find_kernel_base()

    if config.exists(kallsyms):
        ksymaddr_path = pwnc.util.Path(config.load(kallsyms))
        if ksymaddr_path.exists():
            bata24.info("loading kallsyms cache")
            with open(ksymaddr_path, "rb") as fp:
                relativesyms = pickle.load(fp)

            __kallsyms_cache__ = {}
            ksymaddr_remote.kallsyms = []
            for name, (offset, type) in relativesyms.items():
                __kallsyms_cache__[name] = offset + kbase
                ksymaddr_remote.kallsyms.append((offset + kbase, name, type))
            return

    original_get_ksymaddr(__kbase_symbol__)
    relativesyms = dict((sym[1], (sym[0] - kbase, sym[2])) for sym in ksymaddr_remote.kallsyms)
    cached_kallsyms = pwnc.cache.locate_local_cache() / "kallsyms.pkl"
    cached_kallsyms.parent.mkdir(exist_ok=True)
    with open(cached_kallsyms, "wb+") as fp:
        pickle.dump(relativesyms, fp)
    config.save(kallsyms, str(cached_kallsyms))

@bata24.Cache.cache_this_session
def fast_get_ksymaddr(sym):
    load_ksymaddr_cache()
    if __kallsyms_cache__ is not None and sym in __kallsyms_cache__:
        return __kallsyms_cache__[sym]

    res = original_get_ksymaddr(sym)
    return res

@bata24.Cache.cache_this_session
def fast_kernel_version():
    bata24.info("trying kernel version fast path")
    version = config.Key("kernel") / "version"
    kbase = find_kernel_base()

    try:
        if config.exists(version):
            verstr = config.load(version / "version-string")
            major = config.load(version / "major")
            minor = config.load(version / "minor")
            patch = config.load(version / "patch")
            offset = config.load(version / "offset")
            return bata24.Kernel.KernelVersion(kbase + offset, verstr, major, minor, patch)
    except KeyError as e:
        pass
    bata24.info("failed kernel version fast path.")

    kversion = original_kernel_version()
    if kversion is not None:
        config.save(version / "version-string", kversion.version_string)
        config.save(version / "major", kversion.major)
        config.save(version / "minor", kversion.minor)
        config.save(version / "patch", kversion.patch)
        config.save(version / "offset", kversion.address - kbase)
        return kversion

# original_get_ksymaddr = bata24.Symbol.get_ksymaddr
# original_kernel_version = bata24.Kernel.kernel_version

# bata24.Kernel.kernel_version = fast_kernel_version
# bata24.Symbol.get_ksymaddr = fast_get_ksymaddr

"""
// defined in include/linux/module.h
struct module
    // defined in kernel/module/sysfs.c
	struct module_sect_attrs *sect_attrs;
        // defined in include/linux/sysfs.h
	    struct attribute_group grp;
            // defined in include/linux/sysfs.h
		    struct attribute	**attrs;
                // defined in include/linux/sysfs.h
                struct attribute	attr;
                    struct attribute {
                        const char		*name;
                        umode_t			mode;
                    #ifdef CONFIG_DEBUG_LOCK_ALLOC
                        bool			ignore_lockdep:1;
                        struct lock_class_key	*key;
                        struct lock_class_key	skey;
                    #endif
                    };

We care about name and address.
`name` offset into struct module_sect_attr is always 0, and we assume it is 0.
`address` offset changes.
"""

@bata24.register_command
class KernelModuleLoadCommand(bata24.GenericCommand):
    """Load the kernel module without a load address."""

    _cmdline_ = "kmod-load"
    _category_ = "08-e. Qemu-system Cooperation - Linux Symbol/Type"

    parser = bata24.argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("name", type=str, help="name of the loaded module to search for by `kmod`.")
    parser.add_argument("path", type=str, help="path to compiled kernel module.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} sample /path/to/sample.ko",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command needs CONFIG_RANDSTRUCT=n.",
        "It is useful if you have a kernel module with debuginfo at hand.",
    ]
    _note_ = "\n".join(_note_)

    def get_modules_list(self):
        modules = bata24.KernelAddressHeuristicFinder.get_modules()
        if modules is None:
            self.quiet_err("Not found modules (maybe, CONFIG_MODULES is not set)")
            return None

        self.quiet_info("modules: {:#x}".format(modules))

        module_addrs = []
        current = modules
        while True:
            try:
                addr = bata24.read_int_from_memory(current)
            except gdb.MemoryError:
                return None
            if addr == modules:
                break
            module_addrs.append(addr - bata24.current_arch.ptrsize)
            current = addr
        return module_addrs

    def get_offset_module_name(self, module_addrs):
        for i in range(0x100):
            offset_name = i * bata24.current_arch.ptrsize
            valid = True
            for module in module_addrs:
                if not bata24.is_ascii_string(module + offset_name):
                    valid = False
                    break
                s = bata24.read_cstring_from_memory(module + offset_name)
                if len(s) < 2:
                    valid = False
                    break
            if valid:
                self.quiet_info("offsetof(module, name): {:#x}".format(offset_name))
                return offset_name

        self.quiet_err("Not found module->name[MODULE_NAME_LEN]")
        return None

    def get_offset_sect_attrs(self, module_addrs):
        for i in range(400):
            cached_sect_attrs = []
            offset_sect_attrs = bata24.current_arch.ptrsize * i
            for module in module_addrs:
                # access check
                if not bata24.is_valid_addr(module + offset_sect_attrs):
                    break
                sect_attrs = bata24.read_int_from_memory(module + offset_sect_attrs)
                if not self.is_valid_sect_attrs(sect_attrs):
                    break
                cached_sect_attrs.append(sect_attrs)
            else:
                self.quiet_info("offsetof(module, sect_attrs): {:#x}".format(offset_sect_attrs))
                return offset_sect_attrs, cached_sect_attrs

        self.quiet_err("Not found module->sect_attrs")
        return None, None

    def is_valid_sect_attrs(self, sect_attrs):
        if not bata24.is_valid_addr(sect_attrs):
            return False
        for offset in range(40):
            attribute_list = bata24.read_int_from_memory(sect_attrs + offset * bata24.current_arch.ptrsize)
            if self.is_valid_attribute_list(attribute_list):
                return True
        return False

    def is_valid_attribute_list(self, attribute_list):
        found = 0
        while True:
            if not bata24.is_valid_addr(attribute_list):
                return False
            attribute = bata24.read_int_from_memory(attribute_list)
            # self.quiet_info("attribute: {:#x}".format(attribute))
            if attribute == 0:
                break
            if not bata24.is_valid_addr(attribute):
                return False
            nameptr = bata24.read_int_from_memory(attribute)
            if not self.is_valid_sectname(nameptr):
                return False
            # self.quiet_info("name: {:s}".format(bata24.read_cstring_from_memory(nameptr)))
            found += 1
            attribute_list += bata24.current_arch.ptrsize
        # self.quiet_info("attr list: {:#x}".format(attribute_list))
        # self.quiet_info("found: {}".format(found))
        return found > 0

    def is_valid_sectname(self, nameptr):
        if not bata24.is_valid_addr(nameptr):
            return False
        sectname = bata24.read_cstring_from_memory(nameptr)
        if sectname is None or not sectname.startswith((".", "__")):
            if sectname and len(sectname) >= 4:
                self.quiet_info(
                    "possible section name (rejected for not starting with . or __): {:s}".format(sectname),
                )
            return False
        return True

    def get_offset_attrs(self):
        for i in range(10):
            cached_attribute_list = []
            offset_attrs = bata24.current_arch.ptrsize * i
            for sect_attrs in self.cached_sect_attrs:
                attribute_list = bata24.read_int_from_memory(sect_attrs + offset_attrs)
                if not self.is_valid_attribute_list(attribute_list):
                    break
                cached_attribute_list.append(attribute_list)
            else:
                self.quiet_info("offsetof(sect_attrs, attrs): {:#x}".format(offset_attrs))
                return offset_attrs, cached_attribute_list

        self.quiet_err("Not found sect_attrs->attrs")
        return None, None

    def get_offset_address(self):
        def is_executable(x):
            maps = bata24.Kernel.get_maps()
            for start, size, perm in maps:
                if start <= x and x < start + size:
                    return perm.endswith("X")
            return False

        executable_sections = [
            ".text",
            ".init.text",
            ".exit.text",
        ]

        data_sections = [
            ".data",
            ".bss",
            ".init.data",
            ".exit.data",
        ]
        
        for i in range(30):
            offset_address = bata24.current_arch.ptrsize * i
            for attribute_list in self.cached_attribute_list:
                valid_executable_section = False
                valid_data_section = False
                while True:
                    attribute = bata24.read_int_from_memory(attribute_list)
                    if attribute == 0:
                        break
                    nameptr = bata24.read_int_from_memory(attribute)
                    name = bata24.read_cstring_from_memory(nameptr)
                    addr = bata24.read_int_from_memory(attribute + offset_address)

                    # # This check doesnt actually work because
                    # # its not guaranteed that the kmod data
                    # # is faulted in yet.
                    # if not bata24.is_valid_addr(addr):
                    #     valid = False
                    #     break

                    if name in executable_sections and is_executable(addr):
                        valid_executable_section = True
                    elif name in data_sections and not is_executable(addr):
                        valid_data_section = True
                    if valid_executable_section and valid_data_section:
                        break
                    attribute_list += bata24.current_arch.ptrsize
                if not valid_executable_section or not valid_data_section: break
            else:
                self.quiet_info("offsetof(attribute, address): {:#x}".format(offset_address))
                return offset_address

        # this field doesnt *really* exists but idk what to call it
        self.quiet_err("Not found attribute->address")

    def initialize(self):
        self.module_addrs = self.get_modules_list()
        if self.module_addrs is None:
            return False

        self.offset_name = self.get_offset_module_name(self.module_addrs)
        if self.offset_name is None:
            return False

        self.offset_sect_attrs, self.cached_sect_attrs = self.get_offset_sect_attrs(self.module_addrs)
        if self.offset_sect_attrs is None:
            return False

        self.offset_attrs, self.cached_attribute_list = self.get_offset_attrs()
        if self.offset_attrs is None:
            return False

        self.offset_address = self.get_offset_address()
        if self.offset_address is None:
            return False

        return True

    @bata24.parse_args
    @bata24.only_if_gdb_running
    @bata24.only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @bata24.only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @bata24.only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if not bata24.os.path.exists(args.path):
            self.quiet_err("Not found {:s}".format(args.path))
            return

        kversion = bata24.Kernel.kernel_version()
        if kversion < "3.0":
            self.quiet_err("Unsupported before v3.0")
            return

        ret = self.initialize()
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        for module in self.module_addrs:
            name_string = bata24.read_cstring_from_memory(module + self.offset_name)
            if name_string != args.name:
                continue

            sect_attrs = bata24.read_int_from_memory(module + self.offset_sect_attrs)
            attribute_list = bata24.read_int_from_memory(sect_attrs + self.offset_attrs)

            # get each section name and address
            sections = []
            while True:
                attribute = bata24.read_int_from_memory(attribute_list)
                if attribute == 0:
                    break
                nameptr = bata24.read_int_from_memory(attribute)
                name = bata24.read_cstring_from_memory(nameptr)
                # self.quiet_info("attr={:#x}".format(attribute))
                addr = bata24.read_int_from_memory(attribute + self.offset_address)
                self.quiet_info("name={:s}, addr={:#x}".format(name, addr))
                sections.append((name, addr))
                attribute_list += bata24.current_arch.ptrsize

                # unneeded, but for convenience
                gdb.execute("set ${:s} = {:#x}".format(name.replace(".", "").replace("-", ""), addr))

            # load
            command = " ".join(['-s {:s} {:#x}'.format(name, addr) for (name, addr) in sections])
            gdb.execute("add-symbol-file {!r} {:s}".format(args.path, command))
            break
        else:
            self.quiet_err("Not found {:s}".format(args.name))
        return

try:
    bata24.Gef.main()
except Exception as e:
    import traceback
    traceback.print_exc()
    pwnc.err.info(f"Exception: {e}")
    pwnc.err.fatal("failed to start bata24 gef")
