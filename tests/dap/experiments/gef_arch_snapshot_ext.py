# ruff: noqa: BLE001

"""JSON-safe architecture observations from an unmodified bata24 GEF.

Source this file after the pinned ``gef.py`` fixture.  The extension only
registers a DAP request; it does not replace or edit any GEF implementation.
The request runs on GDB's main thread because several of GEF's architecture
helpers use the synchronous ``gdb`` Python API.
"""

from gdb.dap.server import request as _pwnc_gef_arch_request


def _pwnc_gef_arch_error(error):
    """Return a deliberately small, JSON-only exception description."""

    try:
        message = str(error)
    except BaseException:
        message = "<exception stringification failed>"
    return {
        "type": type(error).__name__,
        "message": message,
    }


def _pwnc_gef_arch_json(value):
    """Normalize the narrow probe result surface to DAP JSON values."""

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {
            str(key): _pwnc_gef_arch_json(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_pwnc_gef_arch_json(item) for item in value]
    return str(value)


def _pwnc_gef_arch_capture(errors, field, operation):
    try:
        return _pwnc_gef_arch_json(operation())
    except BaseException as error:
        errors[field] = _pwnc_gef_arch_error(error)
        return None


def _pwnc_gef_arch_register_names(architecture):
    """Find GEF's canonical PC/SP register spellings when it declares them."""

    registers = [str(register) for register in architecture.all_registers]
    aliases = getattr(architecture, "alias_registers", None) or {}

    def declared_attribute(*names):
        for name in names:
            value = getattr(architecture, name, None)
            if isinstance(value, str):
                return value
        return None

    pc_name = declared_attribute("pc_register", "program_counter_register")
    if pc_name is None:
        for candidate in ("$pc", "$rip", "$eip", "$ip", "$iaoq"):
            if candidate in registers:
                pc_name = candidate
                break

    sp_name = declared_attribute("sp_register", "stack_pointer_register")
    if sp_name is None:
        for register, alias in aliases.items():
            alias_tokens = str(alias).replace("/", " ").split()
            if "$sp" in alias_tokens:
                sp_name = str(register)
                break
    if sp_name is None:
        for candidate in ("$sp", "$rsp", "$esp"):
            if candidate in registers:
                sp_name = candidate
                break

    return {
        "pc": pc_name,
        "sp": sp_name,
    }


def _pwnc_gef_arch_runtime_endian():
    endian = globals()["Endian"]
    elf = globals()["Elf"]
    value = endian.get_endian()
    if value == elf.LITTLE_ENDIAN:
        name = "little"
    elif value == elf.BIG_ENDIAN:
        name = "big"
    else:
        name = "unknown"
    return {
        "value": value,
        "name": name,
        "format": endian.endian_str(),
    }


if not globals().get("_pwnc_gef_arch_snapshot_registered", False):

    @_pwnc_gef_arch_request(
        "pwncGefArchitectureSnapshot",
        expect_stopped=False,
    )
    def _pwnc_gef_arch_snapshot(**_extra):
        errors = {}
        architecture = globals().get("current_arch")

        if architecture is None:
            errors["current_arch"] = {
                "type": "Unavailable",
                "message": "GEF current_arch is not initialized",
            }
            architecture_snapshot = None
            registers = {"pc": None, "sp": None}
        else:
            architecture_snapshot = {
                "arch": _pwnc_gef_arch_capture(
                    errors,
                    "current_arch.arch",
                    lambda: architecture.arch,
                ),
                "mode": _pwnc_gef_arch_capture(
                    errors,
                    "current_arch.mode",
                    lambda: architecture.mode,
                ),
                "bit_length": _pwnc_gef_arch_capture(
                    errors,
                    "current_arch.bit_length",
                    lambda: architecture.bit_length,
                ),
                "endianness": _pwnc_gef_arch_capture(
                    errors,
                    "current_arch.endianness",
                    lambda: architecture.endianness,
                ),
            }
            registers = _pwnc_gef_arch_capture(
                errors,
                "registers",
                lambda: _pwnc_gef_arch_register_names(architecture),
            )

        return {
            "current_arch": architecture_snapshot,
            "runtime_endian": _pwnc_gef_arch_capture(
                errors,
                "runtime_endian",
                _pwnc_gef_arch_runtime_endian,
            ),
            "p32_01020304": _pwnc_gef_arch_capture(
                errors,
                "p32_01020304",
                lambda: globals()["p32"](0x01020304).hex(),
            ),
            "is_remote_debug": _pwnc_gef_arch_capture(
                errors,
                "is_remote_debug",
                lambda: globals()["is_remote_debug"](),
            ),
            "is_qemu": _pwnc_gef_arch_capture(
                errors,
                "is_qemu",
                lambda: globals()["is_qemu"](),
            ),
            "is_qemu_user": _pwnc_gef_arch_capture(
                errors,
                "is_qemu_user",
                lambda: globals()["is_qemu_user"](),
            ),
            "registers": registers,
            "errors": errors,
        }

    _pwnc_gef_arch_snapshot_registered = True
