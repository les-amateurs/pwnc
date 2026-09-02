"""Run an independently managed terminal viewer for a DAP GDB pool."""


def command(args):
    # Keep heavy GDB/DAP imports out of ordinary `pwnc --help` startup.
    from pwnc.gdb.dap.viewer_client import view
    from pwnc.gdb.dap.discovery import _os_error_reason

    try:
        return view(
            socket_path=args.socket_path,
            config_path=args.config_path,
            name=args.name,
            keep_open=args.keep_open,
            reconnect=args.reconnect,
            tty=args.tty,
        )
    except RuntimeError as error:
        # Public discovery/connection errors already carry operation, pool,
        # path, and remediation context. Add only the command boundary.
        raise RuntimeError(f"gdb view: {error}") from error
    except OSError as error:
        # TTY/open failures can still originate below the typed pool boundary.
        # Never make CLI users interpret a bare ``[Errno N]`` diagnostic.
        raise RuntimeError(
            f"gdb view: could not open the requested terminal or viewer resource: "
            f"{_os_error_reason(error)}"
        ) from error
    except (TypeError, ValueError) as error:
        raise RuntimeError(f"gdb view: invalid option or discovery value: {error}") from error
