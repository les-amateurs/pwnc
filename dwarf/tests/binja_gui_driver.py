#!/usr/bin/env python3
"""Submit the Teemo probe command through Binary Ninja's Xvfb GUI console."""

from __future__ import annotations

import ctypes
import time


def _library(name: str) -> ctypes.CDLL:
    return ctypes.CDLL(name)


def main() -> int:
    x11 = _library("libX11.so.6")
    xtst = _library("libXtst.so.6")

    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x11.XOpenDisplay.restype = ctypes.c_void_p
    x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x11.XDefaultRootWindow.restype = ctypes.c_ulong
    x11.XDisplayWidth.argtypes = [ctypes.c_void_p, ctypes.c_int]
    x11.XDisplayWidth.restype = ctypes.c_int
    x11.XDisplayHeight.argtypes = [ctypes.c_void_p, ctypes.c_int]
    x11.XDisplayHeight.restype = ctypes.c_int
    x11.XQueryTree.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)),
        ctypes.POINTER(ctypes.c_uint),
    ]
    x11.XQueryTree.restype = ctypes.c_int
    x11.XFetchName.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_char_p),
    ]
    x11.XFetchName.restype = ctypes.c_int
    x11.XGetGeometry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    x11.XGetGeometry.restype = ctypes.c_int
    x11.XFree.argtypes = [ctypes.c_void_p]
    x11.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
    x11.XStringToKeysym.restype = ctypes.c_ulong
    x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    x11.XKeysymToKeycode.restype = ctypes.c_uint
    x11.XFlush.argtypes = [ctypes.c_void_p]
    x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
    xtst.XTestFakeMotionEvent.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    xtst.XTestFakeButtonEvent.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    xtst.XTestFakeKeyEvent.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.c_ulong,
    ]

    deadline = time.monotonic() + 30
    display = None
    while display is None and time.monotonic() < deadline:
        display = x11.XOpenDisplay(b":99")
        if display is None:
            time.sleep(0.1)
    if display is None:
        raise RuntimeError("Binary Ninja Xvfb display did not become available")

    def geometry(window: int) -> tuple[int, int]:
        root_return = ctypes.c_ulong()
        x = ctypes.c_int()
        y = ctypes.c_int()
        width = ctypes.c_uint()
        height = ctypes.c_uint()
        border = ctypes.c_uint()
        depth = ctypes.c_uint()
        if not x11.XGetGeometry(
            display,
            window,
            ctypes.byref(root_return),
            ctypes.byref(x),
            ctypes.byref(y),
            ctypes.byref(width),
            ctypes.byref(height),
            ctypes.byref(border),
            ctypes.byref(depth),
        ):
            return (0, 0)
        return (width.value, height.value)

    def children(window: int) -> list[int]:
        root_return = ctypes.c_ulong()
        parent_return = ctypes.c_ulong()
        child_pointer = ctypes.POINTER(ctypes.c_ulong)()
        count = ctypes.c_uint()
        if not x11.XQueryTree(
            display,
            window,
            ctypes.byref(root_return),
            ctypes.byref(parent_return),
            ctypes.byref(child_pointer),
            ctypes.byref(count),
        ):
            return []
        try:
            return [int(child_pointer[index]) for index in range(count.value)]
        finally:
            if child_pointer:
                x11.XFree(child_pointer)

    def title(window: int) -> str:
        pointer = ctypes.c_char_p()
        if not x11.XFetchName(display, window, ctypes.byref(pointer)) or not pointer.value:
            return ""
        try:
            return pointer.value.decode("utf-8", errors="replace")
        finally:
            x11.XFree(pointer)

    root = int(x11.XDefaultRootWindow(display))
    main_window = None
    while main_window is None and time.monotonic() < deadline:
        pending = [root]
        while pending:
            window = pending.pop()
            width, height = geometry(window)
            if width >= 640 and height >= 480 and "Binary Ninja" in title(window):
                main_window = window
                break
            pending.extend(children(window))
        if main_window is None:
            time.sleep(0.1)
    if main_window is None:
        x11.XCloseDisplay(display)
        raise RuntimeError("Binary Ninja main window did not become available")

    x11.XRaiseWindow(display, main_window)
    screen_height = x11.XDisplayHeight(display, 0)
    xtst.XTestFakeMotionEvent(display, -1, 20, screen_height - 53, 0)
    xtst.XTestFakeButtonEvent(display, 1, 1, 0)
    xtst.XTestFakeButtonEvent(display, 1, 0, 0)
    x11.XFlush(display)
    time.sleep(0.75)

    key_names = [
        *(bytes([value]) for value in b"import"),
        b"space",
        *(bytes([value]) for value in b"binjaprobe"),
        b"Return",
    ]
    for name in key_names:
        keycode = x11.XKeysymToKeycode(display, x11.XStringToKeysym(name))
        if not keycode:
            x11.XCloseDisplay(display)
            raise RuntimeError(f"Xvfb has no keycode for {name!r}")
        xtst.XTestFakeKeyEvent(display, keycode, 1, 0)
        xtst.XTestFakeKeyEvent(display, keycode, 0, 0)
        time.sleep(0.005)
    x11.XFlush(display)
    time.sleep(0.25)
    x11.XCloseDisplay(display)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
