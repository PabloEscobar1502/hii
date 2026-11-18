# -*- coding: utf-8 -*-
"""
caps_peek.py - hold Caps Lock to "peek" at a hidden window.   (Windows 11, Python 3.10+)

Double-click to run. No admin rights, standard library only.

Flow
  1. A picker lists the open windows. You choose ONE target app (no re-targeting later).
  2. The target is hidden (invisible, no taskbar button) and stays hidden while the script runs.
  3. Hold Caps Lock for 0.5 s  -> target appears at 50% opacity, topmost, focused.
       Right Alt (while Caps held) toggles 30% <-> 50%.
       Typed letters come out lowercase while held.
     Release Caps Lock        -> target hides again, focus returns to the previous window.
     Tap Caps Lock (< 0.5 s)  -> normal Caps Lock toggle.
  4. KILL SWITCH: press Esc 3 times within 1.5 s (works anywhere, Esc is NOT swallowed).
     It FORCE-TERMINATES the target process (unsaved work is lost), exits, and permanently
     deletes this .py file.  Closing the target yourself does the same.
     Closing the picker without choosing just exits (nothing is deleted).

Safety nets
  * If the script crashes, the target window is restored (visible, taskbar, opacity).
  * If the script is killed from outside (Task Manager), a tiny detached watchdog restores it.
  * Refuses: elevated/protected apps, apps that reject window transparency, UWP/Store windows,
    shell windows and critical system processes (explorer.exe etc., because force-terminating
    those would kill your desktop).
  * The global keyboard hook only watches Caps Lock, Right Alt and Esc. Nothing is logged.
"""
import os
import sys

if os.name != "nt":
    sys.stderr.write("caps_peek.py only runs on Windows.\n")
    sys.exit(1)

import ctypes
import json
import queue
import subprocess
import threading
import time
from collections import deque
from ctypes import wintypes

SCRIPT_PATH = os.path.abspath(__file__)
APP_NAME = "CapsPeek"
MUTEX_NAME = "Local\\CapsPeek.single-instance.8f3a1c"

HOLD_SECS = 0.5          # how long Caps Lock must be held
ESC_PRESSES = 3          # kill switch: this many Esc presses ...
ESC_WINDOW = 1.5         # ... within this many seconds
ALPHA_HI = 128           # 50 %
ALPHA_LO = 77            # 30 %

# --------------------------------------------------------------------------------------
# Win32 plumbing
# --------------------------------------------------------------------------------------
HWND = wintypes.HWND
DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
UINT = wintypes.UINT
HANDLE = wintypes.HANDLE
LONG = ctypes.c_long
ULONG_PTR = ctypes.c_size_t
WPARAM = ctypes.c_size_t
LPARAM = ctypes.c_ssize_t
LRESULT = ctypes.c_ssize_t

HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, WPARAM, LPARAM)
WNDENUMPROC = ctypes.WINFUNCTYPE(BOOL, HWND, LPARAM)

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def _fn(dll, name, restype, *argtypes):
    f = getattr(dll, name)
    f.restype = restype
    f.argtypes = list(argtypes)
    return f


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", DWORD), ("scanCode", DWORD), ("flags", DWORD),
                ("time", DWORD), ("dwExtraInfo", ULONG_PTR)]


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", LONG), ("dy", LONG), ("mouseData", DWORD), ("dwFlags", DWORD),
                ("time", DWORD), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", DWORD),
                ("time", DWORD), ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", DWORD), ("u", _INPUT_UNION)]


SetWindowsHookExW = _fn(user32, "SetWindowsHookExW", ctypes.c_void_p, ctypes.c_int, HOOKPROC, HANDLE, DWORD)
UnhookWindowsHookEx = _fn(user32, "UnhookWindowsHookEx", BOOL, ctypes.c_void_p)
CallNextHookEx = _fn(user32, "CallNextHookEx", LRESULT, ctypes.c_void_p, ctypes.c_int, WPARAM, LPARAM)
GetMessageW = _fn(user32, "GetMessageW", ctypes.c_int, ctypes.POINTER(wintypes.MSG), HWND, UINT, UINT)
TranslateMessage = _fn(user32, "TranslateMessage", BOOL, ctypes.POINTER(wintypes.MSG))
DispatchMessageW = _fn(user32, "DispatchMessageW", LRESULT, ctypes.POINTER(wintypes.MSG))
PostThreadMessageW = _fn(user32, "PostThreadMessageW", BOOL, DWORD, UINT, WPARAM, LPARAM)
EnumWindows = _fn(user32, "EnumWindows", BOOL, WNDENUMPROC, LPARAM)
IsWindow = _fn(user32, "IsWindow", BOOL, HWND)
IsWindowVisible = _fn(user32, "IsWindowVisible", BOOL, HWND)
IsIconic = _fn(user32, "IsIconic", BOOL, HWND)
GetWindowTextLengthW = _fn(user32, "GetWindowTextLengthW", ctypes.c_int, HWND)
GetWindowTextW = _fn(user32, "GetWindowTextW", ctypes.c_int, HWND, wintypes.LPWSTR, ctypes.c_int)
GetClassNameW = _fn(user32, "GetClassNameW", ctypes.c_int, HWND, wintypes.LPWSTR, ctypes.c_int)
GetWindowThreadProcessId = _fn(user32, "GetWindowThreadProcessId", DWORD, HWND, ctypes.POINTER(DWORD))
GetWindowLongW = _fn(user32, "GetWindowLongW", LONG, HWND, ctypes.c_int)
SetWindowLongW = _fn(user32, "SetWindowLongW", LONG, HWND, ctypes.c_int, LONG)
SetLayeredWindowAttributes = _fn(user32, "SetLayeredWindowAttributes", BOOL, HWND, DWORD, ctypes.c_ubyte, DWORD)
GetLayeredWindowAttributes = _fn(user32, "GetLayeredWindowAttributes", BOOL, HWND, ctypes.POINTER(DWORD),
                                 ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(DWORD))
ShowWindow = _fn(user32, "ShowWindow", BOOL, HWND, ctypes.c_int)
SetWindowPos = _fn(user32, "SetWindowPos", BOOL, HWND, HWND, ctypes.c_int, ctypes.c_int,
                   ctypes.c_int, ctypes.c_int, UINT)
GetForegroundWindow = _fn(user32, "GetForegroundWindow", HWND)
SetForegroundWindow = _fn(user32, "SetForegroundWindow", BOOL, HWND)
BringWindowToTop = _fn(user32, "BringWindowToTop", BOOL, HWND)
SwitchToThisWindow = _fn(user32, "SwitchToThisWindow", None, HWND, BOOL)
AttachThreadInput = _fn(user32, "AttachThreadInput", BOOL, DWORD, DWORD, BOOL)
SendInput = _fn(user32, "SendInput", UINT, UINT, ctypes.POINTER(INPUT), ctypes.c_int)
GetKeyState = _fn(user32, "GetKeyState", ctypes.c_short, ctypes.c_int)
MessageBoxW = _fn(user32, "MessageBoxW", ctypes.c_int, HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, UINT)

GetConsoleWindow = _fn(kernel32, "GetConsoleWindow", HWND)
FreeConsole = _fn(kernel32, "FreeConsole", BOOL)
GetModuleHandleW = _fn(kernel32, "GetModuleHandleW", HANDLE, wintypes.LPCWSTR)
GetCurrentThreadId = _fn(kernel32, "GetCurrentThreadId", DWORD)
GetCurrentProcessId = _fn(kernel32, "GetCurrentProcessId", DWORD)
OpenProcess = _fn(kernel32, "OpenProcess", HANDLE, DWORD, BOOL, DWORD)
CloseHandle = _fn(kernel32, "CloseHandle", BOOL, HANDLE)
TerminateProcess = _fn(kernel32, "TerminateProcess", BOOL, HANDLE, UINT)
WaitForSingleObject = _fn(kernel32, "WaitForSingleObject", DWORD, HANDLE, DWORD)
QueryFullProcessImageNameW = _fn(kernel32, "QueryFullProcessImageNameW", BOOL, HANDLE, DWORD,
                                 wintypes.LPWSTR, ctypes.POINTER(DWORD))
CreateMutexW = _fn(kernel32, "CreateMutexW", HANDLE, ctypes.c_void_p, BOOL, wintypes.LPCWSTR)

try:
    _dwm = ctypes.WinDLL("dwmapi")
    DwmGetWindowAttribute = _fn(_dwm, "DwmGetWindowAttribute", ctypes.c_long, HWND, DWORD,
                                ctypes.c_void_p, DWORD)
except Exception:  # pragma: no cover
    DwmGetWindowAttribute = None

# constants
WH_KEYBOARD_LL = 13
WM_QUIT = 0x0012
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x0100, 0x0101, 0x0104, 0x0105
LLKHF_INJECTED = 0x10
VK_ESCAPE, VK_CAPITAL, VK_LCONTROL, VK_RMENU = 0x1B, 0x14, 0xA2, 0xA5
ALTGR_FAKE_LCTRL_SCAN = 0x21D

GWL_EXSTYLE = -20
WS_EX_TOPMOST, WS_EX_TOOLWINDOW, WS_EX_APPWINDOW = 0x00000008, 0x00000080, 0x00040000
WS_EX_LAYERED, WS_EX_NOREDIRECTIONBITMAP = 0x00080000, 0x00200000
LWA_COLORKEY, LWA_ALPHA = 0x1, 0x2
SW_HIDE, SW_SHOWNA, SW_RESTORE = 0, 8, 9
SWP_NOSIZE, SWP_NOMOVE, SWP_NOZORDER, SWP_NOACTIVATE, SWP_FRAMECHANGED = 0x1, 0x2, 0x4, 0x10, 0x20
HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
PROCESS_TERMINATE, PROCESS_QUERY_LIMITED, SYNCHRONIZE = 0x1, 0x1000, 0x00100000
INPUT_KEYBOARD, KEYEVENTF_KEYUP = 1, 0x2
DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP, CREATE_BREAKAWAY_FROM_JOB = 0x8, 0x200, 0x01000000

BLOCKED_EXES = {
    "explorer.exe", "dwm.exe", "winlogon.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "smss.exe", "svchost.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
    "applicationframehost.exe", "runtimebroker.exe", "searchhost.exe", "searchapp.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe",
    "systemsettings.exe", "lockapp.exe", "securityhealthsystray.exe",
}
BLOCKED_CLASSES = {
    "ApplicationFrameWindow", "Windows.UI.Core.CoreWindow", "Shell_TrayWnd",
    "Shell_SecondaryTrayWnd", "Progman", "WorkerW", "XamlExplorerHostIslandWindow",
}


def _s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def _fatal(msg):
    try:
        MessageBoxW(None, msg, APP_NAME, 0x10)
    except Exception:
        pass


# --------------------------------------------------------------------------------------
# Detached helper (separate process). Used for (a) deleting this script after we exit and
# (b) a watchdog that restores the target if we die without cleaning up.
# --------------------------------------------------------------------------------------
HELPER_SRC = r'''
import sys, os, time, json, ctypes
from ctypes import wintypes
k32 = ctypes.WinDLL("kernel32"); u32 = ctypes.WinDLL("user32")
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
u32.IsWindow.argtypes = [wintypes.HWND]
u32.SetWindowLongW.restype = ctypes.c_long
u32.SetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_long]
u32.SetLayeredWindowAttributes.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.c_ubyte, wintypes.DWORD]
u32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND] + [ctypes.c_int] * 4 + [wintypes.UINT]
u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]

def exited(pid, ms):
    h = k32.OpenProcess(0x00100000, False, pid)
    if not h:
        return True
    r = k32.WaitForSingleObject(h, ms)
    k32.CloseHandle(h)
    return r == 0

def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v

mode = sys.argv[1]
main_pid = int(sys.argv[2])
if mode == "delete":
    while not exited(main_pid, 2000):
        pass
    path = sys.argv[3]
    for _ in range(300):
        try:
            os.remove(path)
            break
        except FileNotFoundError:
            break
        except OSError:
            time.sleep(0.1)
elif mode == "watch":
    st = json.loads(sys.argv[3])
    while not exited(main_pid, 5000):
        pass
    time.sleep(1.5)
    if not exited(st["pid"], 0):
        hwnd = st["hwnd"]
        if u32.IsWindow(hwnd):
            u32.SetWindowLongW(hwnd, -20, s32(st["ex"]))
            lay = st["layered"]
            if lay[0]:
                u32.SetLayeredWindowAttributes(hwnd, lay[1], lay[2], lay[3])
            u32.SetWindowPos(hwnd, -1 if st["topmost"] else -2, 0, 0, 0, 0, 0x1 | 0x2 | 0x10 | 0x20)
            u32.ShowWindow(hwnd, 8)
'''


def _pythonw():
    exe = sys.executable
    if os.path.basename(exe).lower() == "python.exe":
        cand = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return exe


def _spawn_detached(argv):
    kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
              close_fds=True)
    base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    try:  # try to escape a parent job object first
        return subprocess.Popen(argv, creationflags=base | CREATE_BREAKAWAY_FROM_JOB, **kw)
    except OSError:
        return subprocess.Popen(argv, creationflags=base, **kw)


def spawn_helper(mode, *args):
    _spawn_detached([_pythonw(), "-I", "-c", HELPER_SRC, mode, *[str(a) for a in args]])


# --------------------------------------------------------------------------------------
# Startup: no console, single instance, DPI
# --------------------------------------------------------------------------------------
def _hide_console_or_relaunch():
    """Re-launch under pythonw.exe (no console at all); fall back to hiding the console."""
    base = os.path.basename(sys.executable).lower()
    if "--child" in sys.argv or base.startswith("pythonw"):
        return
    pyw = _pythonw()
    if pyw != sys.executable:
        try:
            _spawn_detached([pyw, SCRIPT_PATH, "--child"])
            sys.exit(0)
        except OSError:
            pass
    try:
        hwnd = GetConsoleWindow()
        if hwnd:
            ShowWindow(hwnd, SW_HIDE)
            FreeConsole()
    except Exception:
        pass


def _acquire_single_instance():
    h = CreateMutexW(None, True, MUTEX_NAME)
    if not h:
        return True
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


def _set_dpi_aware():
    try:
        ctypes.WinDLL("shcore").SetProcessDpiAwareness(2)
    except Exception:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass


# --------------------------------------------------------------------------------------
# Window helpers
# --------------------------------------------------------------------------------------
def get_ex(hwnd):
    return GetWindowLongW(hwnd, GWL_EXSTYLE) & 0xFFFFFFFF


def set_ex(hwnd, value):
    ctypes.set_last_error(0)
    r = SetWindowLongW(hwnd, GWL_EXSTYLE, _s32(value))
    return not (r == 0 and ctypes.get_last_error() != 0)


def apply_frame(hwnd):
    SetWindowPos(hwnd, None, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED)


def get_layered_state(hwnd):
    """-> (is_layered, colorkey, alpha, flags); None if layered but attributes unreadable."""
    if not (get_ex(hwnd) & WS_EX_LAYERED):
        return (False, 0, 255, 0)
    key, alpha, flags = DWORD(0), ctypes.c_ubyte(255), DWORD(0)
    if GetLayeredWindowAttributes(hwnd, ctypes.byref(key), ctypes.byref(alpha), ctypes.byref(flags)):
        return (True, key.value, alpha.value, flags.value)
    return None


def set_alpha(hwnd, alpha, orig_layered):
    ex = get_ex(hwnd)
    if not (ex & WS_EX_LAYERED):
        if not set_ex(hwnd, ex | WS_EX_LAYERED):
            return False
    flags, key = LWA_ALPHA, 0
    if orig_layered and orig_layered[0] and (orig_layered[3] & LWA_COLORKEY):
        flags |= LWA_COLORKEY
        key = orig_layered[1]
    return bool(SetLayeredWindowAttributes(hwnd, key, alpha, flags))


def restore_layered(hwnd, orig):
    if orig and orig[0]:
        SetLayeredWindowAttributes(hwnd, orig[1], orig[2], orig[3])
    else:
        set_ex(hwnd, get_ex(hwnd) & ~WS_EX_LAYERED)
        apply_frame(hwnd)


def probe_transparency(hwnd):
    """Try 50% opacity on the window and verify it; always restores the original state."""
    if get_ex(hwnd) & WS_EX_NOREDIRECTIONBITMAP:
        return False, "it uses a composition-only window (WinUI/UWP style) that cannot be made transparent"
    orig = get_layered_state(hwnd)
    if orig is None:
        return False, "it already uses per-pixel transparency that cannot be overridden"
    ok = set_alpha(hwnd, ALPHA_HI, orig)
    if ok:
        got = get_layered_state(hwnd)
        ok = bool(got and got[0] and got[2] == ALPHA_HI)
    restore_layered(hwnd, orig)
    if not ok:
        return False, "Windows refused to change its opacity (elevated or protected app?)"
    return True, ""


def window_text(hwnd):
    n = GetWindowTextLengthW(hwnd)
    if n <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(n + 1)
    GetWindowTextW(hwnd, buf, n + 1)
    return buf.value


def window_class(hwnd):
    buf = ctypes.create_unicode_buffer(256)
    GetClassNameW(hwnd, buf, 256)
    return buf.value


def window_pid(hwnd):
    pid = DWORD(0)
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def process_exe(pid):
    h = OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = DWORD(1024)
        if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
        return ""
    finally:
        CloseHandle(h)


def is_cloaked(hwnd):
    if DwmGetWindowAttribute is None:
        return False
    v = DWORD(0)
    try:
        hr = DwmGetWindowAttribute(hwnd, 13, ctypes.byref(v), 4)  # DWMWA_CLOAKED
    except Exception:
        return False
    return hr == 0 and v.value != 0


def list_windows():
    """All visible, non-cloaked top-level windows (titled or not). -> [(hwnd, title, pid, exe)]"""
    out, exe_cache = [], {}

    def cb(hwnd, _lp):
        try:
            if IsWindowVisible(hwnd) and not is_cloaked(hwnd):
                pid = window_pid(hwnd)
                if pid not in exe_cache:
                    exe_cache[pid] = process_exe(pid)
                out.append((hwnd, window_text(hwnd), pid, exe_cache[pid]))
        except Exception:
            pass
        return True

    proc = WNDENUMPROC(cb)
    EnumWindows(proc, 0)
    out.sort(key=lambda w: ((w[3] or "~").lower(), w[1].lower()))
    return out


class Target(object):
    pass


def validate_target(hwnd, pid, exe):
    """-> (Target, "") or (None, reason)."""
    if not IsWindow(hwnd):
        return None, "that window no longer exists"
    if pid == os.getpid():
        return None, "that is this script's own window"
    if not exe:
        return None, "Windows won't let this script inspect it (elevated or protected app)"
    if exe.lower() in BLOCKED_EXES:
        return None, "%s is a shell/system process - force-terminating it would take down your desktop" % exe
    if window_class(hwnd) in BLOCKED_CLASSES:
        return None, "it is a Store/UWP or shell window, which can't be made transparent or safely hidden"
    handle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE | PROCESS_QUERY_LIMITED, False, pid)
    if not handle:
        return None, "this script can't terminate that process (it is elevated/protected; no admin allowed)"
    ok, why = probe_transparency(hwnd)
    if not ok:
        CloseHandle(handle)
        return None, why
    t = Target()
    t.hwnd, t.pid, t.handle, t.exe = hwnd, pid, handle, exe
    t.orig_ex = get_ex(hwnd)
    t.orig_layered = get_layered_state(hwnd) or (False, 0, 255, 0)
    t.topmost = bool(t.orig_ex & WS_EX_TOPMOST)
    return t, ""


def restore_target(t):
    """Put the target back the way we found it (visible, taskbar, original opacity)."""
    try:
        if not IsWindow(t.hwnd):
            return
        set_ex(t.hwnd, t.orig_ex)
        if t.orig_layered[0]:
            SetLayeredWindowAttributes(t.hwnd, t.orig_layered[1], t.orig_layered[2], t.orig_layered[3])
        SetWindowPos(t.hwnd, HWND_TOPMOST if t.topmost else HWND_NOTOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_FRAMECHANGED)
        ShowWindow(t.hwnd, SW_SHOWNA)
    except Exception:
        pass


def force_foreground(hwnd):
    """Best-effort focus steal that works from a background (hook) process without admin."""
    try:
        fg = GetForegroundWindow()
        cur = GetCurrentThreadId()
        fg_tid = GetWindowThreadProcessId(fg, None) if fg else 0
        attached = bool(fg_tid and fg_tid != cur and AttachThreadInput(cur, fg_tid, True))
        try:
            BringWindowToTop(hwnd)
            SetForegroundWindow(hwnd)
        finally:
            if attached:
                AttachThreadInput(cur, fg_tid, False)
        if GetForegroundWindow() != hwnd:
            SwitchToThisWindow(hwnd, True)
    except Exception:
        pass


def send_caps_toggle():
    arr = (INPUT * 2)()
    for i, flags in enumerate((0, KEYEVENTF_KEYUP)):
        arr[i].type = INPUT_KEYBOARD
        arr[i].ki.wVk = VK_CAPITAL
        arr[i].ki.wScan = 0x3A
        arr[i].ki.dwFlags = flags
    SendInput(2, arr, ctypes.sizeof(INPUT))


# --------------------------------------------------------------------------------------
# Picker (tkinter, no taskbar button)
# --------------------------------------------------------------------------------------
def run_picker():
    import tkinter as tk
    from tkinter import messagebox

    result = {"target": None}
    root = tk.Tk()
    root.title("%s - choose a window" % APP_NAME)
    try:
        root.attributes("-toolwindow", True)   # tool window => no taskbar button
    except tk.TclError:
        pass
    root.geometry("720x520")
    root.minsize(560, 400)

    tk.Label(
        root, anchor="w", justify="left", wraplength=680,
        text=("Choose the window to control. Hold Caps Lock for 0.5 s to peek at it "
              "(Right Alt toggles 50%/30% while held).\n"
              "Esc pressed 3 times within 1.5 s = FORCE-KILL the chosen app, exit, and "
              "permanently delete this script.  Closing this window just exits.")
    ).pack(fill="x", padx=10, pady=(10, 4))

    filter_var = tk.StringVar()
    entry = tk.Entry(root, textvariable=filter_var)
    entry.pack(fill="x", padx=10)

    frame = tk.Frame(root)
    frame.pack(fill="both", expand=True, padx=10, pady=6)
    scroll = tk.Scrollbar(frame)
    listbox = tk.Listbox(frame, exportselection=False, activestyle="dotbox", yscrollcommand=scroll.set)
    scroll.config(command=listbox.yview)
    scroll.pack(side="right", fill="y")
    listbox.pack(side="left", fill="both", expand=True)

    state = {"all": [], "view": []}

    def label(w):
        return "%s    [%s  pid %d]" % (w[1] or "(no title)", w[3] or "?", w[2])

    def apply_filter(*_):
        needle = filter_var.get().strip().lower()
        listbox.delete(0, "end")
        state["view"] = []
        for w in state["all"]:
            text = label(w)
            if needle in text.lower():
                state["view"].append(w)
                listbox.insert("end", text)

    def refresh():
        state["all"] = list_windows()
        apply_filter()

    def choose(_evt=None):
        sel = listbox.curselection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a window first.", parent=root)
            return
        hwnd, title, pid, exe = state["view"][sel[0]]
        target, why = validate_target(hwnd, pid, exe)
        if target is None:
            messagebox.showerror(APP_NAME, "Can't use this window:\n\n%s." % why, parent=root)
            return
        ok = messagebox.askyesno(
            APP_NAME,
            "Hide '%s' (%s) and start?\n\n"
            "It will vanish from the screen and taskbar; only a 0.5 s Caps Lock hold shows it.\n"
            "Esc x3 within 1.5 s force-kills it (unsaved work is lost) and deletes this script."
            % (title or "(no title)", exe), parent=root)
        if not ok:
            restore_target(target)
            CloseHandle(target.handle)
            return
        result["target"] = target
        root.destroy()

    row = tk.Frame(root)
    row.pack(fill="x", padx=10, pady=(0, 10))
    tk.Button(row, text="Refresh", command=refresh).pack(side="left")
    tk.Button(row, text="Select && hide", command=choose).pack(side="right")

    filter_var.trace_add("write", apply_filter)
    listbox.bind("<Double-Button-1>", choose)
    root.bind("<Return>", choose)
    root.protocol("WM_DELETE_WINDOW", root.destroy)

    refresh()
    root.after(80, lambda: (root.lift(), root.focus_force(), entry.focus_set()))
    root.mainloop()
    return result["target"]


# --------------------------------------------------------------------------------------
# Runtime: keyboard hook (fast, non-blocking) + worker thread (does all window work)
# --------------------------------------------------------------------------------------
EVENTS = queue.Queue()

_caps_down = False
_esc_down = False
_esc_times = deque(maxlen=ESC_PRESSES)
_swallowed = set()          # vk codes whose key-down we ate, so we also eat the matching key-up


def handle_key(vk, scan, down):
    """Runs inside the low-level hook. Return True to swallow the key. Must stay fast."""
    global _caps_down, _esc_down
    now = time.monotonic()

    if vk == VK_CAPITAL:
        if down:
            if not _caps_down:
                _caps_down = True
                EVENTS.put(("down", now))
        else:
            if not _caps_down:
                return False
            _caps_down = False
            EVENTS.put(("up", now))
        return True             # real Caps events never reach Windows; a short tap is replayed later

    if vk == VK_ESCAPE:
        if down:
            if not _esc_down:
                _esc_down = True
                _esc_times.append(now)
                if len(_esc_times) == ESC_PRESSES and now - _esc_times[0] <= ESC_WINDOW:
                    _esc_times.clear()
                    EVENTS.put(("kill",))
        else:
            _esc_down = False
        return False            # Esc always passes through

    if vk == VK_RMENU or (vk == VK_LCONTROL and scan == ALTGR_FAKE_LCTRL_SCAN):
        if down:
            if vk in _swallowed:
                return True     # auto-repeat of a key we already ate
            if _caps_down:
                _swallowed.add(vk)
                if vk == VK_RMENU:
                    EVENTS.put(("alt",))
                return True
            return False
        if vk in _swallowed:
            _swallowed.discard(vk)
            return True
        return False

    return False


def _hook_proc(n_code, w_param, l_param):
    try:
        if n_code == 0:
            kb = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            if not (kb.flags & LLKHF_INJECTED):
                down = w_param in (WM_KEYDOWN, WM_SYSKEYDOWN)
                up = w_param in (WM_KEYUP, WM_SYSKEYUP)
                if (down or up) and handle_key(kb.vkCode, kb.scanCode, down):
                    return 1
    except Exception:
        pass
    return CallNextHookEx(None, n_code, w_param, l_param)


class Controller(object):
    def __init__(self, target, caps_on, main_tid):
        self.t = target
        self.caps_launch = caps_on
        self.caps_on = caps_on
        self.forced_off = False
        self.prev_fg = None
        self.level = 0
        self.main_tid = main_tid
        self.delete_script = False

    # -- setup -----------------------------------------------------------------------
    def arm(self):
        t = self.t
        ShowWindow(t.hwnd, SW_HIDE)
        self.ensure_style()
        set_alpha(t.hwnd, ALPHA_HI, t.orig_layered)
        spawn_helper("watch", os.getpid(), json.dumps({
            "hwnd": int(t.hwnd), "pid": t.pid, "ex": t.orig_ex,
            "layered": list(t.orig_layered), "topmost": t.topmost}))

    def ensure_style(self):
        ex = get_ex(self.t.hwnd)
        want = (ex | WS_EX_TOOLWINDOW) & ~WS_EX_APPWINDOW
        if want != ex:
            set_ex(self.t.hwnd, want)
        apply_frame(self.t.hwnd)

    # -- caps bookkeeping ------------------------------------------------------------
    def toggle_caps(self):
        send_caps_toggle()
        self.caps_on = not self.caps_on

    def restore_caps(self):
        if self.caps_on != self.caps_launch:
            self.toggle_caps()
        self.forced_off = False

    # -- show / hide -----------------------------------------------------------------
    def alpha(self):
        return ALPHA_HI if self.level == 0 else ALPHA_LO

    def show(self):
        t = self.t
        fg = GetForegroundWindow()
        self.prev_fg = fg if fg and fg != t.hwnd else None
        if self.caps_on:                       # force lowercase while held
            self.toggle_caps()
            self.forced_off = True
        set_alpha(t.hwnd, self.alpha(), t.orig_layered)
        self.ensure_style()
        ShowWindow(t.hwnd, SW_RESTORE if IsIconic(t.hwnd) else SW_SHOWNA)
        SetWindowPos(t.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
        force_foreground(t.hwnd)

    def hide(self):
        t = self.t
        SetWindowPos(t.hwnd, HWND_TOPMOST if t.topmost else HWND_NOTOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE)
        ShowWindow(t.hwnd, SW_HIDE)
        if self.forced_off:
            self.toggle_caps()
            self.forced_off = False
        pf = self.prev_fg
        self.prev_fg = None
        if pf and IsWindow(pf) and IsWindowVisible(pf):
            force_foreground(pf)

    # -- exit paths ------------------------------------------------------------------
    def process_dead(self):
        return WaitForSingleObject(self.t.handle, 0) == 0

    def quit_loop(self):
        PostThreadMessageW(self.main_tid, WM_QUIT, 0, 0)

    def kill_and_exit(self):
        """Kill switch / target closed: silently terminate target, delete script, exit."""
        t = self.t
        try:
            ShowWindow(t.hwnd, SW_HIDE)        # never leave it visible
        except Exception:
            pass
        alive = not self.process_dead()
        ok = True
        if alive:
            ok = bool(TerminateProcess(t.handle, 1))
            if ok:
                WaitForSingleObject(t.handle, 3000)
        if not ok:
            restore_target(t)                  # could not kill it: don't leave a ghost
        try:
            self.restore_caps()
        except Exception:
            pass
        try:
            spawn_helper("delete", os.getpid(), SCRIPT_PATH)
        except Exception:
            pass
        self.quit_loop()

    def failsafe_exit(self):
        """Unexpected error: give the window back, do NOT kill or delete anything."""
        restore_target(self.t)
        try:
            self.restore_caps()
        except Exception:
            pass
        self.quit_loop()

    # -- worker ----------------------------------------------------------------------
    def run(self):
        holding = shown = consumed = False
        t0 = 0.0
        last_check = time.monotonic()
        while True:
            timeout = 0.03 if (holding and not shown) else 0.25
            try:
                cmd = EVENTS.get(timeout=timeout)
            except queue.Empty:
                cmd = None
            try:
                if cmd is not None:
                    kind = cmd[0]
                    if kind == "down":
                        if not holding:
                            holding, shown, consumed, t0 = True, False, False, cmd[1]
                            self.level = 0
                    elif kind == "up":
                        was_holding, dur = holding, cmd[1] - t0
                        holding = False
                        if shown:
                            self.hide()
                            shown = False
                        elif was_holding and not consumed and dur < HOLD_SECS:
                            self.toggle_caps()          # plain tap: normal Caps Lock behaviour
                    elif kind == "alt":
                        if holding:
                            consumed = True
                            self.level = 1 - self.level
                            if shown:
                                set_alpha(self.t.hwnd, self.alpha(), self.t.orig_layered)
                    elif kind == "kill":
                        self.kill_and_exit()
                        return
                now = time.monotonic()
                if holding and not shown and now - t0 >= HOLD_SECS:
                    self.show()
                    shown = True
                if now - last_check >= 0.5:
                    last_check = now
                    if self.process_dead() or not IsWindow(self.t.hwnd):
                        self.kill_and_exit()
                        return
            except Exception:
                self.failsafe_exit()
                return


def main():
    _hide_console_or_relaunch()
    if not _acquire_single_instance():
        return
    _set_dpi_aware()
    try:
        target = run_picker()
    except Exception as exc:
        _fatal("Could not show the window picker:\n%s" % exc)
        return
    if target is None:
        return

    caps_on = bool(GetKeyState(VK_CAPITAL) & 1)
    ctrl = Controller(target, caps_on, GetCurrentThreadId())
    try:
        ctrl.arm()
    except Exception as exc:
        restore_target(target)
        _fatal("Could not set up the target window:\n%s" % exc)
        return

    hook_ref = HOOKPROC(_hook_proc)            # keep a reference or it gets garbage-collected
    hook = SetWindowsHookExW(WH_KEYBOARD_LL, hook_ref, GetModuleHandleW(None), 0)
    if not hook:
        restore_target(target)
        _fatal("Could not install the keyboard hook.")
        return

    threading.Thread(target=ctrl.run, name="worker", daemon=True).start()

    msg = wintypes.MSG()
    while True:
        r = GetMessageW(ctypes.byref(msg), None, 0, 0)
        if r == 0 or r == -1:
            break
        TranslateMessage(ctypes.byref(msg))
        DispatchMessageW(ctypes.byref(msg))

    UnhookWindowsHookEx(hook)
    os._exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # last resort; nothing else may be visible
        _fatal("%s crashed:\n%s" % (APP_NAME, exc))
