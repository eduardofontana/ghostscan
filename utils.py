"""CLI output formatting helpers for GhostScan."""

from datetime import datetime

try:
    from colorama import Fore, Style, init

    init(autoreset=True, convert=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""

    class Style:
        RESET_ALL = BRIGHT = DIM = NORMAL = ALL_OFF = ""


class HackerColors:
    """Matrix-inspired color palette."""

    if COLORAMA_AVAILABLE:
        GREEN = Fore.GREEN
        CYAN = Fore.CYAN
        RED = Fore.RED
        YELLOW = Fore.YELLOW
        MAGENTA = Fore.MAGENTA
        BLUE = Fore.BLUE
        WHITE = Fore.WHITE
        RESET = Style.RESET_ALL

        GB = GREEN + Style.BRIGHT
        CB = CYAN + Style.BRIGHT
        RB = RED + Style.BRIGHT
        YB = YELLOW + Style.BRIGHT
        MB = MAGENTA + Style.BRIGHT
        BB = BLUE + Style.BRIGHT
        WB = WHITE + Style.BRIGHT
        GD = GREEN + Style.DIM
        MD = MAGENTA + Style.DIM
    else:
        GREEN = CYAN = RED = YELLOW = MAGENTA = BLUE = WHITE = RESET = ""
        GB = CB = RB = YB = MB = BB = WB = GD = MD = ""


HC = HackerColors()


def print_color(text: str, color: str = "") -> None:
    if COLORAMA_AVAILABLE and color:
        print(f"{color}{text}{Style.RESET_ALL}")
        return
    print(text)


def print_banner() -> None:
    """Print GhostScan ASCII banner."""
    print_color(
        r"""
   ____ _               _    ____                 
  / ___| |__   ___  ___| |_ / ___|  ___ __ _ _ __
 | |  _| '_ \ / _ \/ __| __|\___ \ / __/ _` | '_ \
 | |_| | | | | (_) \__ \ |_  ___) | (_| (_| | | | |
  \____|_| |_|\___/|___/\__||____/ \___\__,_|_| |_|

      [ GHOSTSCAN v1.2.0 // BLACK-OPS MODE ]
      [ ATTACK SURFACE ENUMERATION ENGINE ]
      [ AUTHORIZED TARGETS ONLY ]
""",
        HC.GB,
    )


def print_info(msg: str) -> None:
    print_color(f"[::] {msg}", HC.CB)


def print_success(msg: str) -> None:
    print_color(f"[+] {msg}", HC.GB)


def print_error(msg: str) -> None:
    print_color(f"[!] ERROR: {msg}", HC.RB)


def print_warning(msg: str) -> None:
    print_color(f"[*] {msg}", HC.YB)


def print_scan_header(target: str, target_ip: str, ports: str, count: int, threads: int, timeout: float) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_color("  [ STRIKE PROFILE ]", HC.MB)
    print_color("  " + ("=" * 42), HC.MD)
    print_color(f"  {HC.WB}Target   {HC.GD}: {target}", HC.WB)
    print_color(f"  {HC.WB}IP       {HC.GD}: {target_ip}", HC.WB)
    print_color(f"  {HC.WB}Ports    {HC.GD}: {ports} ({count} vectors)", HC.WB)
    print_color(f"  {HC.WB}Threads  {HC.GD}: {threads}", HC.WB)
    print_color(f"  {HC.WB}Timeout  {HC.GD}: {timeout:.2f}s", HC.WB)
    print_color(f"  {HC.WB}Launch   {HC.GD}: {timestamp}", HC.WB)
    print_color("  " + ("=" * 42), HC.MD)
    print()


def print_open_port(port: int, service: str) -> None:
    print_color(f"  {HC.GB}[OPEN]{HC.RESET}  {HC.BB}{port:>5}{HC.RESET}  ->  {HC.CB}{service}{HC.RESET}")
