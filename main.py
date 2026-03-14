import os
import sys

_DEPENDENCIES = [
    ("tkinter", "python3-tk (install via: sudo apt install python3-tk)"),
    ("dns", "dnspython (install via: pip install dnspython)"),
    ("whois", "python-whois (install via: pip install python-whois)"),
]


def _check_dependencies() -> None:
    missing = []
    for module, install_hint in _DEPENDENCIES:
        try:
            __import__(module)
        except ImportError:
            missing.append(install_hint)
    if missing:
        print("Missing required dependencies:\n")
        for hint in missing:
            print(f"  - {hint}")
        print("\nPlease install the missing dependencies and try again.")
        sys.exit(1)


def _check_display() -> None:
    if not os.environ.get("DISPLAY"):
        # WSLg provides an X server at :0
        if os.path.exists("/tmp/.X11-unix/X0"):
            os.environ["DISPLAY"] = ":0"
        else:
            print(
                "No display server found.\n\n"
                "If you are running under WSL2, ensure WSLg is enabled\n"
                "or install an X server and set the DISPLAY variable:\n\n"
                "  export DISPLAY=:0"
            )
            sys.exit(1)


def main() -> None:
    _check_dependencies()
    _check_display()
    from dnsquery.gui.app import DNSQueryApp

    print("Starting DNSQuery... (CTRL+C to quit)")
    app = DNSQueryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
