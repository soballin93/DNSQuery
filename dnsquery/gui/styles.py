from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# Colors
BG_PRIMARY = "#f5f5f5"
BG_SECONDARY = "#ffffff"
FG_PRIMARY = "#1a1a1a"
FG_SECONDARY = "#555555"
ACCENT = "#2563eb"
ACCENT_HOVER = "#1d4ed8"
SUCCESS = "#16a34a"
ERROR = "#dc2626"
WARNING = "#d97706"
BORDER = "#d1d5db"

# Fonts
FONT_FAMILY = "Segoe UI" if tk.TkVersion >= 8.6 else "TkDefaultFont"
FONT_HEADING = (FONT_FAMILY, 11, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_SMALL = (FONT_FAMILY, 9)
FONT_MONO = ("Consolas", 10)

# Dimensions
PAD_X = 10
PAD_Y = 6
ENTRY_WIDTH = 50


def configure_styles(root: tk.Tk) -> None:
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(".", background=BG_PRIMARY, foreground=FG_PRIMARY, font=FONT_BODY)
    style.configure("TFrame", background=BG_PRIMARY)
    style.configure("TLabel", background=BG_PRIMARY, foreground=FG_PRIMARY, font=FONT_BODY)
    style.configure("TNotebook", background=BG_PRIMARY)
    style.configure("TNotebook.Tab", padding=[12, 6], font=FONT_BODY)

    style.configure(
        "Accent.TButton",
        background=ACCENT,
        foreground="#ffffff",
        font=FONT_BODY,
        padding=[16, 6],
    )
    style.map(
        "Accent.TButton",
        background=[("active", ACCENT_HOVER), ("disabled", BORDER)],
    )

    style.configure("TButton", padding=[12, 6], font=FONT_BODY)

    style.configure(
        "Treeview",
        background=BG_SECONDARY,
        foreground=FG_PRIMARY,
        fieldbackground=BG_SECONDARY,
        font=FONT_BODY,
        rowheight=26,
    )
    style.configure("Treeview.Heading", font=FONT_HEADING)

    style.configure("Heading.TLabel", font=FONT_HEADING)
    style.configure("Status.TLabel", font=FONT_SMALL, foreground=FG_SECONDARY)
    style.configure("Success.TLabel", font=FONT_SMALL, foreground=SUCCESS)
    style.configure("Error.TLabel", font=FONT_SMALL, foreground=ERROR)
