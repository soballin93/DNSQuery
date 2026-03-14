from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from dnsquery.gui.styles import ENTRY_WIDTH, FONT_BODY, FONT_SMALL, PAD_X, PAD_Y


class InputPanel(ttk.Frame):
    def __init__(
        self,
        parent: tk.Widget,
        on_query: Callable[[str], None],
        on_export: Callable[[], None],
        on_api_key: Callable[[str | None], None],
    ) -> None:
        super().__init__(parent)
        self._on_query = on_query
        self._on_export = on_export
        self._on_api_key = on_api_key
        self._build()

    def _build(self) -> None:
        label = ttk.Label(self, text="Domain or IP Address:")
        label.grid(row=0, column=0, columnspan=5, sticky="w", padx=PAD_X, pady=(PAD_Y, 2))

        self.entry = ttk.Entry(self, width=ENTRY_WIDTH)
        self.entry.grid(row=1, column=0, sticky="ew", padx=(PAD_X, 4), pady=PAD_Y)
        self.entry.bind("<Return>", lambda _: self._trigger_query())

        self.query_btn = ttk.Button(
            self, text="Query", style="Accent.TButton", command=self._trigger_query
        )
        self.query_btn.grid(row=1, column=1, padx=4, pady=PAD_Y)

        self.export_btn = ttk.Button(
            self, text="Export CSV", command=self._on_export, state="disabled"
        )
        self.export_btn.grid(row=1, column=2, padx=4, pady=PAD_Y)

        self.api_key_btn = ttk.Button(
            self, text="API Key", command=self._show_api_key_dialog
        )
        self.api_key_btn.grid(row=1, column=3, padx=(4, PAD_X), pady=PAD_Y)

        self.status_label = ttk.Label(self, text="Ready", style="Status.TLabel")
        self.status_label.grid(row=2, column=0, columnspan=3, sticky="w", padx=PAD_X, pady=(0, PAD_Y))

        self.api_status_label = ttk.Label(self, text="SecurityTrails: not connected", style="Status.TLabel")
        self.api_status_label.grid(row=2, column=3, sticky="e", padx=(4, PAD_X), pady=(0, PAD_Y))

        self.columnconfigure(0, weight=1)

    def _trigger_query(self) -> None:
        query = self.entry.get().strip()
        if query:
            self._on_query(query)

    def _show_api_key_dialog(self) -> None:
        ApiKeyDialog(self.winfo_toplevel(), self._on_api_key_result)

    def _on_api_key_result(self, api_key: str | None) -> None:
        self._on_api_key(api_key)

    def set_api_connected(self, connected: bool) -> None:
        if connected:
            self.api_status_label.configure(
                text="SecurityTrails: connected", style="Success.TLabel"
            )
        else:
            self.api_status_label.configure(
                text="SecurityTrails: not connected", style="Status.TLabel"
            )

    def set_querying(self) -> None:
        self.query_btn.configure(state="disabled")
        self.export_btn.configure(state="disabled")
        self.entry.configure(state="disabled")
        self.status_label.configure(text="Querying...", style="Status.TLabel")

    def set_done(self, error_count: int = 0) -> None:
        self.query_btn.configure(state="normal")
        self.export_btn.configure(state="normal")
        self.entry.configure(state="normal")
        if error_count:
            self.status_label.configure(
                text=f"Done ({error_count} warning{'s' if error_count != 1 else ''})",
                style="Error.TLabel",
            )
        else:
            self.status_label.configure(text="Done", style="Success.TLabel")

    def set_error(self, message: str) -> None:
        self.query_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.entry.configure(state="normal")
        self.status_label.configure(text=f"Error: {message}", style="Error.TLabel")


class ApiKeyDialog(tk.Toplevel):
    """Modal dialog for entering a SecurityTrails API key."""

    def __init__(self, parent: tk.Widget, callback: Callable[[str | None], None]) -> None:
        super().__init__(parent)
        self._callback = callback
        self.title("SecurityTrails API Key")
        self.geometry("480x200")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        # Center on parent
        self.update_idletasks()
        px = parent.winfo_rootx() + (parent.winfo_width() - 480) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - 200) // 2
        self.geometry(f"+{max(0, px)}+{max(0, py)}")

    def _build(self) -> None:
        frame = ttk.Frame(self, padding=16)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="Enter your SecurityTrails API key to enable\nfull subdomain and CNAME discovery.",
            font=FONT_SMALL,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(
            frame,
            text="The key is used for this session only and is never stored.",
            font=FONT_SMALL,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        self._entry = ttk.Entry(frame, width=52, show="*", font=FONT_BODY)
        self._entry.pack(fill="x", pady=(0, 4))
        self._entry.focus_set()
        self._entry.bind("<Return>", lambda _: self._on_connect())

        self._error_label = ttk.Label(frame, text="", style="Error.TLabel")
        self._error_label.pack(anchor="w")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(8, 0))

        ttk.Button(btn_frame, text="Disconnect", command=self._on_disconnect).pack(side="left")
        ttk.Button(btn_frame, text="Cancel", command=self._on_cancel).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Connect", style="Accent.TButton", command=self._on_connect).pack(side="right")

    def _on_connect(self) -> None:
        key = self._entry.get().strip()
        if not key:
            self._error_label.configure(text="Please enter an API key.")
            return

        # Validate the key before accepting
        self._error_label.configure(text="Validating...")
        self.update()

        from dnsquery.securitytrails import ping
        ok, err = ping(key)
        if ok:
            self._callback(key)
            self.destroy()
        else:
            self._error_label.configure(text=err or "Invalid API key.")

    def _on_disconnect(self) -> None:
        self._callback(None)
        self.destroy()

    def _on_cancel(self) -> None:
        self.destroy()
