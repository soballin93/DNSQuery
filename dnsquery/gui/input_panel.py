from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from dnsquery.gui.styles import ENTRY_WIDTH, PAD_X, PAD_Y


class InputPanel(ttk.Frame):
    def __init__(
        self,
        parent: tk.Widget,
        on_query: Callable[[str], None],
        on_export: Callable[[], None],
    ) -> None:
        super().__init__(parent)
        self._on_query = on_query
        self._on_export = on_export
        self._build()

    def _build(self) -> None:
        label = ttk.Label(self, text="Domain or IP Address:")
        label.grid(row=0, column=0, columnspan=4, sticky="w", padx=PAD_X, pady=(PAD_Y, 2))

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
        self.export_btn.grid(row=1, column=2, padx=(4, PAD_X), pady=PAD_Y)

        self.status_label = ttk.Label(self, text="Ready", style="Status.TLabel")
        self.status_label.grid(row=2, column=0, columnspan=4, sticky="w", padx=PAD_X, pady=(0, PAD_Y))

        self.columnconfigure(0, weight=1)

    def _trigger_query(self) -> None:
        query = self.entry.get().strip()
        if query:
            self._on_query(query)

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
