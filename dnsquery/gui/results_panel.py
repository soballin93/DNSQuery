from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from dnsquery.gui.styles import (
    BG_SECONDARY,
    FONT_HEADING,
    FONT_MONO,
    PAD_X,
    PAD_Y,
)
from dnsquery.models import QueryResult


class ResultsPanel(ttk.Notebook):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._build_tabs()

    def _build_tabs(self) -> None:
        self.summary_tab = _SummaryTab(self)
        self.ns_tab = _TreeTab(self, columns=("Name", "TTL", "Value"))
        self.soa_tab = _SoaTab(self)
        self.dns_tab = _TreeTab(self, columns=("Type", "Name", "TTL", "Value", "Priority"))
        self.whois_tab = _WhoisTab(self)
        self.errors_tab = _TextTab(self)

        self.add(self.summary_tab, text=" Summary ")
        self.add(self.ns_tab, text=" Name Servers ")
        self.add(self.soa_tab, text=" SOA ")
        self.add(self.dns_tab, text=" DNS Records ")
        self.add(self.whois_tab, text=" WHOIS ")
        self.add(self.errors_tab, text=" Errors ")

    def populate(self, result: QueryResult) -> None:
        self.summary_tab.populate(result)
        self.ns_tab.clear()
        for rec in result.nameservers:
            self.ns_tab.insert(rec.name, str(rec.ttl), rec.value)

        self.soa_tab.populate(result.soa)

        self.dns_tab.clear()
        for rec in result.dns_records:
            self.dns_tab.insert(
                rec.record_type,
                rec.name,
                str(rec.ttl),
                rec.value,
                str(rec.priority) if rec.priority is not None else "",
            )

        self.whois_tab.populate(result.whois)

        self.errors_tab.clear()
        if result.errors:
            self.errors_tab.set_text("\n".join(result.errors))
        else:
            self.errors_tab.set_text("No errors or warnings.")

        if result.reverse_dns:
            for rec in result.reverse_dns:
                self.dns_tab.insert(
                    rec.record_type,
                    rec.name,
                    str(rec.ttl),
                    rec.value,
                    "",
                )

    def clear(self) -> None:
        self.summary_tab.clear()
        self.ns_tab.clear()
        self.soa_tab.clear()
        self.dns_tab.clear()
        self.whois_tab.clear()
        self.errors_tab.clear()


class _TreeTab(ttk.Frame):
    def __init__(self, parent: tk.Widget, columns: tuple[str, ...]) -> None:
        super().__init__(parent)
        self._columns = columns
        self._sort_reverse: dict[str, bool] = {col: False for col in columns}
        self._build()

    def _build(self) -> None:
        self.tree = ttk.Treeview(self, columns=self._columns, show="headings", selectmode="extended")
        for col in self._columns:
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, minwidth=60)

        # Adjust column widths for common layouts
        if len(self._columns) == 5:  # DNS Records tab
            self.tree.column("Type", width=70, stretch=False)
            self.tree.column("Name", width=200)
            self.tree.column("TTL", width=70, stretch=False)
            self.tree.column("Value", width=400)
            self.tree.column("Priority", width=70, stretch=False)
        elif len(self._columns) == 3:  # NS tab
            self.tree.column("Name", width=200)
            self.tree.column("TTL", width=80, stretch=False)
            self.tree.column("Value", width=400)

        scrollbar_y = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        scrollbar_x = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        scrollbar_x.grid(row=1, column=0, sticky="ew")

        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def insert(self, *values: str) -> None:
        self.tree.insert("", "end", values=values)

    def clear(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _sort_by(self, col: str) -> None:
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children()]
        items.sort(reverse=self._sort_reverse[col])
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)
        self._sort_reverse[col] = not self._sort_reverse[col]


class _SummaryTab(ttk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._text = tk.Text(
            self,
            wrap="word",
            font=FONT_MONO,
            background=BG_SECONDARY,
            relief="flat",
            padx=PAD_X,
            pady=PAD_Y,
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        self._text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def populate(self, result: QueryResult) -> None:
        lines: list[str] = []
        lines.append("TRANSFER STATUS")
        lines.append("=" * 50)

        w = result.whois
        if w:
            locked = any(
                "transferprohibited" in s.lower() for s in w.status
            )
            lock_label = "LOCKED" if locked else "UNLOCKED"
            lock_codes = [s for s in w.status if "transfer" in s.lower()]
            lock_detail = f" ({', '.join(lock_codes)})" if lock_codes else ""
            lines.append(f"  Lock Status:    {lock_label}{lock_detail}")
            lines.append(f"  Registrar:      {w.registrar or 'N/A'}")
            lines.append(f"  DNSSEC:         {w.dnssec or 'N/A'}")
            lines.append("")
            lines.append("DATES")
            lines.append("-" * 50)
            lines.append(f"  Created:        {w.creation_date or 'N/A'}")
            lines.append(f"  Expires:        {w.expiration_date or 'N/A'}")
            lines.append(f"  Updated:        {w.updated_date or 'N/A'}")
            lines.append("")

            # EPP Status Codes
            if w.status:
                lines.append("EPP STATUS CODES")
                lines.append("-" * 50)
                for s in w.status:
                    lines.append(f"  {s}")
                lines.append("")
        else:
            lines.append("  WHOIS data unavailable")
            lines.append("")

        lines.append("NAME SERVERS")
        lines.append("-" * 50)
        if result.nameservers:
            for ns in result.nameservers:
                lines.append(f"  {ns.value}")
        else:
            lines.append("  No NS records found")

        self._set_text("\n".join(lines))

    def _set_text(self, text: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self._set_text("")


class _SoaTab(ttk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._text = tk.Text(
            self,
            wrap="word",
            font=FONT_MONO,
            background=BG_SECONDARY,
            relief="flat",
            padx=PAD_X,
            pady=PAD_Y,
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        self._text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def populate(self, soa) -> None:
        if soa is None:
            self._set_text("No SOA record found.")
            return
        lines = [
            "SOA RECORD",
            "=" * 50,
            f"  Primary NS:          {soa.mname}",
            f"  Responsible Party:   {soa.rname}",
            f"  Serial:              {soa.serial}",
            f"  Refresh:             {soa.refresh}s",
            f"  Retry:               {soa.retry}s",
            f"  Expire:              {soa.expire}s",
            f"  Minimum TTL:         {soa.minimum}s",
        ]
        self._set_text("\n".join(lines))

    def _set_text(self, text: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self._set_text("")


class _WhoisTab(ttk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._text = tk.Text(
            self,
            wrap="word",
            font=FONT_MONO,
            background=BG_SECONDARY,
            relief="flat",
            padx=PAD_X,
            pady=PAD_Y,
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        self._text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def populate(self, whois) -> None:
        if whois is None:
            self._set_text("WHOIS data unavailable.")
            return
        lines: list[str] = []
        lines.append("REGISTRAR")
        lines.append("=" * 50)
        lines.append(f"  Name:    {whois.registrar or 'N/A'}")
        lines.append(f"  URL:     {whois.registrar_url or 'N/A'}")
        lines.append("")

        lines.append("REGISTRANT CONTACT")
        lines.append("-" * 50)
        lines.append(f"  Name:    {whois.registrant_name or 'N/A'}")
        lines.append(f"  Org:     {whois.registrant_org or 'N/A'}")
        lines.append(f"  Email:   {whois.registrant_email or 'N/A'}")
        lines.append("")

        lines.append("ADMIN CONTACT")
        lines.append("-" * 50)
        lines.append(f"  Name:    {whois.admin_name or 'N/A'}")
        lines.append(f"  Email:   {whois.admin_email or 'N/A'}")
        lines.append("")

        lines.append("TECH CONTACT")
        lines.append("-" * 50)
        lines.append(f"  Name:    {whois.tech_name or 'N/A'}")
        lines.append(f"  Email:   {whois.tech_email or 'N/A'}")
        lines.append("")

        lines.append("DOMAIN STATUS")
        lines.append("-" * 50)
        if whois.status:
            for s in whois.status:
                lines.append(f"  {s}")
        else:
            lines.append("  No status codes available")
        lines.append("")

        lines.append("NAME SERVERS (WHOIS)")
        lines.append("-" * 50)
        if whois.name_servers:
            for ns in whois.name_servers:
                lines.append(f"  {ns}")
        else:
            lines.append("  No name servers listed")

        self._set_text("\n".join(lines))

    def _set_text(self, text: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self._set_text("")


class _TextTab(ttk.Frame):
    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent)
        self._text = tk.Text(
            self,
            wrap="word",
            font=FONT_MONO,
            background=BG_SECONDARY,
            relief="flat",
            padx=PAD_X,
            pady=PAD_Y,
            state="disabled",
        )
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        self._text.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

    def set_text(self, text: str) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.insert("1.0", text)
        self._text.configure(state="disabled")

    def clear(self) -> None:
        self.set_text("")
