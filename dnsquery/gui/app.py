from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox

from dnsquery.dns_resolver import is_ip_address, resolve_domain, resolve_ip
from dnsquery.export import export_to_csv
from dnsquery.gui.input_panel import InputPanel
from dnsquery.gui.results_panel import ResultsPanel
from dnsquery.gui.styles import configure_styles
from dnsquery.models import QueryResult
from dnsquery.securitytrails import get_domain_details, get_subdomains
from dnsquery.validation import ValidationResult, validate_dns
from dnsquery.whois_lookup import lookup_whois


class DNSQueryApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DNSQuery - Domain Transfer Toolkit")
        self.geometry("960x720")
        self.minsize(800, 600)

        configure_styles(self)

        self._result: QueryResult | None = None
        self._api_key: str | None = None
        self._build()

        # Force window on-screen (WSLg can place windows at negative coordinates)
        self.update_idletasks()
        x = self.winfo_x()
        y = self.winfo_y()
        if x < 0 or y < 0:
            self.geometry("+0+0")
        self.lift()
        self.focus_force()

        # Allow CTRL+C to exit from the terminal
        self.after(200, self._poll)

    def _build(self) -> None:
        self.input_panel = InputPanel(
            self,
            on_query=self._start_query,
            on_export=self._export_csv,
            on_api_key=self._on_api_key_changed,
        )
        self.input_panel.pack(fill="x", padx=8, pady=(8, 4))

        self.results_panel = ResultsPanel(self)
        self.results_panel.pack(fill="both", expand=True, padx=8, pady=(4, 8))

    def _on_api_key_changed(self, api_key: str | None) -> None:
        self._api_key = api_key
        self.input_panel.set_api_connected(api_key is not None)

    def _start_query(self, query: str) -> None:
        self.input_panel.set_querying()
        self.results_panel.clear()
        self._result = None
        thread = threading.Thread(target=self._run_query, args=(query,), daemon=True)
        thread.start()

    def _run_query(self, query: str) -> None:
        try:
            if is_ip_address(query):
                result = resolve_ip(query)
                # Attempt WHOIS on PTR hostname if found
                if result.reverse_dns:
                    hostname = result.reverse_dns[0].value.rstrip(".")
                    whois_info, whois_err = lookup_whois(hostname)
                    result.whois = whois_info
                    if whois_err:
                        result.errors.append(f"WHOIS: {whois_err}")
            else:
                # If we have an API key, fetch subdomains from SecurityTrails
                subdomains: list[str] | None = None
                if self._api_key:
                    subdomains, st_err = get_subdomains(query, self._api_key)
                    if st_err:
                        result_errors = [f"SecurityTrails: {st_err}"]
                        # Continue without subdomains
                        subdomains = None
                    else:
                        result_errors = []
                else:
                    result_errors = []

                result = resolve_domain(query, subdomains=subdomains)
                result.errors.extend(result_errors)

                whois_info, whois_err = lookup_whois(query)
                result.whois = whois_info
                if whois_err:
                    result.errors.append(f"WHOIS: {whois_err}")

            # Validate DNS against SecurityTrails if API key is present
            validation: ValidationResult | None = None
            if self._api_key and not is_ip_address(query):
                st_dns, st_err = get_domain_details(query, self._api_key)
                if st_err:
                    result.errors.append(f"SecurityTrails validation: {st_err}")
                elif st_dns is not None:
                    validation = validate_dns(result, st_dns)
                    result.errors.extend(validation.errors)

            self.after(0, lambda: self._on_query_complete(result, validation))
        except Exception as e:
            self.after(0, lambda: self.input_panel.set_error(str(e)))

    def _on_query_complete(self, result: QueryResult, validation: ValidationResult | None = None) -> None:
        self._result = result
        self.results_panel.populate(result, validation=validation)
        self.input_panel.set_done(error_count=len(result.errors))

    def _poll(self) -> None:
        """Periodic no-op callback so Python can process signals (e.g. CTRL+C)."""
        self.after(200, self._poll)

    def _export_csv(self) -> None:
        if self._result is None:
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialfile=f"{self._result.query_input.replace('.', '_')}_dns_report.csv",
        )
        if not filepath:
            return
        try:
            export_to_csv(self._result, filepath)
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export:\n{e}")
