#!/usr/bin/env python3
"""
PDF PII Redactor
A simple tool to redact personally identifiable information from PDFs.
https://github.com/prebhdevsingh/
"""

import re
import os
import sys
import subprocess
import webbrowser
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

# Auto-install dependencies on first run
def _ensure_dependencies():
    missing = []
    try:
        import fitz
    except ImportError:
        missing.append("PyMuPDF")
    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")
    if missing:
        print(f"Installing missing packages: {', '.join(missing)}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install"] + missing,
            stdout=subprocess.DEVNULL,
        )
        print("Done. Starting app...")

_ensure_dependencies()

import fitz  # PyMuPDF
import customtkinter as ctk

# --- PII Patterns -----------------------------------------------------------

PII_CATEGORIES = {
    "SSN": {
        "label": "Social Security Numbers",
        "patterns": [
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b\d{3}\s\d{2}\s\d{4}\b",
            r"\b\d{9}\b(?=.*(?:SSN|social))",
        ],
    },
    "EIN": {
        "label": "Employer Identification Numbers",
        "patterns": [
            r"\b\d{2}-\d{7}\b",
        ],
    },
    "Phone": {
        "label": "Phone Numbers",
        "patterns": [
            r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            r"\b\d{3}-\d{3}-\d{4}\b",
        ],
    },
    "Email": {
        "label": "Email Addresses",
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ],
    },
    "DOB": {
        "label": "Dates of Birth",
        "patterns": [
            r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b",
            r"\b(?:19|20)\d{2}[/-](?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])\b",
        ],
    },
    "Address": {
        "label": "Street Addresses",
        "patterns": [
            r"\b\d{1,5}\s+(?:[A-Za-z]+\s?){1,4}(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court|Pl|Place|Way|Cir|Circle|Pkwy|Parkway)\.?\b",
        ],
    },
    "ZipCode": {
        "label": "ZIP Codes",
        "patterns": [
            r"\b\d{5}(?:-\d{4})?\b",
        ],
    },
    "AccountNum": {
        "label": "Bank Account / Routing Numbers",
        "patterns": [
            r"\b\d{8,17}\b(?=.*(?:account|routing|acct))",
        ],
    },
}

# --- Redaction Engine --------------------------------------------------------


def find_pii(text, selected_categories, custom_regex=None):
    """Find all PII matches in text. Returns list of (start, end, category)."""
    matches = []
    for cat_key, cat_info in PII_CATEGORIES.items():
        if cat_key not in selected_categories:
            continue
        for pattern in cat_info["patterns"]:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                matches.append((m.start(), m.end(), cat_key, m.group()))
    if custom_regex and custom_regex.strip():
        try:
            for m in re.finditer(custom_regex, text):
                matches.append((m.start(), m.end(), "Custom", m.group()))
        except re.error:
            pass  # invalid regex silently skipped during detection
    return matches


def redact_pdf(input_path, output_path, selected_categories, custom_regex=None):
    """Redact PII from a PDF. Returns count of redactions made."""
    doc = fitz.open(input_path)
    total_redactions = 0

    for page in doc:
        text = page.get_text()
        matches = find_pii(text, selected_categories, custom_regex)

        for start, end, category, matched_text in matches:
            # Search for the matched text on the page and redact each occurrence
            text_instances = page.search_for(matched_text)
            for inst in text_instances:
                page.add_redact_annot(inst, fill=(0, 0, 0))
                total_redactions += 1

        page.apply_redactions()

    doc.save(output_path)
    doc.close()
    return total_redactions


# --- GUI Application --------------------------------------------------------


class RedactorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("PDF PII Redactor")
        self.geometry("620x700")
        self.minsize(580, 650)
        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self.selected_file = None
        self.category_vars = {}

        self._build_ui()

    def _build_ui(self):
        # --- Header ---
        header = ctk.CTkLabel(
            self,
            text="PDF PII Redactor",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.pack(pady=(20, 5))

        subtitle = ctk.CTkLabel(
            self,
            text="Remove personally identifiable information from PDFs",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        )
        subtitle.pack(pady=(0, 15))

        # --- PII Categories ---
        cat_frame = ctk.CTkFrame(self)
        cat_frame.pack(padx=20, pady=(0, 10), fill="x")

        cat_label = ctk.CTkLabel(
            cat_frame,
            text="Select PII categories to redact:",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        cat_label.pack(anchor="w", padx=15, pady=(12, 8))

        # Two-column layout for checkboxes
        checks_frame = ctk.CTkFrame(cat_frame, fg_color="transparent")
        checks_frame.pack(padx=15, pady=(0, 12), fill="x")
        checks_frame.columnconfigure(0, weight=1)
        checks_frame.columnconfigure(1, weight=1)

        items = list(PII_CATEGORIES.items())
        for i, (key, info) in enumerate(items):
            var = ctk.BooleanVar(value=True)
            self.category_vars[key] = var
            cb = ctk.CTkCheckBox(checks_frame, text=info["label"], variable=var)
            cb.grid(row=i // 2, column=i % 2, sticky="w", padx=10, pady=4)

        # Select All / Deselect All
        btn_row = ctk.CTkFrame(cat_frame, fg_color="transparent")
        btn_row.pack(padx=15, pady=(0, 12), fill="x")

        ctk.CTkButton(
            btn_row, text="Select All", width=100, height=28,
            font=ctk.CTkFont(size=12),
            command=lambda: self._toggle_all(True),
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="Deselect All", width=100, height=28,
            font=ctk.CTkFont(size=12),
            command=lambda: self._toggle_all(False),
        ).pack(side="left")

        # --- Custom Regex ---
        regex_frame = ctk.CTkFrame(self)
        regex_frame.pack(padx=20, pady=(0, 10), fill="x")

        regex_label = ctk.CTkLabel(
            regex_frame,
            text="Custom regex pattern (optional):",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        regex_label.pack(anchor="w", padx=15, pady=(12, 4))

        regex_hint = ctk.CTkLabel(
            regex_frame,
            text="Generate patterns at regex101.com — paste them here",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        regex_hint.pack(anchor="w", padx=15, pady=(0, 6))

        self.regex_entry = ctk.CTkEntry(
            regex_frame, placeholder_text=r"e.g. \b\d{4}-\d{4}-\d{4}-\d{4}\b"
        )
        self.regex_entry.pack(padx=15, pady=(0, 12), fill="x")

        # --- File Selection ---
        file_frame = ctk.CTkFrame(self)
        file_frame.pack(padx=20, pady=(0, 10), fill="x")

        self.file_label = ctk.CTkLabel(
            file_frame,
            text="No file selected",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        )
        self.file_label.pack(anchor="w", padx=15, pady=(12, 8))

        file_btn_row = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_btn_row.pack(padx=15, pady=(0, 12), fill="x")

        ctk.CTkButton(
            file_btn_row, text="Select PDF", width=140,
            command=self._select_file,
        ).pack(side="left")

        # --- Redact Button ---
        self.redact_btn = ctk.CTkButton(
            self,
            text="Redact PDF",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=45,
            command=self._run_redaction,
            state="disabled",
        )
        self.redact_btn.pack(padx=20, pady=(5, 10), fill="x")

        # --- Status ---
        self.status_label = ctk.CTkLabel(
            self, text="", font=ctk.CTkFont(size=12), text_color="gray"
        )
        self.status_label.pack(pady=(0, 5))

        # --- Footer ---
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.pack(side="bottom", pady=(0, 12))

        github_link = ctk.CTkLabel(
            footer_frame,
            text="GitHub: prebhdevsingh",
            font=ctk.CTkFont(size=12, underline=True),
            text_color="#3B8ED0",
            cursor="hand2",
        )
        github_link.pack()
        github_link.bind(
            "<Button-1>",
            lambda e: webbrowser.open("https://github.com/prebhdevsingh/"),
        )

    def _toggle_all(self, state):
        for var in self.category_vars.values():
            var.set(state)

    def _select_file(self):
        path = filedialog.askopenfilename(
            title="Select a PDF",
            filetypes=[("PDF files", "*.pdf")],
        )
        if path:
            self.selected_file = path
            name = Path(path).name
            self.file_label.configure(
                text=f"Selected: {name}", text_color=("black", "white")
            )
            self.redact_btn.configure(state="normal")
            self.status_label.configure(text="")

    def _run_redaction(self):
        if not self.selected_file:
            return

        selected = [k for k, v in self.category_vars.items() if v.get()]
        custom_regex = self.regex_entry.get().strip() or None

        if not selected and not custom_regex:
            messagebox.showwarning(
                "Nothing to redact",
                "Please select at least one PII category or enter a custom regex.",
            )
            return

        # Validate custom regex
        if custom_regex:
            try:
                re.compile(custom_regex)
            except re.error as e:
                messagebox.showerror(
                    "Invalid Regex",
                    f"Your custom regex pattern is invalid:\n{e}\n\n"
                    "Tip: Use regex101.com to test your pattern first.",
                )
                return

        # Build output path
        input_path = Path(self.selected_file)
        output_path = input_path.parent / f"{input_path.stem}_redacted.pdf"

        self.status_label.configure(text="Redacting... please wait.")
        self.redact_btn.configure(state="disabled")
        self.update()

        try:
            count = redact_pdf(
                str(input_path), str(output_path), selected, custom_regex
            )
            self.status_label.configure(
                text=f"Done! {count} redaction(s) applied.", text_color="green"
            )
            messagebox.showinfo(
                "Redaction Complete",
                f"Redacted PDF saved to:\n{output_path}\n\n{count} redaction(s) applied.",
            )
        except Exception as e:
            self.status_label.configure(text="Error during redaction.", text_color="red")
            messagebox.showerror("Error", f"Failed to redact PDF:\n{e}")
        finally:
            self.redact_btn.configure(state="normal")


# --- Entry Point -------------------------------------------------------------

if __name__ == "__main__":
    app = RedactorApp()
    app.mainloop()
