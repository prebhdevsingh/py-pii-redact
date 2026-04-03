# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Single-file Python GUI application that redacts PII from PDFs using regex-based pattern matching. Targeted at non-technical users on Windows and Mac. All processing is local/offline.

## Running

```
python redact.py
```

Dependencies (`PyMuPDF`, `customtkinter`) auto-install on first run via `_ensure_dependencies()`.

## Architecture

Everything lives in `redact.py`, organized in three sections:

1. **PII Patterns** (`PII_CATEGORIES` dict) — regex patterns grouped by category (SSN, EIN, Phone, Email, DOB, Address, ZipCode, AccountNum). Each category has a label and list of patterns.
2. **Redaction Engine** (`find_pii`, `redact_pdf`) — extracts text per page with `fitz`, matches against selected patterns, uses `page.add_redact_annot()` + `page.apply_redactions()` for permanent text removal.
3. **GUI** (`RedactorApp` class, extends `ctk.CTk`) — customtkinter app with category checkboxes, custom regex input, file picker, and redact button. Output saves as `{stem}_redacted.pdf` alongside the original.

## Key Design Decisions

- **Single file** — intentional for easy distribution to non-technical users. Do not split into modules.
- **Regex-only detection** — no ML/NLP dependencies. Patterns are in `PII_CATEGORIES` and easy to extend.
- **True redaction** — uses PyMuPDF's `apply_redactions()` which permanently removes underlying text, not just a visual overlay.
- **Auto-install** — `_ensure_dependencies()` runs before any library imports so users never need to run pip manually.
- **GitHub link** — footer links to https://github.com/prebhdevsingh/

## Adding a New PII Category

Add an entry to `PII_CATEGORIES` with a key, label, and list of regex patterns. The GUI checkbox is generated automatically from this dict.
