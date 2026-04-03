# PDF PII Redactor

A simple, lightweight tool to redact personally identifiable information (PII) from PDFs like tax returns. Works on **Windows** and **Mac**.

All processing happens **locally on your machine** — no data is sent anywhere.

## What It Redacts

Built-in categories you can toggle on/off:

- **Social Security Numbers** (SSN)
- **Employer Identification Numbers** (EIN)
- **Phone Numbers**
- **Email Addresses**
- **Dates of Birth**
- **Street Addresses**
- **ZIP Codes**
- **Bank Account / Routing Numbers**

You can also enter a **custom regex pattern** to match anything else. Use [regex101.com](https://regex101.com/) to build and test patterns.

## Setup (One-Time)

### 1. Install Python

If you don't have Python installed:

- **Mac**: Download from [python.org/downloads](https://www.python.org/downloads/) and run the installer.
- **Windows**: Download from [python.org/downloads](https://www.python.org/downloads/). During installation, **check the box that says "Add Python to PATH"**.

To verify it's installed, open a terminal (Mac) or Command Prompt (Windows) and type:

```
python --version
```

You should see something like `Python 3.12.x`.

> **Note:** On some Macs, you may need to use `python3` instead of `python` in the commands below.

### 2. Install Dependencies

Open a terminal / Command Prompt, navigate to this folder, and run:

```
pip install -r requirements.txt
```

That's it — one-time setup is done.

## Usage

1. Open a terminal / Command Prompt and navigate to this folder.
2. Run:

```
python redact.py
```

3. The app will open. Select which PII categories you want to redact (all are selected by default).
4. Optionally enter a custom regex pattern.
5. Click **Select PDF** and choose your file.
6. Click **Redact PDF**.
7. A new file named `yourfile_redacted.pdf` will be saved in the same folder as the original.

## Important Notes

- **Redaction is permanent** — the original text is removed from the redacted PDF, not just hidden behind a black box.
- **Always keep your original PDF** — the tool creates a new file and does not modify the original.
- **Review the output** — regex-based detection may miss some items or catch false positives. Always check the redacted PDF before sharing.

## Author

[prebhdevsingh](https://github.com/prebhdevsingh/)
