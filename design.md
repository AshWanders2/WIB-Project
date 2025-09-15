# WIB Project – Design Notes


MIT License

Copyright (c) 2025 Verity

## Purpose
WIB (Windows Integrity Baseline) gives everyday Windows users a way to **capture a “day-one snapshot” of their system**.  
This snapshot is a trusted baseline that can be compared later to detect tampering, malware persistence, or unauthorized changes.  

The philosophy is simple:
- Start with a clean machine.
- Record everything that matters (drivers, services, autoruns, certs, boot trust, etc.).
- Store it securely.
- Compare against it when something feels “off.”

## Goals
- **Consumer-focused**: no enterprise tools, no cloud requirements.
- **Zero-cost trust**: all functions are local-first.
- **Evidence-grade logging**: hashes, manifests, and optional encrypted archives.
- **Resilience**: support for offline backup, USB export, and future rescue boot environments.

## Architecture Overview
### Components
- **PowerShell Script (baseline.ps1)**  
  Captures system state, writes JSON + manifest, compresses into ZIP, optional upload.
- **Manifest**  
  Provides tamper-evident SHA-256 hash of the baseline snapshot.
- **README & Docs**  
  Guidance for non-technical users to run and protect their baseline.

### Planned Extensions
- **Diff Mode**: compare current system against baseline.json.
- **Encryption Helper**: password-protect baseline archives.
- **Rescue Toolkit**: bootable Linux ISO for forensic export and verification.
- **TPM Anchoring**: seal baseline hashes to device TPM for boot-time integrity alerts.

## Design Principles
- **User Sovereignty**: the user owns their data, always.
- **Transparency**: logs and hashes are human-readable.
- **No Telemetry**: nothing leaves the machine unless the user chooses to upload.
- **Minimalism**: one script does the job; other tools remain optional.

---

_Last updated: 2025-09-15_

