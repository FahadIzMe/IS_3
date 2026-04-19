# Network Security Scanner & Firewall Visualizer

A full-stack project for live network scanning and firewall rule simulation.

## Overview

This repository contains:

- Django backend API for scan orchestration and firewall simulation
- Flutter frontend dashboard for live scan monitoring and traffic flow visualization

Core features:

- Scan target by IP/hostname
- Scan modes: TCP SYN, UDP, Full Connect
- Live progress updates with per-port streaming results
- Firewall rule chain (allow/deny, protocol, source IP, port, priority)
- Traffic flow simulation with allow/deny decisions

## Project Structure

- backend: Django API and scan engine logic
- frontend: Flutter web/desktop UI
- requirements.txt: Python dependencies (backend)
- report.tex: LaTeX project report

## Tech Stack

### Backend

- Python 3.13+
- Django 6
- python-nmap
- scapy
- django-cors-headers

### Frontend

- Flutter 3.x
- Dart 3.x
- dio

## Prerequisites

Install the following tools first:

- Python 3.13+
- Flutter SDK 3.x
- Nmap (required for TCP SYN and UDP scans)

### Install Nmap

Windows (winget):

```powershell
winget install Insecure.Nmap
```

Or install from: https://nmap.org/download.html

After installation, ensure `nmap` is available on PATH.

## Setup

### 1) Clone repository

```bash
git clone git@github.com:FahadIzMe/IS_3.git
cd IS_3
```

### 2) Python environment and backend packages

If a `.env` virtual environment already exists, activate it.

Windows PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.env\Scripts\Activate.ps1
```

If `.env` does not exist, create it and install dependencies:

```powershell
python -m venv .env
.\.env\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3) Flutter packages

```powershell
Set-Location .\frontend
flutter pub get
```

## Run the Project

Open two terminals.

### Terminal A: Run backend

```powershell
Set-Location .\backend
..\.env\Scripts\Activate.ps1
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

Backend base URL:

- http://127.0.0.1:8000/api

### Terminal B: Run frontend

```powershell
Set-Location .\frontend
flutter run -d chrome
```

The default frontend API target is `http://127.0.0.1:8000/api`.

## API Endpoints

- `GET /api/health/`
- `POST /api/scan/start/`
- `GET /api/scan/jobs/`
- `GET /api/scan/jobs/<job_id>/`
- `GET /api/firewall/rules/`
- `POST /api/firewall/rules/`
- `DELETE /api/firewall/rules/<id>/`
- `POST /api/firewall/simulate/`

## Validation Commands

Backend checks:

```powershell
Set-Location .\backend
..\.env\Scripts\Activate.ps1
python manage.py check
```

Frontend checks:

```powershell
Set-Location .\frontend
flutter analyze
flutter test
```

## Notes on Scan and Firewall Behavior

- Scan results report actual network scan status (open/closed/filtered/etc.).
- Firewall rules are evaluated in the simulation module and produce policy decisions (allow/deny).
- A port can be technically open in scan results and still be denied in simulated traffic flow.

## Troubleshooting

### TCP SYN or UDP scan fails immediately

Cause: Nmap is missing or not on PATH.

Fix:

- Install Nmap
- Restart terminal
- Verify with:

```powershell
nmap --version
```

### Frontend cannot connect to backend

- Confirm backend is running on port 8000
- Confirm frontend API Base URL is `http://127.0.0.1:8000/api`

## License

This project is for educational use under the assignment context.
