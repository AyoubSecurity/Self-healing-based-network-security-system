# Self-Healing Network Security System

An autonomous, modular network security engine built in Python to detect real-time anomalies, mitigate network threats without manual intervention, and maintain system self-healing capabilities.

## Key Features
- **Real-Time Monitoring & Detection:** Scapy-based packet inspection and `python-nmap` host scanning.
- **Automated Mitigation:** Automated IP/MAC blocking, dynamic rate limiting, and alert generation.
- **Self-Healing Engine:** Multi-threaded process recovery, automatic database validation, and backup restoration.
- **Admin Control Web Portal:** Flask dashboard utilizing Chart.js for real-time traffic monitoring, threshold configuration, and socket endpoint execution.

## Architecture
Designed using strict software design patterns and UML modeling (StarUML), separating the scanner, traffic monitor, database engine, socket engine, and web dashboard into decoupled components.

## Setup

Set up virtual environment (venv):

> **Admin PowerShell / CMD**
> python -m venv venv
> .\venv\Scripts\activate
> pip install -r requirements.txt

Linux / macOS:
> **Bash**
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt

## Launch the application:

> **Windows:** 
> python app.py

> **Linux / macOS:** 
> sudo ./venv/bin/python app.py

Access Dashboard: Open http://localhost:5000 (User: admin | Password: admin).


