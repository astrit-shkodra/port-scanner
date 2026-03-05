# Port Scanner

A multi-threaded TCP port scanner with service detection and banner grabbing.

## Features

- Multi-threaded scanning with configurable thread pool
- Service detection (SSH, HTTP, FTP, etc.)
- Banner grabbing (IPv4/IPv6)
- Export results to JSON or CSV
- Clean CLI interface

## Installation
```bash
git clone git@github.com:astrit-shkodra/port-scanner.git
cd port-scanner
```

No dependencies required — uses only Python standard library.

## Usage
```bash
# Basic scan
python3 scanner.py -t scanme.nmap.org

# Scan specific ports
python3 scanner.py -t scanme.nmap.org -p 22,80,443

# Scan port range with banner grabbing
python3 scanner.py -t scanme.nmap.org -p 1-1000 --banner

# Export results
python3 scanner.py -t scanme.nmap.org -p 1-100 --banner -o results.json
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target` | Target IP or hostname | Required |
| `-p, --ports` | Port range or list | 1-1000 |
| `--timeout` | Timeout per port (seconds) | 1.0 |
| `--threads` | Number of threads | 100 |
| `-b, --banner` | Enable banner grabbing | Off |
| `-o, --output` | Output file (.json or .csv) | None |

## Example Output
```
==================================================
Cible      : scanme.nmap.org
Ports      : 1-100 (100 ports)
Threads    : 100
Timeout    : 1.0s
Banner     : Oui
==================================================
[+] Port 22 (SSH)
[+] Port 80 (HTTP)

[*] Récupération des bannières...
    Port 22 (SSH): SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    Port 80 (HTTP): HTTP/1.1 200 OK

==================================================
2 ports ouverts : [22, 80]
```
