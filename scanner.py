import json
import csv
import socket
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy"
        }

def parse_arguments():
    """
    Parse les arguments de la ligne de commande

    Returns:
        Les arguments parsés
    """
    parser = argparse.ArgumentParser(
            description="Scanner de ports multi-threadé",
            usage="python3 scanner.py -t TARGET [options]"
            )

    # Argument obligatoire
    parser.add_argument(
            "-t", "--target",
            required=True,
            help="Cible à scanner (IP ou hostname)"
            )

    # Arguments optionnels
    parser.add_argument(
            "-p", "--ports",
            default="1-1000",
            help="Plage de ports (ex: 1-1000 ou 22,80,443). Défaut: 1-1000"
            )

    parser.add_argument(
            "--timeout",
            type=float,
            default=1.0,
            help="Timeout par port en secondes. Défaut: 1.0"
            )

    parser.add_argument(
            "--threads",
            type=int,
            default=100,
            help="Nombre de threads. Défaut: 100"
            )

    parser.add_argument(
            "-b", "--banner",
            action="store_true",
            help="activer le banner grabbing"
            )
    parser.add_argument(
            "-o", "--output",
            help="Fichier de sortie (EX: results.json ou results.csv)"
            )

    return parser.parse_args()

def export_json(results, filename):
    """
    Exporte les resultats en JSON.

    arg:
        results: Dictionnaire des resultats
        filename: Nom du fichier de sortie
    """
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[*] Résultats exportés dans {filename}")

def export_csv(results, filename):
    """
    Exporte les resultats en CSV.
    
    arg:
        results: Dictionnaire des resultats
        filename: Nom du fichier de sortie

    """
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Service", "Bannière"])

        for port_info in results["ports"]:
            writer.writerow([
                port_info["port"],
                port_info["service"],
                port_info["banner"]
            ])
    print(f"[*] Résultats exportés dans {filename}")


def parse_ports(ports_str):
    """
    Parse une chaîne de ports en liste.

    Args:
        ports_str: "1-1000" ou "22,80,443"

    """
    ports = []

    for part in ports_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end)+ 1))
        else:
            ports.append(int(part))
        
    return ports

def scan_port(target, port, timeout=1):
	"""
		
	Tente une connexion TCP sur un port.
		
	Args:
		target: Adresse IP ou hostname de la cible
		port: Numéro du port à scanner
		timeout: Délai max d'attente (en seconde)
		
	returns:
		true si le port est ouvert, False sinon
		
    """
	try:
		
		# Création d'une socket TCP (IPv4)
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(timeout)

		# connect_ex retourne 0 si connexion réussie
		result = sock.connect_ex((target, port))
		sock.close()
		
		return result == 0
		
	except socket.error:
		return False



def grab_banner(target, port, timeout=2):
    """

    Tente de récupérer la bannière d'un service.

    Returns:
        La bannière (string) ou None si échec
    
    """
    for family in [socket.AF_INET, socket.AF_INET6]:
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))               
            
            # Étape 1 : Écouter si le service parle en premier
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    sock.close()
                    return banner[:100]
            except socket.timeout:
                pass

            # Étape 2 : Envoyer une requête HTTP si rien reçu
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            if banner:
                return banner[:100]

        except:
            continue
   
    return None




def scan_port_range(target, start_port, end_port, max_workers=100, timeout=1):
    """

    Scanne une plage de ports avec multi-threading contrôle.

    Args:
        target: Adresse IP ou hostname de la cible
        start_port: Premier port à scanner
        end_port: Dernier port à scanner
        max_workers: Nombre de threads simultanés
        timeout: Délai d'attente par port


    returns:
        liste des ports ouverts
    
    """
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # On crée un dictionnaire {future: port}
        futures = {
                executor.submit(scan_port, target, port, timeout): port
                for port in range(start_port, end_port + 1)
        }

        # On récupère les résultats au fur et à mesure
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result(): # Si le port est ouvert
                    print(f"[+] Port {port} ouvert")
                    open_ports.append(port)
            except Exception as e:
                print(f"[-] Erreur sur port {port}: {e}")

    return sorted(open_ports)




# Test rapide
if __name__ == "__main__":
    args = parse_arguments()

    target = args.target
    ports = parse_ports(args.ports)
    timeout = args.timeout
    max_workers = args.threads
    grab = args.banner

    print(f"{'='*50}")
    print(f"Cible       : {target}")
    if len(ports) <= 10:
        print(f"Ports       : {ports}")
    else:
        print(f"Ports       : {ports[0]}-{ports[-1]} ({len(ports)} ports)")
    print(f"Threads     : {max_workers}")
    print(f"Timeout     : {timeout}s")
    print(f"Banner      : {'Oui' if grab else 'Non'}")
    print(f"{'='*50}")
    
    # Étape 1 : Scanner les ports
    open_ports = scan_port_range(target, ports[0], ports[-1], max_workers, timeout)

    # Étape 2 : Récupérer les bannière si demandé
    results = {
            "target": target,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ports": []
            }


    if args.banner and open_ports:
        print(f"\n[*] Récupération des bannières...")
        for port in open_ports:
            service = COMMON_PORTS.get(port, "Inconnu")
            banner = grab_banner(target, port) #if args.banner else None
            print(f"    Port {port} ({service}): {banner}")

            results["ports"].append({
                "port": port,
                "service": service,
                "banner": banner
                })
    # Étape 3 : Export si demandé
    if args.output:
        if args.output.endswith(".json"):
            export_json(results, args.output)
        elif args.output.endswith(".csv"):
            export_csv(results, args.output)
        else:
            print(f"[*] Format non reconnu. Utilise .json ou .csv")


    print(f"\n{'='*50}")
    print(f"{len(open_ports)} ports ouverts : {open_ports}")

