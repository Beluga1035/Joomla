# Joomla Pentest Pro 🔍

## Key Features 🛠️
- ✅ **Smart Brute Force** with CSRF handling
- ✅ **Vulnerability detection** (LFI, XSS, SQLi)
- ✅ **Integrated com_sef LFI exploit**
- ✅ **200+ common passwords** wordlist
- ✅ **Configurable multi-threading** (up to 50 threads)
- ✅ **Randomized User-Agents** for WAF evasion
- ✅ **Multi-URL scanning** via file input

## Installation ⚙️

### Requirements
- Python 3.8+
- Required libraries:

```bash
pip install requests beautifulsoup4 argparse
git clone https://github.com/HackfutSec/Joomla.git
cd Joomla

# Single target scan
python joomla.py -u http://example.com

# Scan with custom wordlists
python joomla.py -f urls.txt -l users.txt -p passwords.txt

# Advanced options
python joomla.py -u http://example.com -t 30 -d 0.2

Full Options
Option	Description	Default Value
-u URL	Target URL	-
-f FILE	File containing target URLs	-
-l USERLIST	Custom username wordlist	Built-in
-p PASSLIST	Custom password wordlist	Built-in
