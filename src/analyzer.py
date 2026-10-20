import sys
import os
import hashlib
from pathlib import Path
import mimetypes
from email import policy
from email.parser import BytesParser
import re
import ipaddress
from urllib.parse import urlparse
import urllib.request
import urllib.error
from bs4 import BeautifulSoup
import json
import argparse
import time
import dns.resolver
import dns.exception
import unicodedata


URGENCY_WORDS = ("urgent", "suspendu", "immédiat", "24h", "verify", "action required", "urgent", "urgently", "immediately", "immediate", "suspended", "suspension", "deactivated", "disabled", "locked", "expired", "expiration", "terminate", "termination", "verify", "verification", "validate", "validation", "confirm", "confirmation", "unauthorized", "unusual", "suspicious", "security alert", "security warning", "fraud", "fraudulent", "compromised", "breach", "threat", "warning", "account", "password", "credential", "credentials", "login", "signin", "sign-in", "sign in", "username", "authentication", "authenticate", "access", "payment", "billing", "invoice", "transaction", "refund", "purchase", "order", "bank", "banking", "credit", "debit", "card", "wallet", "money", "transfer", "security", "identity", "personal", "information", "private", "document", "attachment", "notification", "alert", "request", "action", "required", "mandatory", "update", "renew", "renewal", "recover", "restore", "unlock", "click", "link")

HIGH_RISK_EXT = [".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".msi", ".msp", ".msix", ".msixbundle", ".appx", ".appxbundle", ".hta", ".cpl", ".lnk", ".scf", ".reg", ".jar", ".apk", ".ipa", ".dmg", ".pkg"]

MEDIUM_RISK_EXT = [".dll", ".ocx", ".sys", ".drv", ".psm1", ".psd1", ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf", ".bin", ".elf", ".run", ".command", ".desktop", ".application", ".gadget"]

LOW_RISK_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".txt", ".csv", ".rtf", ".odt", ".ods", ".odp", ".py", ".pyw", ".pyc", ".pyo", ".sh", ".bash", ".zsh", ".ksh", ".fish", ".pl", ".pm", ".php", ".asp", ".aspx", ".jsp", ".cgi", ".class", ".c", ".h", ".cpp", ".hpp"]

def parse_eml(path):
    with open (path, "rb") as file:
        return BytesParser(policy=policy.default).parse(file)

IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

def extract_received_ips(msg):

    ips=[]
    for hop in msg.get_all("Received", []):
        for match in IP_RE.findall(hop):
            try:
                ips.append(str(ipaddress.ip_address(match)))
            except ValueError:
                continue
    return ips

def origin_ip(msg):
    ips = extract_received_ips(msg)
    return ips[-1] if ips else None

def classify_ips(msg): #on separe les ips privees et publics
    private_ips = []
    public_ips = []
    for ip in extract_received_ips(msg):
        if ipaddress.ip_address(ip).is_private:
            private_ips.append(ip)
        else:
            public_ips.append(ip)
    return private_ips, public_ips

def get_html_body(msg):
    part = msg.get_body(preferencelist=("html",))
    return part.get_content() if part else ""

def extract_links(html):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for x in soup.find_all("a", href=True):
        links.append({"text": x.get_text(strip=True), "href": x["href"]})
    return links 

def is_misleading(link):
    text = link["text"]
    if not text.startswith(("http://", "https://", "www.")):
        return False
    shown = urlparse(text if "//" in text else "//" + text).hostname
    real = urlparse(link["href"]).hostname
    return shown != real

def domain_of(adress):
    match = re.search(r"@([\w.-]+)", adress or "")
    return match.group(1).lower() if match else None

def is_ip(href):
    host = urlparse(href).hostname
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

AUTHENTICATION = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)

def authentication_results(msg):
    results = {}
    for header in msg.get_all("Authentication-Results", []):
        for mech, verdict in AUTHENTICATION.findall(str(header)):
            results.setdefault(mech.lower(), verdict.lower())
    return results

def attachment(msg):
    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append({
            "name" : part.get_filename() or "(without name)",
            "sha256" : hashlib.sha256(data).hexdigest(),
            "mime" : part.get_content_type(),
            "size" : len(data),
        })
    return attachments

def get_ext(name):
    return os.path.splitext(name.lower())[1]

def double_extension(name):
    parts = name.lower().split(".")
    if len(parts) < 3:
        return False
    last, previous = "." + parts[-1], "." + parts[-2]
    return (last in HIGH_RISK_EXT or last in MEDIUM_RISK_EXT) and previous in LOW_RISK_EXT

def same_ext(att):
    guessed, _ = mimetypes.guess_type(att["name"])
    return guessed is not None and guessed != att["mime"]

#gerer le typosquatting, par exemple si quelqu'un se fait passer pour microsoft en ecrivant rnicrosoft au lieu de micro...

#marques souvent imitées :

BRANDS = ("paypal", "microsoft", "amazon", "google", "apple", "netflix",
          "facebook", "linkedin", "instagram", "whatsapp", "outlook",
          "dropbox", "docusign", "laposte", "ameli")

SHORT_BRANDS = (
    "bnp", "lcl", "cic", "wise", "n26", "visa", "ups", "dhl", "dpd", "gls",
    "ibm", "amd", "hp", "dell", "asus", "sony", "box", "mega", "caf", "ants",
    "axa", "edx", "mgen", "maif", "macif", "sfr", "ovh", "ebay", "etsy",
    "zoom", "slack", "uber", "bolt", "free", "teams", "target", "signal",
    "notion", "hotels", "booking","orange", "temu", "fnac", "shein",
    "lidl", "jira", "sosh", "xbox", "intel",
)

CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"})


def levenshtein(a, b):
    #Nombre minimal de modifications (ajout, retrait, changement) entre a et b
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize_label(label):
    #Ramène un nom à sa forme 'lisible' : accents retirés, 0->o, 1->l, rn->m
    label = unicodedata.normalize("NFKD", label.lower()).encode("ascii", "ignore").decode()
    return label.translate(CONFUSABLES).replace("rn", "m").replace("vv", "w")


def typosquat_check(domain):
    #Renvoie (marque, type, points) si le domaine imite une marque, sinon None

    parts = domain.lower().split(".")
    if len(parts) < 2:
        return None
    label = parts[-2]  # 'paypa1' pour 'mail.paypa1.com'
    if label in BRANDS or label in SHORT_BRANDS:
        return None
    normalized = normalize_label(label)

    for brand in SHORT_BRANDS:
        if normalized == brand:
            return brand, "caractères trompeurs", 30

    for brand in BRANDS:
        if label == brand:
            return None  # le vrai nom de la marque
        if normalized == brand:
            return brand, "caractères trompeurs", 30
        # la distance est utilisee que pour les noms assez longs (évitez les faux positifs)
        if len(brand) >= 6 and levenshtein(normalized, brand) == 1:
            return brand, "faute de frappe", 25
        if brand in label.split("-"):
            return brand, "marque accolée à un autre mot", 20
    return None

def compute_score(msg):

    score = 0
    reasons = []
    fromd = domain_of(msg.get("From"))
    replyd = domain_of(msg.get("Reply-To"))
    returnd = domain_of(msg.get("Return-Path"))
    if replyd and fromd and replyd != fromd:
        score += 15
        reasons.append(f"+15 : Reply-To ({replyd}) different de From ({fromd})")
    if returnd and fromd and returnd != fromd:
        score += 15
        reasons.append(f"+15 : Return-Path ({returnd}) different de From ({fromd})")

    for field, dom in (("From", fromd), ("Reply-To", replyd)):
        hit = typosquat_check(dom) if dom else None
        if hit:
            brand, kind, points = hit
            score += points
            reasons.append(f"+{points} : domaine {field} imitant {brand} ({kind}) : {dom}")

    for link in extract_links(get_html_body(msg)):
        if is_misleading(link):
            score += 25
            reasons.append(f"+25 : lien trompeur ({link['text']} -> {link['href']})")
        if is_ip(link["href"]):
            score+=20
            reasons.append(f"+20 : lien vers une ip brute ({link['href']}")
    subject = (msg.get("Subject") or "").lower()
    if any(word in subject for word in URGENCY_WORDS):
        score += 10
        reasons.append("+10 : email contenant un ou des mot(s) suspect(s)")

    auth = authentication_results(msg)
    if auth.get("spf") in ("fail", "softfail"):
        score+=20
        reasons.append(f"+20 : SPF erreur ({auth['spf']})")
    if auth.get("dkim") in ("fail", "none"):
        score += 10
        reasons.append(f"+10 : DKIM absent ou en erreur ({auth['dkim']})")
    if auth.get("dmarc") == "fail":
        score += 20
        reasons.append("+20 : DMARC en erreur")
    for att in attachment(msg):
        ext = get_ext(att["name"])
        if double_extension(att["name"]):
            score += 30
            reasons.append(f"+30 : double extension ({att['name']})")
        elif ext in HIGH_RISK_EXT:
            score += 25
            reasons.append(f"+25 : extension à haut risque ({att['name']})")
        elif ext in MEDIUM_RISK_EXT:
            score += 10
            reasons.append(f"+10 : extension à risque moyen ({att['name']})")

        if same_ext(att):
            score += 15
            reasons.append(f"+15 : type MIME incohérent ({att['name']} déclaré {att['mime']})")
    score = min(score, 100) 
    return score, reasons

def risk_level(score):
    if score >= 70:
        return "ÉLEVÉ"
    if score >= 40:
        return "MOYEN"
    return "FAIBLE"

RISK_MESSAGES = {
    "ÉLEVÉ": "Score élevé, mail suspect",
    "MOYEN": "Score moyen, faites attention",
    "FAIBLE": "Score faible, peu d'indices suspects",
}

def analyze(msg):
    private_ips, public_ips = classify_ips(msg)
    score, reasons = compute_score(msg)
    return {
        "headers" : {h: msg.get(h) for h in ("From", "Reply-To", "Return-Path", "Subject", "Date")},
        "received" : [" ".join(hop.split()) for hop in msg.get_all("Received", [])],
        "ips": {
            "all": extract_received_ips(msg),
            "origin": origin_ip(msg),
            "private": private_ips,
            "public": public_ips,
        },
        "links": [
            {**link, "misleading": is_misleading(link), "ip_url": is_ip(link["href"])}
            for link in extract_links(get_html_body(msg))
        ],
        "attachments": attachment(msg),
        "authentication": authentication_results(msg),
        "score": score,
        "risk_level": risk_level(score),
        "reasons": reasons,
    }

VT_URL = "https://www.virustotal.com/api/v3/files/"
VT_DELAY = 15 #delaie en secondes pour la version gratuite, 4 lookups / min 

def vt_lookup(sha256, api_key, timeout=10):
    #on prendra que les hash car il ne faut pas upload les fichiers critiques dans virustotal directement car les abonnées de virustotal y ont accès, on donnera a virustotal seulement le hash de fichier. 
    req = urllib.request.Request(VT_URL + sha256, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "unknown"}
        details = {401: "cle api invalide", 429: "quota atteint"} #erreur 429 : "L’erreur HTTP 429 (« Too Many Requests ») signifie que le client (votre navigateur, une application ou un script) a envoyé trop de requêtes au serveur dans un laps de temps imparti."
        return {"status": "error", "detail": details.get(e.code, f"HTTP {e.code}")}

        return {"status": "error", "detail": "reseau inaccessible"}

    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    return {
        "status" : "detected" if malicious + suspicious > 0 else "clean",
        "malicious": malicious,
        "suspicious": suspicious,
        "total": sum(stats.values()),
    }

def apply_virustotal(result):
    #Ajoute le verdict VT à chaque pièce jointe et met à jour le score."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("VT_API_KEY absente : enrichissement VirusTotal ignoré.", file=sys.stderr)
        return result
    if not result["attachments"]:
        print("VirusTotal : aucune pièce jointe à vérifier.", file=sys.stderr)
        return result

    for i, att in enumerate(result["attachments"]):
        if i > 0:
            time.sleep(VT_DELAY)
        att["virustotal"] = vt_lookup(att["sha256"], api_key)
        vt = att["virustotal"]
        if vt["status"] == "detected":
            hits = vt["malicious"] + vt["suspicious"]
            if hits >= 10:
                points = 40
            elif hits >= 3:
                points = 25
            else:
                points = 10
            result["score"] += points
            result["reasons"].append(
                f"+{points} : VirusTotal signale {att['name']} "
                f"({vt['malicious']} malveillant, {vt['suspicious']} suspect "
                f"sur {vt['total']} moteurs)"
            )# on justifie ce choix car elle est rare et se déclenche seulement sur détection. Les faux positifs sont limités par construction : unknown et clean ne rapportent rien., sachant qu'il contient plus de 70 moteurs d'anti virus, les autres restrictions decrivent un comportement suspect, tandis qu'ici on a la confirmation de la présence d'un fichier dangereux.
    result["score"] = min(result["score"], 100)
    result["risk_level"] = risk_level(result["score"])
    return result

def dns_txt(name, timeout=5):#Renvoie la liste des enregistrements TXT, [] si aucun, None si erreur réseau
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return ["".join(s.decode(errors="replace") for s in r.strings) for r in answers]


def check_dns_policy(domain):
    #Lit les politiques SPF et DMARC publiées par un domaine
    info = {"domain": domain, "spf": None, "spf_all": None,
            "dmarc": None, "dmarc_policy": None, "error": False}
    spf_txt = dns_txt(domain)
    dmarc_txt = dns_txt("_dmarc." + domain)
    if spf_txt is None or dmarc_txt is None:
        info["error"] = True
        return info

    for record in spf_txt:
        if record.lower().startswith("v=spf1"):
            info["spf"] = record
            m = re.search(r"\s([+\-~?]?)all\b", record)
            if m:
                info["spf_all"] = (m.group(1) or "+") + "all"

    for record in dmarc_txt:
        if record.lower().startswith("v=dmarc1"):
            info["dmarc"] = record
            m = re.search(r"\bp=(\w+)", record, re.IGNORECASE)
            if m:
                info["dmarc_policy"] = m.group(1).lower()
    return info


def apply_dns(result, msg):
    #Ajoute la politique DNS du domaine du From et met à jour le score
    domain = domain_of(msg.get("From"))
    if not domain:
        return result

    info = check_dns_policy(domain)
    result["dns"] = info
    if info["error"]:
        print("DNS : requête impossible, vérification ignorée.", file=sys.stderr)
        return result

    if info["spf"] is None:
        result["score"] += 10
        result["reasons"].append(f"+10 : aucun enregistrement SPF pour {domain}")
    elif info["spf_all"] in ("+all", "?all"):
        result["score"] += 10
        result["reasons"].append(f"+10 : SPF permissif ({info['spf_all']}) pour {domain}")

    if info["dmarc"] is None:
        result["score"] += 10
        result["reasons"].append(f"+10 : aucun enregistrement DMARC pour {domain}")
    elif info["dmarc_policy"] == "none":
        result["score"] += 5
        result["reasons"].append(f"+5 : DMARC en mode surveillance seulement (p=none) pour {domain}")

    result["score"] = min(result["score"], 100)
    result["risk_level"] = risk_level(result["score"])
    return result




def main():

    parser = argparse.ArgumentParser(description="Analyseur d'e-mails de phishing")
    parser.add_argument("file", help="fichier .eml à analyser")
    parser.add_argument("--json", action="store_true", help="sortie au format JSON")
    parser.add_argument("--vt", action="store_true",
                        help="interroger VirusTotal avec le SHA256 des pièces jointes")
    parser.add_argument("--dns", action="store_true",
                        help="lire les politiques SPF/DMARC du domaine du From")
    args = parser.parse_args()

    msg = parse_eml(args.file)
    result = analyze(msg)
    if args.vt:
        apply_virustotal(result)
    if args.dns:
        apply_dns(result, msg)

    # ces lignes ne s'exécutent que si on utilise --json
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    for header in ("From", "Reply-To", "Return-Path", "Subject", "Date"):
        print(f"{header}: {msg.get(header, '(absent)')}")

    print("\nChemin de transit (received) :")
    for i, hop in enumerate(msg.get_all("Received", []), 1):
        print(f" {i}. {' '.join(hop.split())}")

    print("\nIP trouvees :", extract_received_ips(msg))
    # seul le Received ajouté leserveur est fiable : l'IP d'origine peut être falsifiée par l'attaquant, c'est un indice, pas une preuve
    print("IP d'origine :", origin_ip(msg))
    private_ips, public_ips = classify_ips(msg)
    print("IP privees:", private_ips if private_ips else "aucune")
    print("IP public :", public_ips if public_ips else "aucune")

    links = extract_links(get_html_body(msg))
    if links:
        print("\nLiens trouvés :")
        for link in links:
            flag = " [Fake]" if is_misleading(link) else ""
            print(f" - affiché : {link['text']}")
            print(f" - réel : {link['href']}{flag}")
    else:
        print("\nLiens trouvés : aucun")

    attachments = result["attachments"]
    if attachments:
        print("\nPièces jointes :")
        for att in attachments:
            print(f"  - {att['name']} ({att['mime']}, {att['size']} octets)")
            print(f"    sha256 : {att['sha256']}")
            if "virustotal" in att:
                print(f"    virustotal : {att['virustotal']}")
    else:
        print("\nPièces jointes : aucune")

    if "dns" in result and not result["dns"]["error"]:
        d = result["dns"]
        print(f"\nPolitique DNS de {d['domain']} :")
        print(f"  SPF   : {d['spf'] or 'absent'}")
        print(f"  DMARC : {d['dmarc'] or 'absent'}")

    level = result["risk_level"]
    print(f"\nScore de suspicion : {result['score']}/100 ({RISK_MESSAGES[level]})")
    for reason in result["reasons"]:
        print(f"  {reason}")


if __name__ == "__main__":
    main()
