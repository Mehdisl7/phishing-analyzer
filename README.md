# phishing-analyzer

Static phishing email analyzer with an explainable suspicion score.

Give it a `.eml` file and it extracts the technical indicators an SOC analyst
would check by hand, then explains every point of the final score.
## Features

- Header parsing (`From`, `Reply-To`, `Return-Path`, `Subject`, `Date`)
- Received chain reconstruction and IP extraction (public / private)
- Link extraction and misleading-link detection (displayed text vs real destination)
- Raw IP URL detection and urgency vocabulary detection in the subject
- SPF / DKIM / DMARC results read from `Authentication-Results`
- Attachment analysis: SHA256, double extensions, risk-tiered extensions, MIME mismatch
- Explainable score capped at 100 with a risk level (low / medium / high)

## Roadmap

- [x] SPF / DKIM / DMARC checks from `Authentication-Results`
- [x] Attachment analysis (double extensions, MIME mismatch, SHA256)
- [x] Score cap and risk levels
- [x] Unit tests with `pytest`
- [x] More test cases (Reply-To only, no HTML, malformed mail)
- [x] JSON output (`--json`) 
- [x] Enrichment (domain age, VirusTotal lookup by hash)
- [x] Own SPF/DMARC verification via DNS
- [x] Typosquatting detection

## Installation

```bash
git clone https://github.com/Medoche6/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python src/analyzer.py path/to/email.eml
python src/analyzer.py path/to/email.eml --json
python src/analyzer.py path/to/email.eml --vt
python src/analyzer.py path/to/email.eml --dns # with SPF/DMARC DNS lookup
```
## Tests

    pip install -r requirements-dev.txt
    pytest -v

Test emails in `tests/data/` are fictional (reserved documentation
domains and IP ranges).

## Example output

By default, the tool prints a human-readable report: headers, `Received` chain, IPs, links, attac     hments and the explained suspicion score.

python src/analyzer.py path/to/email.eml

```
Liens trouvés :
 - affiché : https://www.banque-securite.example/connexion
 - réel : http://X.X.X.X/verification/login.php [Fake]

Pièces jointes :
  aucune

Score de suspicion : 100/100 (Score élevé)
  +15 : Reply-To (gmail.example) different de From (banque-securite.example)
  +15 : Return-Path (mailer-xk92.example.net) different de From (banque-securite.example)
  +25 : lien trompeur (https://www.banque-securite.example/connexion -> http://X.X.X.X/verification/login.php)
  +20 : lien vers une ip brute (http://X.X.X.X/verification/login.php)
  +10 : email contenant un ou des mot(s) suspect(s)
  +20 : SPF erreur (fail)
  +10 : DKIM absent ou en erreur (none)
  +20 : DMARC en erreur
```
## JSON output

Use `--json` to get machine-readable results, for example to feed another script or a SIEM:

    python src/analyzer.py path/to/email.eml --json

Abridged example:
```json
    
    {
  "headers": {
    "From": "Service Securite Banque <alerte@banque-securite.example>",
    "Reply-To": "support-urgent@gmail.example",
    "Return-Path": "<bounce@mailer-xk92.example.net>",
    "Subject": "URGENT : Votre compte sera suspendu sous 24h",
    "Date": "Thu, 01 Oct 2026 09:58:00 +0200"
  },
  "received": [
    "from mail-xk92.example.net (mail-xk92.example.net [X.X.X.X]) by mx.local with ESMTP id abc123 for <victime@exemple.fr>; Thu, 1 Oct 2026 09:58:12 +0200",
    "from localhost (unknown [X.X.X.X]) by mail-xk92.example.net with SMTP id def456; Thu, 1 Oct 2026 09:58:10 +0200"
  ],
  "ips": {
    "all": [
      "X.X.X.X",
      "X.X.X.X"
    ],
    "origin": "X.X.X.X",
    "private": [
      "X.X.X.X",
      "X.X.X.X"
    ],
    "public": []
  },
  "links": [
    {
      "text": "https://www.banque-securite.example/connexion",
      "href": "http://X.X.X.X/verification/login.php",
      "misleading": true,
      "ip_url": true
    },
    {
      "text": "Verifier mon compte",
      "href": "http://bit.example/x7Yz9",
      "misleading": false,
      "ip_url": false
    }
  ],
  "attachments": [],
  "authentication": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail"
  },
  "score": 100,
  "risk_level": "ÉLEVÉ",
  "reasons": [
    "+15 : Reply-To (gmail.example) different de From (banque-securite.example)",
    "+15 : Return-Path (mailer-xk92.example.net) different de From (banque-securite.example)",
    "+25 : lien trompeur (https://www.banque-securite.example/connexion -> http://X.X.X.X/verification/login.php)",
    "+20 : lien vers une ip brute (http://X.X.X.X/verification/login.php",
    "+10 : email contenant un ou des mot(s) suspect(s)",
    "+20 : SPF erreur (fail)",
    "+10 : DKIM absent ou en erreur (none)",
    "+20 : DMARC en erreur"
  ]
}
```
## VirusTotal enrichment (optional)

The `--vt` option checks the SHA256 hash of each attachment against
[VirusTotal](https://www.virustotal.com). It is optional: without it, the tool
works fully offline.

### What is sent to VirusTotal

Only the **SHA256 hash** of each attachment is sent, never the file itself.
Email content, headers and links are not sent either.

### Setup

VirusTotal requires an API key. The key is **not included** in this project:
each user must use their own free key.

1. Create a free account at [virustotal.com](https://www.virustotal.com).
2. Open your profile and copy your **API key**.
3. Load the key in your terminal (the input is hidden and not saved in
   your shell history):

       read -s VT_API_KEY && export VT_API_KEY

   Paste the key, then press Enter.

4. Check that it is loaded (a VirusTotal key has 64 characters):

       echo ${#VT_API_KEY}

The variable only exists in the terminal where you set it. Repeat step 3 in
each new terminal.

### Usage

python src/analyzer.py path/to/email.eml --vt # with VirusTotal lookup

Combine it with JSON output if needed:

python src/analyzer.py path/to/email.eml --vt --json

### Possible results

| Status     | Meaning                                                        | Score impact |
|------------|----------------------------------------------------------------|--------------|
| `detected` | At least one engine flags the file as malicious or suspicious  | +40          |
| `clean`    | Known file, no detection                                       | none         |
| `unknown`  | Hash never seen by VirusTotal (this does **not** mean "safe")  | none         |
| `error`    | Network problem, invalid key or quota exceeded                 | none         |

### Without an API key

If `VT_API_KEY` is not set, the tool prints a warning and runs the local
analysis only:

    VT_API_KEY absente : enrichissement VirusTotal ignoré.

### Limits

- The free VirusTotal API allows about **4 requests per minute** and is meant
  for non-commercial use. The tool waits 15 seconds between two attachments to
  respect this quota.
- A network connection is required for this option.
- An `unknown` result does not prove that a file is harmless: targeted or
  very recent malware may not be known yet.

### Security notes

- **Never commit your API key.** Do not write it in the code, in a README or
  in a file inside the repository.
- If you think your key was exposed, regenerate it from your VirusTotal
  profile page.
- You can test your setup safely with the EICAR test file hash, which
  antivirus engines flag on purpose: 
    
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

## DNS policy lookup (optional)

`--dns` reads the SPF and DMARC records published by the `From` domain. It requires network access.

python src/analyzer.py path/to/email.eml --dns

It can be combined with the other options:

python src/analyzer.py path/to/email.eml --vt --dns --json

| Finding | Score impact |
|---------|--------------|
| No SPF record | +10 |
| Permissive SPF (`+all` / `?all`) | +10 |
| No DMARC record | +10 |
| DMARC `p=none` (monitoring only) | +5 |

This measures how well the domain is protected against spoofing. It does **not** check whether the sending IP is authorized by SPF (full SPF evaluation is a future improvement). If the DNSquery fails, the tool prints a warning and adds no points. Note that the lookup sends DNS queries about the sender's domain.

## Typosquatting detection

The tool checks whether the domain of the `From` and `Reply-To` addresses imitates a well-known brand (for example `paypa1.com` instead of `paypal.com`). This check is **offline**: it needs no network access and no option.

Such emails can pass SPF, DKIM and DMARC, because the attacker configures his own look-alike domain correctly. That is why this rule complements the authentication checks.

### How it works

1. The domain name is isolated (`mail.paypa1.com` gives `paypa1`).
2. If it is exactly a known brand, it is **not** flagged (`paypal.com` is the real site).
3. Look-alike characters are normalized (`0`→`o`, `1`→`l`, `3`→`e`, `5`→`s`, `rn`→`m`, `vv`→`w`) and accents are removed.
4. The result is compared with the brand lists.

### Detected techniques

| Technique | Example | Score impact |
|-----------|---------|--------------|
| Look-alike characters | `paypa1.com`, `arnazon.com` | +30 |
| Typo (edit distance of 1) | `gooogle.com` | +25 |
| Brand + another word | `paypal-secure.com` | +20 |

The score is added once per address (`From` and `Reply-To` are checked separately).

### Brand lists

- `BRANDS`: distinctive brand names. All three techniques apply.
- `SHORT_BRANDS`: short or common names (`orange`, `free`, `visa`, `target`...). Only the look-alike character rule applies, to avoid false positives such as `orange-vif.fr` or `free-games.fr`.

To add a brand, put its name in lowercase, without extension, accents or hyphens (for example `"societegenerale"`). Use `SHORT_BRANDS` for short or common words. A test checks that the two lists never overlap.

### Limitations

- The brand list is built in and static: an imitated brand that is not in the list is not detected.
- Only the name before the extension is compared: `paypal.xyz` and misleading subdomains such as `paypal.com.evil.example` are not flagged.
- Non-Latin look-alike letters (for example a Cyrillic "а") are only caught indirectly, through the edit distance.
- A legitimate domain close to a brand name can be flagged by mistake, so the weights are kept moderate.

##scoring
| Sender domain imitating a brand (look-alike: 30, typo: 25, brand + word: 20) | +20 to +30 |


## Safety

The analysis is static only: links are never visited and attachments are
never opened or executed. Do not commit real emails or malware samples;
the `samples/` folder is git-ignored.

## Limitations

The score is a decision aid, not a verdict. A legitimate email can fail some
checks (forwarding, misconfiguration), and a malicious one can pass them
(compromised account). `Received` headers other than the one added by your
own server can be forged.

## Liscence

MIT
