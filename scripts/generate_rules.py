#!/usr/bin/env python3
"""Emit an apply_patch payload for the checked-in, explicit detection catalog."""
import json
import sys

families = {
    "sqli": [
        r"union\s+(?:all\s+)?select", r"(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", r"(?:or|and)\s+['\"]?[a-z]+['\"]?\s*=\s*['\"]?[a-z]+", r"information_schema\.", r"(?:sleep|benchmark)\s*\(", r"waitfor\s+delay", r"pg_sleep\s*\(", r"dbms_pipe\.receive_message", r"extractvalue\s*\(", r"updatexml\s*\(", r"(?:load_file|into\s+outfile)\b", r"(?:xp_cmdshell|sp_executesql)\b", r"(?:select|insert|update|delete)\s+.+(?:--|#|/\*)", r"(?:select|union)\s+.*\bfrom\b", r"(?:drop|truncate|alter)\s+table\b", r"(?:cast|convert)\s*\(.+\bas\b", r"(?:hex|char|unhex)\s*\(", r"(?:sysobjects|syscolumns|pg_catalog)\b", r"(?:sqlite_master|sqlite_schema)\b", r"(?:having\s+\d+\s*=|group\s+by\s+\d+)\b", r"(?:order\s+by\s+\d{2,})\b", r"(?:@@version|version\s*\(\s*\))", r"(?:user|database|current_user)\s*\(\s*\)", r"(?:procedure\s+analyse|into\s+dumpfile)\b", r"(?:0x[0-9a-f]{8,}\s*=|\bconcat_ws\s*\()"],
    "xss": [
        r"<script\b", r"</script\s*>", r"\bonerror\s*=", r"\bonload\s*=", r"javascript\s*:", r"<svg\b[^>]*\bonload", r"<img\b[^>]*\bonerror", r"<iframe\b", r"<object\b", r"<embed\b", r"<math\b[^>]*\bhref", r"<body\b[^>]*\bonload", r"<details\b[^>]*\bontoggle", r"\bonmouseover\s*=", r"\bonfocus\s*=", r"\bautofocus\b[^>]*\bonfocus", r"\bsrcdoc\s*=", r"data\s*:\s*text/html", r"(?:alert|prompt|confirm)\s*\(", r"document\s*\.\s*(?:cookie|location|write)"],
    "rce": [
        r"(?:;|\|\||&&)\s*(?:id|whoami|uname|cat|curl|wget)\b", r"\$\([^)]*(?:id|whoami|cat)\b", r"`[^`]*(?:id|whoami|cat)\b", r"(?:/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?)\b", r"(?:system|exec|passthru|shell_exec)\s*\(", r"(?:eval|assert)\s*\([^)]*(?:base64|request|post)", r"(?:Runtime\.getRuntime|ProcessBuilder)\b", r"(?:__import__|subprocess\.Popen|os\.system)\s*\(", r"(?:pickle\.loads|yaml\.unsafe_load)\s*\(", r"(?:ObjectInputStream|readObject\s*\()", r"(?:/dev/tcp/|nc\s+-e\s+)", r"(?:base64\s+-d\s*\||base64_decode\s*\()", r"(?:\$\{jndi:|\$\{lower:)\b?", r"(?:php://input|expect://)\b?", r"(?:chmod\s+\+x|curl\s+[^;|]+\|\s*(?:sh|bash))"],
    "lfi": [
        r"(?:\.\./){2,}", r"(?:%2e%2e%2f){2,}", r"(?:%252e%252e%252f){2,}", r"(?:\.\.\\){2,}", r"(?:%2e%2e%5c){2,}", r"(?:/etc/passwd|/etc/shadow)\b", r"(?:/proc/self/(?:environ|cmdline|fd/))", r"(?:php://filter|file://|zip://|phar://)", r"(?:boot\.ini|win\.ini|system32\\drivers)", r"(?:%00|%2500).*(?:\.php|\.jsp)"],
    "ssrf": [
        r"(?:169\.254\.169\.254|metadata\.google\.internal)", r"(?:localhost|127\.0\.0\.1|\[::1\])[:/]", r"(?:0x7f000001|2130706433|017700000001)", r"(?:file|gopher|dict|ftp)://", r"(?:metadata/identity/oauth2/token|latest/meta-data/)", r"(?:100\.100\.100\.200|169\.254\.170\.2)", r"(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", r"(?:192\.168\.[0-9]{1,3}\.[0-9]{1,3})", r"(?:172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})", r"(?:http://\[?::ffff:127\.0\.0\.1)"],
    "xxe": [
        r"<!DOCTYPE\s+[^>]*\[", r"<!ENTITY\s+\w+\s+SYSTEM", r"<!ENTITY\s+%\s+\w+", r"\bSYSTEM\s+['\"](?:file|http|ftp)://", r"\bPUBLIC\s+['\"][^'\"]+['\"]", r"\bxinclude\s*:", r"<xi:include\b", r"<!ENTITY\s+\w+\s+['\"]&", r"(?:php://filter|/etc/passwd).*<!ENTITY", r"<!DOCTYPE\s+[^>]*SYSTEM"],
    "scanner": [
        r"(?:sqlmap|nikto|nmap|masscan)", r"(?:nuclei|acunetix|nessus|openvas)", r"(?:wpscan|dirbuster|gobuster|ffuf)", r"(?:\.git/config|\.git/HEAD)", r"(?:/\.env(?:\.|$)|/\.aws/credentials)", r"(?:/wp-config\.php|/xmlrpc\.php)", r"(?:/phpinfo\.php|/server-status)", r"(?:/actuator/(?:env|health|beans))", r"(?:/cgi-bin/|/vendor/phpunit/)", r"(?:/\.svn/entries|/\.hg/store)", r"(?:/owa/auth/|/autodiscover/)", r"(?:/console/login|/jmx-console/)", r"(?:/swagger-ui|/api-docs)", r"(?:/solr/admin|/manager/html)", r"(?:/debug/pprof|/metrics$)", r"(?:/HNAP1/|/boaform/)", r"(?:/cgi-bin/luci|/shell\?cd\+)", r"(?:/\.well-known/security\.txt\.bak)", r"(?:/adminer\.php|/phpmyadmin/)", r"(?:/wp-json/wp/v2/users)"],
    "bot": [
        r"(?:headlesschrome|phantomjs)", r"(?:python-requests|python-urllib)", r"(?:go-http-client|libwww-perl)", r"(?:curl/|wget/)", r"(?:scrapy|mechanize)", r"(?:selenium|puppeteer|playwright)", r"(?:bytespider|petalbot)", r"(?:ahrefsbot|semrushbot)", r"(?:dotbot|mj12bot)", r"(?:facebookexternalhit|twitterbot)"],
    "custom": [
        r"(?:/admin(?:/|$)|/administrator/)", r"(?:/wp-admin/|/wp-login\.php)", r"(?:/backup\.(?:zip|tar|sql)|/db\.sql)", r"(?:/\.DS_Store|/Thumbs\.db)", r"(?:/config\.(?:json|yml|yaml|php)\.bak)", r"(?:/id_rsa|/\.ssh/)", r"(?:/\.npmrc|/\.pypirc)", r"(?:/web\.config\.bak|/application\.properties)", r"(?:/secrets\.json|/credentials\.json)", r"(?:/admin/login|/api/internal/)"],
}

targets = {"sqli": ["query", "body", "headers", "path"], "xss": ["query", "body", "headers", "path"],
           "rce": ["query", "body", "headers", "path"], "lfi": ["path", "query", "body", "headers", "user_agent"],
           "ssrf": ["query", "body", "headers", "path"], "xxe": ["body", "query", "headers"],
           "scanner": ["path", "user_agent", "headers"], "bot": ["user_agent", "headers", "body", "query"],
           "custom": ["path", "query", "headers", "body"]}
bot_literals = ["headlesschrome", "phantomjs", "python-requests", "curl/", "scrapy", "selenium", "bytespider", "ahrefsbot", "dotbot", "facebookexternalhit"]

print("*** Begin Patch")
for category, signatures in families.items():
    if len(sys.argv) > 1 and category != sys.argv[1]:
        continue
    lines = []
    for signature in signatures:
        for target in targets[category]:
            number = len(lines) + 1
            severity = "critical" if category in ("sqli", "rce", "xxe") else "high" if category in ("xss", "lfi", "ssrf") else "medium" if category in ("scanner", "custom") else "low"
            action = "block" if severity in ("critical", "high") else "log" if category == "bot" else "challenge"
            rule = {"id": f"{category}-{number:03}", "category": category, "severity": severity,
                    "description": f"{category.upper()} signature {number:03} in {target}",
                    ("literal" if category == "bot" else "pattern"): (bot_literals[(number - 1) // 4] if category == "bot" else "(?i)" + signature), "targets": [target], "action": action,
                    "tags": ["owasp-a03"] if category in ("sqli", "xss") else [category]}
            lines.append("- " + "\n  ".join(f"{key}: {json.dumps(value)}" for key, value in rule.items()))
    print(f"*** Add File: internal/rules/categories/{category}.yaml")
    for line in "\n".join(lines).splitlines():
        print("+" + line)
print("*** End Patch")
