import argparse
import os
import sys
import json
import requests
from datetime import datetime
 
 
def build_dorks(domain):
    patterns = [
 
        # ── Open Redirect ────────────────────────────────────────────────────
        'site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http',
        'site:{domain} inurl:"redirect?url=" | inurl:"returnUrl=" | inurl:"next="',
        'site:{domain} inurl:"out.php?url="',
        'site:{domain} inurl="redirect=" intext=http',
        'site:{domain} inurl="next=" intext=http',
        'site:{domain} inurl="url=" intext=http',
        'site:{domain} inurl:go.php?url= | inurl:goto.php?url=',
        'site:{domain} inurl:forward?url= | inurl:jump?to=',
 
        # ── Directory Listing ────────────────────────────────────────────────
        'site:{domain} intitle:"index of /"',
        'site:{domain} intitle:"index of" passwd | admin | uploads | confidential',
        'site:{domain} intitle:"index of" (pdf | doc | xls | zip | sql)',
        'site:{domain} intitle:"index of" ".env"',
        'site:{domain} intitle:"index of" "config"',
        'site:{domain} intitle:"index of" "backup"',
        'site:{domain} intitle:"index of" ".git"',
        'site:{domain} intitle:"index of" "id_rsa"',
        'site:{domain} intitle:"index of" "private"',
 
        # ── Sensitive File Extensions ─────────────────────────────────────────
        'site:{domain} ext:log | ext:env | ext:conf | ext:bak | ext:old | ext:sql | ext:inc | ext:db',
        'site:{domain} ext:xml inurl:web.config',
        'site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:csv',
        'site:{domain} filetype:xls intext:@{domain}',
        'site:{domain} filetype:pdf intext:"confidential"',
        'site:{domain} filetype:csv intext:"password"',
        'site:{domain} filetype:env "DB_PASSWORD" | "SECRET_KEY" | "API_KEY"',
        'site:{domain} filetype:yml "password" | "secret" | "key"',
        'site:{domain} filetype:yaml "password" | "secret" | "key"',
        'site:{domain} filetype:ini "password" | "user" | "pass"',
        'site:{domain} filetype:txt "password" | "secret" | "credentials"',
        'site:{domain} filetype:cfg password | secret | key',
        'site:{domain} filetype:json "password" | "secret" | "token"',
        'site:{domain} filetype:sh "password" | "secret" | "token"',
        'site:{domain} filetype:xml password | secret',
        'site:{domain} filetype:sql "INSERT INTO" | "CREATE TABLE" | "password"',
        'site:{domain} filetype:backup | filetype:bkp | filetype:bak',
        'site:{domain} filetype:pem | filetype:key | filetype:ppk',
        'site:{domain} filetype:ovpn | filetype:pfx | filetype:p12',
 
        # ── Credentials & Secrets ────────────────────────────────────────────
        'site:{domain} "DB_PASSWORD" | "MYSQL_PASSWORD" | "admin" | "root"',
        'site:{domain} "AWS_SECRET" | "AWS_ACCESS_KEY" | "s3.amazonaws.com"',
        'site:{domain} "api_key" | "api_secret" | "client_secret"',
        'site:{domain} "password=" | "passwd=" | "pwd="',
        'site:{domain} "secret_key" | "secretkey" | "app_secret"',
        'site:{domain} "BEGIN RSA PRIVATE KEY" | "BEGIN PRIVATE KEY" | "BEGIN CERTIFICATE"',
        'site:{domain} "STRIPE_SECRET" | "PAYPAL_SECRET" | "TWILIO_AUTH"',
        'site:{domain} "GITHUB_TOKEN" | "GITLAB_TOKEN" | "BITBUCKET"',
        'site:{domain} "smtp_password" | "mail_password" | "email_password"',
        'site:{domain} intext:"Authorization: Bearer" | intext:"token:"',
 
        # ── Admin & Login Panels ─────────────────────────────────────────────
        'site:{domain} inurl:admin | inurl:login | inurl:dashboard | inurl:user',
        'site:{domain} intitle:"Admin Login" | intitle:"Sign in"',
        'site:{domain} inurl:cpanel | inurl:webmail | inurl:wp-admin',
        'site:{domain} inurl:admin/login | inurl:admin/index | inurl:adminpanel',
        'site:{domain} intitle:"phpMyAdmin" | intitle:"Adminer"',
        'site:{domain} inurl:manager/html | inurl:phpmyadmin | inurl:adminer',
        'site:{domain} intitle:"Control Panel" | intitle:"Admin Panel"',
        'site:{domain} inurl:admincp | inurl:moderator | inurl:superadmin',
        'site:{domain} inurl:portal | inurl:staff | inurl:internal',
 
        # ── Error Messages & Debug Info ───────────────────────────────────────
        'site:{domain} intext:"Warning: include" | intext:"Warning: require" | intext:"Fatal error"',
        'site:{domain} "unexpected T_STRING" | "at line" | "in function"',
        'site:{domain} intext:"Stack trace" | "NullPointerException"',
        'site:{domain} intext:"SQL syntax" | intext:"mysql_fetch" | intext:"ORA-"',
        'site:{domain} intext:"You have an error in your SQL syntax"',
        'site:{domain} intext:"Uncaught exception" | intext:"PHP Parse error"',
        'site:{domain} intext:"SQLSTATE" | intext:"PDOException"',
        'site:{domain} intext:"Internal Server Error" inurl:500',
        'site:{domain} intext:"Debug mode" | intext:"debug=true"',
        'site:{domain} intext:"Traceback (most recent call last)"',
        'site:{domain} intext:"Exception in thread" | intext:"RuntimeException"',
 
        # ── Exposed Git & Version Control ─────────────────────────────────────
        'site:{domain} inurl:.git | inurl:.svn | inurl:.DS_Store',
        'site:{domain} inurl:"/.git/config"',
        'site:{domain} inurl:"/.git/HEAD"',
        'site:{domain} inurl:"/.gitignore"',
        'site:{domain} inurl:"/.svn/entries"',
        'site:{domain} inurl:"/.hg/" | inurl:"/.bzr/"',
 
        # ── Backup & Exposed Files ────────────────────────────────────────────
        'site:{domain} inurl:backup | inurl:bak | inurl:zip | inurl:tar | inurl:old',
        'site:{domain} inurl:dump | inurl:archive | inurl:export',
        'site:{domain} inurl:db.sql | inurl:database.sql | inurl:dump.sql',
        'site:{domain} inurl:wp-content/uploads filetype:sql',
        'site:{domain} inurl:backup.zip | inurl:site.zip | inurl:www.zip',
 
        # ── API & Auth Endpoints ──────────────────────────────────────────────
        'site:{domain} inurl:api | inurl:auth | inurl:token | inurl:jwt',
        'site:{domain} inurl:"api/login" | inurl:"api/authenticate"',
        'site:{domain} inurl:"/api/v1" | inurl:"/api/v2" | inurl:"/api/v3"',
        'site:{domain} inurl:swagger | inurl:api-docs | inurl:openapi',
        'site:{domain} intitle:"Swagger UI" | intitle:"API Documentation"',
        'site:{domain} inurl:graphql | inurl:graphiql | inurl:playground',
        'site:{domain} inurl:oauth | inurl:oauth2 | inurl:sso',
        'site:{domain} inurl:"/rest/api" | inurl:"/api/rest"',
 
        # ── Contact & Forms ───────────────────────────────────────────────────
        'site:{domain} inurl:contact | inurl:form | inurl:feedback',
        'site:{domain} intitle:"Contact Us" | intitle:"Feedback"',
 
        # ── Technology Fingerprinting ─────────────────────────────────────────
        'site:{domain} inurl:phpinfo.php | inurl:test.php | inurl:debug',
        'site:{domain} "powered by wordpress" | "powered by drupal" | "powered by laravel"',
        'site:{domain} "Powered by" inurl:login',
        'site:{domain} intitle:"Welcome to nginx"',
        'site:{domain} intitle:"Apache2 Ubuntu Default Page"',
        'site:{domain} intext:"X-Powered-By: PHP" | intext:"X-Powered-By: ASP.NET"',
        'site:{domain} inurl:wp-content | inurl:wp-includes | inurl:wp-login',
        'site:{domain} inurl:Joomla | inurl:administrator/index.php',
        'site:{domain} inurl:"/sites/default/files"',
 
        # ── Cloud & Storage Exposure ──────────────────────────────────────────
        'site:{domain} inurl:s3.amazonaws.com | inurl:blob.core.windows.net',
        'site:{domain} inurl:storage.googleapis.com',
        'site:{domain} "s3.amazonaws.com" | "cloudfront.net" | "azurewebsites.net"',
 
        # ── Subdomains & Internal ─────────────────────────────────────────────
        'site:*.{domain} -www',
        'site:*.{domain} inurl:internal | inurl:dev | inurl:staging | inurl:test',
        'site:*.{domain} intitle:"under construction" | intitle:"coming soon"',
        'site:dev.{domain} | site:staging.{domain} | site:test.{domain}',
        'site:api.{domain} | site:admin.{domain} | site:portal.{domain}',
        'site:mail.{domain} | site:webmail.{domain} | site:smtp.{domain}',
 
        # ── Email & User Enumeration ──────────────────────────────────────────
        'site:{domain} intext:"@{domain}" filetype:xls | filetype:csv',
        'site:{domain} "@{domain}" "password" | "username"',
        '"@{domain}" intext:"password" | intext:"credentials"',
 
        # ── Exposed Panels & Services ─────────────────────────────────────────
        'site:{domain} intitle:"Kibana" | intitle:"Grafana" | intitle:"Jenkins"',
        'site:{domain} intitle:"Elasticsearch" | intitle:"Solr Admin"',
        'site:{domain} intitle:"Redis" | intitle:"MongoDB"',
        'site:{domain} inurl:jenkins | inurl:bamboo | inurl:teamcity',
        'site:{domain} inurl:jira | inurl:confluence | inurl:bitbucket',
        'site:{domain} intitle:"Jupyter Notebook" | intitle:"JupyterLab"',
        'site:{domain} intitle:"Netdata" | intitle:"Zabbix" | intitle:"Nagios"',
 
        # ── Camera & IoT ──────────────────────────────────────────────────────
        'site:{domain} intitle:"webcam" | intitle:"IP camera" | inurl:ViewerFrame',
        'site:{domain} intitle:"Network Camera" | inurl:axis-cgi',
 
        # ── Login Bypass Hints ────────────────────────────────────────────────
        'site:{domain} intext:"default password" | intext:"default credentials"',
        'site:{domain} intext:"admin:admin" | intext:"admin:password"',
        'site:{domain} inurl:reset_password | inurl:forgot_password | inurl:change_password',
 
        # ── Pastebin & Code Leaks ─────────────────────────────────────────────
        'site:pastebin.com "{domain}"',
        'site:github.com "{domain}" password | secret | key | token',
        'site:gitlab.com "{domain}" password | secret | key',
        'site:trello.com "{domain}"',
 
        # ── Google Cache & Wayback ────────────────────────────────────────────
        'cache:{domain}',
        'info:{domain}',
        'related:{domain}',
        'link:{domain}',
    ]
    return [p.format(domain=domain) for p in patterns]
 
 
def serpapi_search(query, api_key, num_results=10):
    url = 'https://serpapi.com/search.json'
    params = {
        'engine': 'google',
        'q': query,
        'num': num_results,
        'api_key': api_key
    }
    response = requests.get(url, params=params)
    if response.status_code != 200:
        raise Exception(f"SerpAPI error: {response.status_code} - {response.text}")
    data = response.json()
    results = data.get('organic_results', [])
    links = [r.get('link') for r in results if r.get('link')]
    return links
 
 
def run_scans(domain, api_key, num_results=10):
    dorks = build_dorks(domain)
    results = {}
    total_urls = 0
 
    # Category labels for display
    categories = {
        0:  "Open Redirect",
        8:  "Directory Listing",
        17: "Sensitive File Extensions",
        35: "Credentials & Secrets",
        45: "Admin & Login Panels",
        54: "Error Messages & Debug Info",
        65: "Exposed Git & VCS",
        71: "Backup & Exposed Files",
        76: "API & Auth Endpoints",
        84: "Contact & Forms",
        86: "Technology Fingerprinting",
        94: "Cloud & Storage Exposure",
        97: "Subdomains & Internal",
        103:"Email & User Enumeration",
        106:"Exposed Panels & Services",
        115:"Camera & IoT",
        117:"Login Bypass Hints",
        120:"Pastebin & Code Leaks",
        123:"Google Cache & Info",
    }
 
    current_category = ""
 
    for idx, query in enumerate(dorks):
        # Print category header if new section
        if idx in categories:
            current_category = categories[idx]
            print(f"\n{'='*60}")
            print(f"  [{current_category}]")
            print(f"{'='*60}")
 
        print(f"\n[*] Query: {query}")
        try:
            urls = serpapi_search(query, api_key, num_results)
        except Exception as e:
            print(f"[!] Error: {e}")
            urls = []
 
        if urls:
            total_urls += len(urls)
            for i, url in enumerate(urls, 1):
                print(f"  {i}. {url}")
        else:
            print("  [-] No results")
 
        results[query] = urls
 
    # Save JSON output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"scan_{domain.replace('.', '_')}_{timestamp}.json"
    with open(output_filename, "w") as f:
        json.dump({
            "domain": domain,
            "timestamp": timestamp,
            "total_dorks": len(dorks),
            "total_results": total_urls,
            "results": results
        }, f, indent=2)
 
    print(f"\n{'='*60}")
    print(f"[+] Scan complete!")
    print(f"[+] Total dorks run  : {len(dorks)}")
    print(f"[+] Total URLs found : {total_urls}")
    print(f"[+] Results saved to : {output_filename}")
    print(f"{'='*60}\n")
 
    return results
 
 
def parse_args():
    parser = argparse.ArgumentParser(
        description="Google Dork Scanner using SerpAPI",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-d', '--domain',   required=True,      help="Target domain e.g. example.com")
    parser.add_argument('-n', '--num',      type=int, default=10,help="Number of results per query (default: 10)")
    parser.add_argument('-k', '--apikey',                        help="SerpAPI key (or set SERPAPI_KEY env var)")
    return parser.parse_args()
 
 
def main():
    args = parse_args()
    domain = args.domain
    num_results = args.num
    api_key = args.apikey or os.getenv("SERPAPI_KEY")
 
    if not api_key:
        print("[!] SerpAPI key not provided. Use -k or set SERPAPI_KEY env var.")
        sys.exit(1)
 
    print(f"\n[*] Target  : {domain}")
    print(f"[*] Dorks   : {len(build_dorks(domain))}")
    print(f"[*] Results per query: {num_results}\n")
 
    run_scans(domain, api_key, num_results)
 
 
if __name__ == '__main__':
    if len(sys.argv) > 1:
        main()
    else:
        print("[!] No arguments provided. Use -h for help.")
 
