import argparse
import os
import sys
import unittest
import requests
import json
import time
import csv
from tqdm import tqdm
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def build_dorks(domain):
    patterns = [
        'site:{domain} intitle:"index of"',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:dashboard',
        'site:{domain} ext:log',
        'site:{domain} ext:sql',
        'site:{domain} ext:conf',
        'site:{domain} ext:ini',
        'site:{domain} ext:db',
        'site:{domain} ext:bkf',
        'site:{domain} ext:bak',
        'site:{domain} ext:old',
        'site:{domain} ext:backup',
        'site:{domain} inurl:.htaccess | inurl:.env | inurl:.git',
        'site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http',
        'site:{domain} inurl:"redirect?url=" | inurl:"returnUrl=" | inurl:"next="',
        'site:{domain} inurl:"out.php?url="',
        'site:{domain} intitle:"index of /"',
        'site:{domain} intitle:"index of" passwd | admin | uploads | confidential',
        'site:{domain} intitle:"index of" (pdf | doc | xls | zip | sql)',
        'site:{domain} ext:log | ext:env | ext:conf | ext:bak | ext:old | ext:sql | ext:inc | ext:db',
        'site:{domain} "DB_PASSWORD" | "MYSQL_PASSWORD" | "admin" | "root"',
        'site:{domain} ext:xml inurl:web.config',
        'site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:csv',
        'site:{domain} filetype:xls intext:@{domain}',
        'site:{domain} filetype:pdf intext:"confidential"',
        'site:{domain} filetype:csv intext:"password"',
        'site:{domain} inurl:admin | inurl:login | inurl:dashboard | inurl:user',
        'site:{domain} intitle:"Admin Login" | intitle:"Sign in"',
        'site:{domain} inurl:cpanel | inurl:webmail | inurl:wp-admin',
        'site:{domain} intext:"Warning: include" | intext:"Warning: require" | intext:"Fatal error"',
        'site:{domain} "unexpected T_STRING" | "at line" | "in function"',
        'site:{domain} intext:"Stack trace" | "NullPointerException"',
        'site:{domain} inurl:.git | inurl:.svn | inurl:.DS_Store',
        'site:{domain} inurl:backup | inurl:bak | inurl:zip | inurl:tar | inurl:old',
        'site:{domain} inurl:api | inurl:auth | inurl:token | inurl:jwt',
        'site:{domain} inurl:"api/login" | inurl:"api/authenticate"',
        'site:{domain} inurl:contact | inurl:form | inurl:feedback',
        'site:{domain} intitle:"Contact Us" | intitle:"Feedback"',
        'site:{domain} inurl="redirect=" intext=http',
        'site:{domain} inurl="next=" intext=http',
        'site:{domain} inurl="url=" intext=http',
        'site:{domain} inurl:phpinfo.php | inurl:test.php | inurl:debug',
        'site:{domain} "powered by wordpress" | "powered by drupal" | "powered by laravel"',
        'site:*.{domain}',
        'site:*.*.{domain}',
        'site:pastebin.com "{domain}"',
        'site:{domain} mime:swf',
        'inurl:{domain} ext:swf',
        'site:{domain} inurl:api',
        'site:{domain} inurl:debug',
        'site:{domain} inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:next',
        'site:{domain} inurl:struts | inurl:action',
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:xls OR filetype:xlsx',
        'site:{domain} filetype:doc OR filetype:docx',
        'site:{domain} filetype:ppt OR filetype:pptx',
        'site:{domain} filetype:txt',
        'site:{domain} inurl:wp-content | inurl:wp-includes',
        'site:{domain} inurl:wp-admin',
        'site:{domain} inurl:wp-login.php',
        'site:{domain} inurl:xmlrpc.php',
        'https://crt.sh/?q=%25.{domain}',
        'https://www.openbugbounty.org/search/?search={domain}&type=host',
        'https://censys.io/domain?q={domain}',
        'https://censys.io/ipv4?q={domain}',
        'https://censys.io/certificates?q={domain}',
        'https://www.shodan.io/search?query={domain}',
        'https://archive.org/wayback/available?url={domain}',
        'https://github.com/search?q="*.{domain}"&type=host',

        
    ]
    return [p.format(domain=domain) for p in patterns]

def serpapi_search(query, api_key, num_results=10, retries=3, delay=2):
    url = 'https://serpapi.com/search.json'
    params = {
        'engine': 'google',
        'q': query,
        'num': num_results,
        'api_key': api_key
    }
    for attempt in range(retries):
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            return [r.get('link') for r in data.get('organic_results', []) if r.get('link')]
        else:
            logger.warning(f"Attempt {attempt + 1} failed: {response.status_code} - {response.text}")
            time.sleep(delay)
    raise Exception(f"SerpAPI failed after {retries} attempts.")

def run_scans(domain, api_key, num_results=10, output_dir="."):
    dorks = build_dorks(domain)
    results = {}

    for query in tqdm(dorks, desc="Scanning Dorks"):
        logger.info(f"[*] Query: {query}")
        try:
            urls = serpapi_search(query, api_key, num_results)
        except Exception as e:
            logger.error(f"[!] Error fetching results: {e}")
            urls = []
        if urls:
            for idx, url in enumerate(urls, 1):
                logger.info(f" {idx}. {url}")
        else:
            logger.info(" [-] No results")
        results[query] = urls

    # Save results to JSON file
    json_filename = os.path.join(output_dir, f"scan_results_{domain.replace('.', '_')}.json")
    with open(json_filename, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"[+] Results saved to {json_filename}")

    # Save results to CSV file
    csv_filename = os.path.join(output_dir, f"scan_results_{domain.replace('.', '_')}.csv")
    with open(csv_filename, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Dork", "Result URL"])
        for dork, urls in results.items():
            for url in urls:
                writer.writerow([dork, url])
    logger.info(f"[+] CSV output saved to {csv_filename}\n")

    return results

def parse_args():
    parser = argparse.ArgumentParser(description="Google Dork Scanner using SerpAPI")
    parser.add_argument('-d', '--domain', required=True, help="Target domain, e.g., example.com")
    parser.add_argument('-n', '--num', type=int, default=10, help="Number of results per query")
    parser.add_argument('-k', '--apikey', help="SerpAPI key (overrides SERPAPI_KEY env var)")
    parser.add_argument('-o', '--output-dir', default='.', help="Directory to save result files")
    return parser.parse_args()

def main():
    args = parse_args()
    domain = args.domain
    num_results = args.num
    api_key = args.apikey or os.getenv("SERPAPI_KEY")

    if not api_key:
        logger.error("[!] SerpAPI key not provided. Use -k or set SERPAPI_KEY env var.")
        sys.exit(1)

    run_scans(domain, api_key, num_results, args.output_dir)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main()
    else:
        logger.warning("[!] No arguments provided. Use -h for help.")

# Unit Tests
class TestBuildDorks(unittest.TestCase):
    def test_pattern_generation(self):
        domain = "example.com"
        dorks = build_dorks(domain)
        self.assertTrue(any("site:example.com" in d for d in dorks))
        self.assertEqual(len(dorks), 31)

    def test_custom_domain(self):
        domain = "airindia.com"
        dorks = build_dorks(domain)
        self.assertTrue(all(domain in d for d in dorks))
        self.assertEqual(len(dorks), 31)

if __name__ == '__main__':
    unittest.main(exit=False)
