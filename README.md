# Google-Dork-Scanner
A Python CLI tool that automates Google Dorking using SerpAPI to discover publicly accessible endpoints, sensitive files, and misconfigurations on any given domain

Features
Predefined Dork Patterns: 31 common dork queries covering redirects, index listings, sensitive files, login portals, error messages, version control leaks, and more.

API-Powered: Uses SerpAPI for reliable, captcha-free Google searches.

Configurable: Control domain, number of results per query, and API key via CLI flags or environment variable.

Output: Prints to console and saves JSON report (scan_results_<domain>.json).

Unit Tests: Built-in tests for dork pattern generation.


Flag                 Description                                           Required                                        Default
  
-d              Target domain (e.g., example.com)                          Yes                                              -

-n              Number of results per dork query                            -                                               10

-k           SerpAPI key (overrides SERPAPI_KEY environment variable)       not mandatory if have sent through system variables



# Examples
1) Basic scan (using env var key): 
python google_dorking.py -d airindia.com -k SERPAPI_KEY

2) Specify number of results:
python google_dorking.py -d airindia.com -n 20 -k SERPAPI_KEY

3) Provide key on CLI:
python google_dorking.py -d airindia.com -k YOUR_SERPAPI_KEY



Using PowerShell (Windows)

setx SERPAPI_KEY "your_serpapi_key_here"
# Restart PowerShell to apply the change.

2. Using macOS/Linux

Add the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):

export SERPAPI_KEY="your_serpapi_key_here"

Then reload:

source ~/.bashrc  # or ~/.zshrc

3. Manual Override in Code

If you prefer, directly pass your key with -k flag:  --recomended

#where can you find the key 
https://serpapi.com/manage-api-key -- login and copy the api key

