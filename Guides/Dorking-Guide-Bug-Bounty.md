# The Complete Guide to Dorking for Bug Bounty Hunters

**Author:** c0d3Ninja  
**Date:** January 2025  
**Version:** 1.0

---

## Table of Contents

1. [Introduction](#introduction)
2. [Shodan Dorking](#shodan-dorking)
3. [Google Dorking](#google-dorking)
4. [GitHub Dorking](#github-dorking)
5. [Advanced Techniques](#advanced-techniques)
6. [Bug Bounty Use Cases](#bug-bounty-use-cases)
7. [Automation & Tools](#automation--tools)
8. [Best Practices](#best-practices)
9. [References](#references)

---

## Introduction

**Dorking** (also called "Google hacking" or "OSINT dorking") is the practice of using advanced search operators to find sensitive information, exposed services, misconfigurations, and vulnerabilities across the internet. For bug bounty hunters, mastering dorking techniques is essential for:

- **Reconnaissance**: Discovering attack surfaces
- **Asset Discovery**: Finding subdomains, APIs, and endpoints
- **Information Disclosure**: Locating exposed credentials, API keys, and secrets
- **Vulnerability Hunting**: Identifying misconfigured services and exposed databases

This guide covers three critical platforms: **Shodan**, **Google**, and **GitHub**.

---

## Shodan Dorking

Shodan is a search engine for internet-connected devices. It's invaluable for finding exposed services, databases, and misconfigurations.

### Basic Shodan Search Operators

#### Product/Service Detection

```
# Find specific web servers
product:"Apache" country:"US"
product:"nginx" port:443
product:"IIS" os:"Windows"

# Find databases
product:"MySQL" port:3306
product:"MongoDB" port:27017
product:"Redis" port:6379
product:"Elasticsearch" port:9200

# Find specific applications
product:"Jenkins" port:8080
product:"GitLab" port:80
product:"Jira" port:443
```

#### Version-Specific Searches

```
# Find vulnerable versions
product:"Apache" version:"2.4.49"
product:"WordPress" version:"5.0"
product:"Drupal" version:"7.0"

# Exclude patched versions
product:"MongoDB" -version:"4.4.30"
product:"Jenkins" -version:"2.414"
```

#### Authentication & Access

```
# Find services without authentication
product:"MongoDB" "authentication":false
product:"Redis" "authentication":false
product:"Elasticsearch" "authentication":false

# Find default credentials
product:"Jenkins" "Jenkins"
product:"phpMyAdmin" "phpMyAdmin"
```

#### Geographic & Network Filters

```
# Geographic targeting
country:"US" product:"Apache"
city:"New York" product:"nginx"
org:"Amazon" product:"MongoDB"

# IP ranges
net:"192.168.1.0/24"
net:"10.0.0.0/8"
```

#### HTTP Headers & Responses

```
# Find specific headers
http.title:"Login"
http.title:"Admin"
http.status:200 http.title:"Dashboard"

# Find exposed directories
http.html:"Index of /"
http.html:"directory listing"
http.html:"parent directory"

# Find specific content
http.html:"phpinfo()"
http.html:"database"
http.html:"password"
```

### Advanced Shodan Queries

#### Finding Exposed APIs

```
# REST APIs
http.title:"Swagger"
http.title:"API Documentation"
http.html:"/api/v1"

# GraphQL endpoints
http.html:"graphql"
http.title:"GraphQL"

# Webhooks
http.html:"webhook"
http.html:"callback"
```

#### Finding Exposed Admin Panels

```
# Common admin panels
http.title:"Admin Panel"
http.title:"Administration"
http.html:"/admin"
http.html:"/wp-admin"
http.html:"/administrator"
```

#### Finding Exposed Files

```
# Configuration files
http.html:".env"
http.html:"config.php"
http.html:"settings.py"

# Backup files
http.html:".bak"
http.html:".sql"
http.html:".tar.gz"
```

#### Finding Specific Vulnerabilities

```
# Exposed databases
product:"MongoDB" port:27017 "authentication":false
product:"Redis" port:6379 "authentication":false
product:"Elasticsearch" port:9200 "authentication":false

# Exposed Docker
product:"Docker" port:2375
product:"Docker" port:2376

# Exposed Kubernetes
product:"Kubernetes" port:6443
```

### Shodan Filters Reference

| Filter | Description | Example |
|--------|-------------|---------|
| `product:` | Product name | `product:"Apache"` |
| `version:` | Version number | `version:"2.4.49"` |
| `port:` | Port number | `port:443` |
| `country:` | Country code | `country:"US"` |
| `city:` | City name | `city:"New York"` |
| `org:` | Organization | `org:"Amazon"` |
| `net:` | IP/CIDR | `net:"192.168.1.0/24"` |
| `os:` | Operating system | `os:"Linux"` |
| `http.title:` | HTTP title | `http.title:"Login"` |
| `http.html:` | HTTP body content | `http.html:"password"` |
| `http.status:` | HTTP status code | `http.status:200` |
| `ssl.cert:` | SSL certificate | `ssl.cert:"example.com"` |
| `has_ssl:` | Has SSL | `has_ssl:true` |
| `vuln:` | CVE ID | `vuln:"CVE-2024-4577"` |

---

## Google Dorking

Google dorking uses advanced search operators to find sensitive information indexed by Google.

### Basic Google Search Operators

#### Site-Specific Searches

```
# Search within a specific domain
site:target.com
site:*.target.com
site:target.com filetype:pdf

# Exclude subdomains
site:target.com -site:*.target.com
```

#### File Type Searches

```
# Find specific file types
filetype:pdf site:target.com
filetype:docx site:target.com
filetype:xlsx site:target.com
filetype:sql site:target.com
filetype:env site:target.com
filetype:log site:target.com
```

#### Content-Based Searches

```
# Find specific content
intext:"password" site:target.com
intext:"api_key" site:target.com
intext:"secret" site:target.com
intext:"token" site:target.com

# Find in URLs
inurl:"admin" site:target.com
inurl:"api" site:target.com
inurl:"config" site:target.com
inurl:"backup" site:target.com
```

#### Directory & Path Searches

```
# Find exposed directories
intitle:"index of" site:target.com
intitle:"directory listing" site:target.com
intitle:"parent directory" site:target.com

# Find specific paths
inurl:"/admin" site:target.com
inurl:"/api/v1" site:target.com
inurl:"/config" site:target.com
inurl:"/.git" site:target.com
```

### Advanced Google Dorks

#### Finding Exposed Credentials

```
# Passwords
intext:"password" filetype:txt site:target.com
intext:"password" filetype:env site:target.com
intext:"password" filetype:log site:target.com

# API Keys
intext:"api_key" site:target.com
intext:"apikey" site:target.com
intext:"api-key" site:target.com
intext:"secret_key" site:target.com

# AWS Keys
intext:"AKIA" site:target.com
intext:"aws_access_key" site:target.com
intext:"aws_secret" site:target.com

# Database credentials
intext:"mysql" intext:"password" site:target.com
intext:"mongodb" intext:"password" site:target.com
intext:"postgres" intext:"password" site:target.com
```

#### Finding Exposed Configuration Files

```
# Environment files
filetype:env site:target.com
intext:".env" site:target.com
filetype:env intext:"password" site:target.com

# Configuration files
filetype:conf site:target.com
filetype:config site:target.com
filetype:ini site:target.com
filetype:yaml site:target.com
filetype:yml site:target.com
```

#### Finding Exposed Backups

```
# Backup files
filetype:bak site:target.com
filetype:sql site:target.com
filetype:dump site:target.com
filetype:tar.gz site:target.com
filetype:zip site:target.com
inurl:"backup" site:target.com
```

#### Finding Exposed Admin Panels

```
# Admin interfaces
intitle:"admin" site:target.com
intitle:"login" site:target.com
intitle:"admin panel" site:target.com
inurl:"/admin" site:target.com
inurl:"/wp-admin" site:target.com
inurl:"/administrator" site:target.com
```

#### Finding Exposed APIs

```
# API endpoints
inurl:"/api" site:target.com
inurl:"/api/v1" site:target.com
inurl:"/api/v2" site:target.com
inurl:"/graphql" site:target.com
inurl:"/swagger" site:target.com
inurl:"/api-docs" site:target.com
```

#### Finding Exposed Git Repositories

```
# Git repositories
inurl:".git" site:target.com
intitle:"index of" ".git" site:target.com
filetype:git site:target.com
```

### Google Dork Operators Reference

| Operator | Description | Example |
|----------|-------------|---------|
| `site:` | Search within domain | `site:target.com` |
| `filetype:` | File extension | `filetype:pdf` |
| `intitle:` | In page title | `intitle:"admin"` |
| `inurl:` | In URL | `inurl:"/api"` |
| `intext:` | In page content | `intext:"password"` |
| `allintext:` | All words in text | `allintext:"api key"` |
| `allinurl:` | All words in URL | `allinurl:"admin login"` |
| `allintitle:` | All words in title | `allintitle:"dashboard admin"` |
| `-` | Exclude term | `site:target.com -site:blog.target.com` |
| `"` | Exact phrase | `"api key"` |
| `*` | Wildcard | `site:*.target.com` |
| `OR` | Logical OR | `site:target.com OR site:target.org` |
| `AND` | Logical AND | `site:target.com AND intext:"api"` |

---

## GitHub Dorking

GitHub dorking searches for exposed secrets, credentials, and sensitive information in public repositories.

### Basic GitHub Search Operators

#### Finding Exposed Secrets

```
# API Keys
"api_key" language:python
"apikey" language:javascript
"api-key" language:javascript
"API_KEY" language:python

# AWS Credentials
"AKIA" language:python
"aws_access_key_id" language:yaml
"aws_secret_access_key" language:env

# Database Credentials
"mysql://" language:env
"mongodb://" language:env
"postgresql://" language:env
"database_password" language:env

# OAuth Tokens
"oauth_token" language:json
"access_token" language:javascript
"refresh_token" language:python
```

#### Finding Configuration Files

```
# Environment files
filename:.env
filename:.env.example
filename:.env.local
filename:.env.production
filename:config.env

# Configuration files
filename:config.yml
filename:config.yaml
filename:settings.py
filename:config.json
filename:application.properties
```

#### Finding Exposed Credentials

```
# Passwords
"password" filename:.env
"password" filename:config.yml
"password" language:python
"PASSWORD" filename:.env

# Private Keys
"-----BEGIN RSA PRIVATE KEY-----"
"-----BEGIN PRIVATE KEY-----"
"-----BEGIN EC PRIVATE KEY-----"
"-----BEGIN DSA PRIVATE KEY-----"

# SSH Keys
"-----BEGIN OPENSSH PRIVATE KEY-----"
"id_rsa" filename:.pem
```

#### Finding Specific Services

```
# Slack Tokens
"xoxb-" language:yaml
"xoxp-" language:env
"slack_token" language:python

# GitHub Tokens
"ghp_" language:python
"gho_" language:javascript
"github_token" language:env

# Stripe Keys
"sk_live" language:python
"pk_live" language:javascript
"stripe_key" language:env

# Firebase
"firebase" filename:.json
"FIREBASE_API_KEY" language:javascript
```

#### Finding Exposed Backups & Databases

```
# SQL Dumps
filename:.sql
"CREATE TABLE" filename:.sql
"INSERT INTO" filename:.sql

# Database Dumps
filename:.dump
filename:.db
filename:.sqlite
```

#### Finding Exposed API Documentation

```
# API Keys in documentation
"api_key" filename:README.md
"API_KEY" filename:docs.md
"apikey" filename:documentation.md
```

### Advanced GitHub Dorks

#### Combining Operators

```
# Find AWS keys in Python files
"AKIA" language:python filename:.py
"aws_secret" language:python -filename:test

# Find database passwords in config files
"password" filename:config.yml language:yaml
"mysql" "password" filename:.env

# Find exposed API keys in JavaScript
"api_key" language:javascript -filename:node_modules
"API_KEY" language:js filename:.js
```

#### Time-Based Searches

```
# Recently committed secrets
"api_key" pushed:>2025-01-01
"password" pushed:>2025-01-01
"secret" pushed:>2025-01-01

# Find secrets in specific date range
"token" pushed:2024-12-01..2024-12-31
```

#### Repository-Specific Searches

```
# Find secrets in specific repos
"api_key" repo:company/project
"password" repo:organization/repository
"secret" user:username
```

### GitHub Search Operators Reference

| Operator | Description | Example |
|----------|-------------|---------|
| `filename:` | Filename | `filename:.env` |
| `language:` | Programming language | `language:python` |
| `path:` | Path in repo | `path:config/.env` |
| `repo:` | Repository | `repo:user/repo` |
| `user:` | User/org | `user:github` |
| `org:` | Organization | `org:company` |
| `size:` | File size | `size:>1000` |
| `extension:` | File extension | `extension:py` |
| `pushed:` | Last push date | `pushed:>2025-01-01` |
| `created:` | Creation date | `created:>2025-01-01` |
| `"` | Exact phrase | `"api_key"` |
| `-` | Exclude | `-filename:test` |

---

## Advanced Techniques

### Combining Multiple Platforms

#### Workflow: Target Reconnaissance

1. **Google Dorking**: Find subdomains and exposed files
   ```
   site:*.target.com
   site:target.com filetype:pdf
   ```

2. **Shodan**: Find exposed services
   ```
   hostname:target.com
   org:"Target Inc"
   ```

3. **GitHub**: Find leaked credentials
   ```
   "target.com" "api_key"
   "target.com" "password"
   ```

### Automation Scripts

#### Python Script for Google Dorking

```python
import requests
from googlesearch import search

def google_dork(query, num_results=10):
    results = []
    for url in search(query, num_results=num_results):
        results.append(url)
    return results

# Example usage
dorks = [
    'site:target.com filetype:env',
    'site:target.com inurl:"/admin"',
    'site:target.com intext:"api_key"'
]

for dork in dorks:
    print(f"\n[*] Searching: {dork}")
    results = google_dork(dork)
    for result in results:
        print(f"  [+] {result}")
```

#### Shodan API Integration

```python
import shodan

API_KEY = "YOUR_SHODAN_API_KEY"
api = shodan.Shodan(API_KEY)

def shodan_search(query):
    try:
        results = api.search(query)
        return results['matches']
    except shodan.APIError as e:
        print(f"Error: {e}")
        return []

# Example usage
queries = [
    'product:"MongoDB" port:27017 "authentication":false',
    'product:"Jenkins" port:8080',
    'http.title:"Admin Panel"'
]

for query in queries:
    print(f"\n[*] Searching: {query}")
    results = shodan_search(query)
    for result in results:
        print(f"  [+] {result['ip_str']}:{result['port']}")
```

#### GitHub API for Secret Hunting

```python
import requests

def github_search(query, token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f"https://api.github.com/search/code?q={query}"
    response = requests.get(url, headers=headers)
    return response.json()

# Example usage
token = "YOUR_GITHUB_TOKEN"
queries = [
    '"api_key" filename:.env',
    '"password" filename:config.yml',
    '"AKIA" language:python'
]

for query in queries:
    print(f"\n[*] Searching: {query}")
    results = github_search(query, token)
    for item in results.get('items', [])[:5]:
        print(f"  [+] {item['html_url']}")
```

---

## Bug Bounty Use Cases

### Use Case 1: Subdomain Enumeration

**Goal**: Find all subdomains of target.com

**Google Dorks**:
```
site:*.target.com
site:target.com -site:www.target.com
```

**Shodan**:
```
hostname:*.target.com
ssl.cert:"*.target.com"
```

**GitHub**:
```
"target.com" filename:CNAME
"*.target.com" filename:nginx.conf
```

### Use Case 2: Finding Exposed Admin Panels

**Goal**: Discover admin interfaces

**Google Dorks**:
```
site:target.com intitle:"admin"
site:target.com inurl:"/admin"
site:target.com intitle:"login"
```

**Shodan**:
```
http.title:"Admin Panel" hostname:target.com
http.html:"/admin" hostname:target.com
```

### Use Case 3: Finding Exposed APIs

**Goal**: Discover API endpoints

**Google Dorks**:
```
site:target.com inurl:"/api"
site:target.com inurl:"/graphql"
site:target.com inurl:"/swagger"
```

**Shodan**:
```
http.title:"Swagger" hostname:target.com
http.html:"/api/v1" hostname:target.com
```

**GitHub**:
```
"target.com/api" filename:README.md
"api.target.com" filename:config.yml
```

### Use Case 4: Finding Exposed Credentials

**Goal**: Discover leaked credentials

**Google Dorks**:
```
site:target.com filetype:env
site:target.com intext:"password" filetype:txt
site:target.com intext:"api_key"
```

**GitHub**:
```
"target.com" "api_key"
"target.com" "password" filename:.env
"target.com" "AKIA"
```

### Use Case 5: Finding Exposed Databases

**Goal**: Find misconfigured databases

**Shodan**:
```
product:"MongoDB" port:27017 "authentication":false
product:"Redis" port:6379 "authentication":false
product:"Elasticsearch" port:9200
```

### Use Case 6: Finding Exposed Backup Files

**Goal**: Discover backup files

**Google Dorks**:
```
site:target.com filetype:sql
site:target.com filetype:bak
site:target.com inurl:"backup"
```

**GitHub**:
```
filename:.sql repo:target/project
filename:.dump repo:target/project
```

---

## Automation & Tools

### Recommended Tools

#### Shodan Tools
- **Shodan CLI**: Official command-line interface
- **Shodan Python API**: Programmatic access
- **Shodanfy**: Shodan search automation

#### Google Dorking Tools
- **GooDork**: Automated Google dorking
- **Google Hacking Database (GHDB)**: Pre-built dorks
- **DorkSearch**: Multi-engine dorking tool

#### GitHub Tools
- **GitHub Dorking Tools**: Automated secret hunting
- **TruffleHog**: Secret scanner for Git repos
- **git-secrets**: Prevents committing secrets

### Building Your Own Dork Database

Create a file with commonly used dorks:

```yaml
# dorks.yaml
google:
  exposed_files:
    - 'site:target.com filetype:env'
    - 'site:target.com filetype:sql'
    - 'site:target.com filetype:bak'
  
  admin_panels:
    - 'site:target.com intitle:"admin"'
    - 'site:target.com inurl:"/admin"'
    - 'site:target.com intitle:"login"'
  
  api_endpoints:
    - 'site:target.com inurl:"/api"'
    - 'site:target.com inurl:"/graphql"'
    - 'site:target.com inurl:"/swagger"'

shodan:
  databases:
    - 'product:"MongoDB" port:27017 "authentication":false'
    - 'product:"Redis" port:6379 "authentication":false'
    - 'product:"Elasticsearch" port:9200'
  
  admin_panels:
    - 'http.title:"Admin Panel"'
    - 'http.html:"/admin"'
    - 'http.title:"Dashboard"'

github:
  secrets:
    - '"api_key" filename:.env'
    - '"password" filename:config.yml'
    - '"AKIA" language:python'
    - '"-----BEGIN RSA PRIVATE KEY-----"'
```

---

## Best Practices

### 1. Stay Within Scope

- **Always check program scope** before testing
- **Respect rate limits** on all platforms
- **Don't test without authorization**

### 2. Document Everything

- **Save all dork queries** that yield results
- **Screenshot findings** for proof
- **Maintain a dork database** for future use

### 3. Be Ethical

- **Report findings responsibly**
- **Don't access unauthorized data**
- **Follow responsible disclosure**

### 4. Automate Wisely

- **Use rate limiting** in automation scripts
- **Respect robots.txt** and ToS
- **Don't overwhelm servers**

### 5. Continuous Learning

- **Stay updated** with new dork techniques
- **Follow security researchers** on Twitter/X
- **Join bug bounty communities**

### 6. Legal Considerations

- **Only test authorized targets**
- **Understand local laws** regarding security testing
- **Get written permission** when possible

---

## References

### Official Documentation

- **Shodan**: https://help.shodan.io/
- **Google Search Operators**: https://support.google.com/websearch/answer/2466433
- **GitHub Search**: https://docs.github.com/en/search-github

### Useful Resources

- **Google Hacking Database (GHDB)**: https://www.exploit-db.com/google-hacking-database
- **Shodan Filters**: https://www.shodan.io/search/filters
- **GitHub Secret Scanning**: https://docs.github.com/en/code-security/secret-scanning

### Tools & Scripts

- **Shodan Python API**: https://github.com/achillean/shodan-python
- **TruffleHog**: https://github.com/trufflesecurity/trufflehog
- **GooDork**: https://github.com/ZephrFish/GooDork

### Learning Resources

- **Bug Bounty Platforms**: HackerOne, Bugcrowd, Intigriti
- **OSINT Communities**: Reddit r/OSINT, Twitter #OSINT
- **Security Blogs**: PortSwigger, HackerOne Blog

---

## Conclusion

Mastering dorking techniques across Shodan, Google, and GitHub is essential for successful bug bounty hunting. These techniques help you:

- **Discover attack surfaces** faster
- **Find exposed assets** and misconfigurations
- **Identify information disclosure** vulnerabilities
- **Build comprehensive target profiles**

Remember: **Always stay within scope, respect rate limits, and follow responsible disclosure practices.**

**Happy Hunting! 🎯**

---

**Author:** c0d3Ninja  
**Website:** https://gotr00t0day.github.io  
**Last Updated:** January 2025

