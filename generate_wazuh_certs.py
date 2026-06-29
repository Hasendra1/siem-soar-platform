#!/usr/bin/env python3
"""
Generate self-signed TLS certificates for Wazuh stack.
Creates root CA + node certs for indexer, manager, dashboard.
"""
import subprocess, os, sys
from pathlib import Path

CERT_DIR = Path(__file__).parent / "config" / "wazuh_indexer_ssl_certs"
CERT_DIR.mkdir(parents=True, exist_ok=True)

def run(cmd):
    print(f"  > {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERROR: {result.stderr}")
    return result.returncode == 0

def generate():
    os.chdir(str(CERT_DIR))

    # 1. Root CA
    print("\n[1/4] Generating Root CA...")
    run('openssl genrsa -out root-ca-key.pem 2048')
    run('openssl req -new -x509 -sha256 -key root-ca-key.pem -subj "/C=US/ST=CA/O=Wazuh/CN=Wazuh Root CA" -out root-ca.pem -days 3650')

    # 2. Indexer cert
    print("\n[2/4] Generating Indexer certificate...")
    run('openssl genrsa -out wazuh.indexer-key.pem 2048')
    # Create SAN config
    san_conf = CERT_DIR / "indexer_san.cnf"
    san_conf.write_text(
        "[req]\nreq_extensions = v3_req\ndistinguished_name = req_distinguished_name\n"
        "[req_distinguished_name]\n"
        "[v3_req]\nsubjectAltName = DNS:wazuh.indexer,DNS:wazuh-indexer,DNS:localhost,IP:127.0.0.1\n"
    )
    run(f'openssl req -new -key wazuh.indexer-key.pem -subj "/C=US/ST=CA/O=Wazuh/CN=wazuh.indexer" -out wazuh.indexer.csr -config {san_conf}')
    run(f'openssl x509 -req -in wazuh.indexer.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -out wazuh.indexer.pem -days 3650 -sha256 -extensions v3_req -extfile {san_conf}')

    # 3. Manager cert
    print("\n[3/4] Generating Manager certificate...")
    run('openssl genrsa -out wazuh.manager-key.pem 2048')
    san_mgr = CERT_DIR / "manager_san.cnf"
    san_mgr.write_text(
        "[req]\nreq_extensions = v3_req\ndistinguished_name = req_distinguished_name\n"
        "[req_distinguished_name]\n"
        "[v3_req]\nsubjectAltName = DNS:wazuh.manager,DNS:wazuh-manager,DNS:localhost,IP:127.0.0.1\n"
    )
    run(f'openssl req -new -key wazuh.manager-key.pem -subj "/C=US/ST=CA/O=Wazuh/CN=wazuh.manager" -out wazuh.manager.csr -config {san_mgr}')
    run(f'openssl x509 -req -in wazuh.manager.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -out wazuh.manager.pem -days 3650 -sha256 -extensions v3_req -extfile {san_mgr}')

    # 4. Dashboard cert
    print("\n[4/4] Generating Dashboard certificate...")
    run('openssl genrsa -out wazuh.dashboard-key.pem 2048')
    san_dash = CERT_DIR / "dashboard_san.cnf"
    san_dash.write_text(
        "[req]\nreq_extensions = v3_req\ndistinguished_name = req_distinguished_name\n"
        "[req_distinguished_name]\n"
        "[v3_req]\nsubjectAltName = DNS:wazuh.dashboard,DNS:wazuh-dashboard,DNS:localhost,IP:127.0.0.1\n"
    )
    run(f'openssl req -new -key wazuh.dashboard-key.pem -subj "/C=US/ST=CA/O=Wazuh/CN=wazuh.dashboard" -out wazuh.dashboard.csr -config {san_dash}')
    run(f'openssl x509 -req -in wazuh.dashboard.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -out wazuh.dashboard.pem -days 3650 -sha256 -extensions v3_req -extfile {san_dash}')

    # 5. Admin cert (for securityadmin)
    print("\n[5/5] Generating Admin certificate...")
    run('openssl genrsa -out admin-key.pem 2048')
    run('openssl req -new -key admin-key.pem -subj "/C=US/ST=CA/O=Wazuh/CN=admin" -out admin.csr')
    run('openssl x509 -req -in admin.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -out admin.pem -days 3650 -sha256')

    print(f"\n  All certificates generated in: {CERT_DIR}")
    for f in sorted(CERT_DIR.glob("*.pem")):
        print(f"    {f.name}")

if __name__ == "__main__":
    generate()
