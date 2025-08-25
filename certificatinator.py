#!/usr/bin/env python3
"""
Certificatinator - A tool to manage SSL certificates in certifi-style bundles.

Usage: certificatinator <url> <cert_file_path>
"""

import argparse
import ssl
import socket
import sys
import warnings
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import re

# Suppress cryptography deprecation warnings for negative serial numbers
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)


def get_certificates_from_url(url):
    """Fetch all certificates from the given URL's SSL chain."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    if not hostname:
        raise ValueError(f"Invalid URL: {url}")
    
    # Create SSL context that captures the full certificate chain
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Connect and get certificate
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Get the peer certificate in DER format
            der_cert_bin = ssock.getpeercert(True)
    
    # For now, we'll just get the server certificate
    # Getting the full chain requires more complex SSL handling
    certificates = []
    cert = x509.load_der_x509_certificate(der_cert_bin)
    certificates.append(cert)
    
    return certificates


def parse_existing_certificates(cert_file_path):
    """Parse existing certificates from the bundle file."""
    try:
        with open(cert_file_path, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        return set()
    
    # Extract all PEM certificates
    cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
    existing_certs = set()
    
    for match in re.finditer(cert_pattern, content, re.DOTALL):
        pem_data = match.group(0)
        try:
            cert = x509.load_pem_x509_certificate(pem_data.encode())
            # Use the certificate's fingerprint as a unique identifier
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            existing_certs.add(fingerprint)
        except Exception:
            continue
    
    return existing_certs


def format_certificate_info(cert):
    """Format certificate information in the certifi style."""
    # Extract certificate details
    subject = cert.subject
    issuer = cert.issuer
    
    # Get common name from subject and issuer
    subject_cn = None
    subject_o = None
    issuer_cn = None
    issuer_o = None
    
    for attribute in subject:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            subject_cn = attribute.value
        elif attribute.oid == x509.NameOID.ORGANIZATION_NAME:
            subject_o = attribute.value
    
    for attribute in issuer:
        if attribute.oid == x509.NameOID.COMMON_NAME:
            issuer_cn = attribute.value
        elif attribute.oid == x509.NameOID.ORGANIZATION_NAME:
            issuer_o = attribute.value
    
    # Build issuer and subject strings
    issuer_str = f"CN={issuer_cn or 'Unknown'}"
    if issuer_o:
        issuer_str += f" O={issuer_o}"
    
    subject_str = f"CN={subject_cn or 'Unknown'}"
    if subject_o:
        subject_str += f" O={subject_o}"
    
    # Get serial number
    serial = cert.serial_number
    
    # Get fingerprints
    md5_fp = cert.fingerprint(hashes.MD5()).hex()
    sha1_fp = cert.fingerprint(hashes.SHA1()).hex()
    sha256_fp = cert.fingerprint(hashes.SHA256()).hex()
    
    # Format fingerprints with colons
    md5_formatted = ':'.join(md5_fp[i:i+2] for i in range(0, len(md5_fp), 2))
    sha1_formatted = ':'.join(sha1_fp[i:i+2] for i in range(0, len(sha1_fp), 2))
    sha256_formatted = ':'.join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))
    
    # Get PEM encoding
    pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
    
    # Format the certificate block
    label = subject_cn or "Unknown Certificate"
    
    cert_block = f"""# Issuer: {issuer_str}
# Subject: {subject_str}
# Label: "{label}"
# Serial: {serial}
# MD5 Fingerprint: {md5_formatted}
# SHA1 Fingerprint: {sha1_formatted}
# SHA256 Fingerprint: {sha256_formatted}
{pem_data}"""
    
    return cert_block


def main():
    parser = argparse.ArgumentParser(
        description="Add SSL certificates from a URL to a certifi-style certificate bundle"
    )
    parser.add_argument("url", help="URL to fetch certificates from (e.g., https://google.com)")
    parser.add_argument("cert_file", help="Path to the certificate bundle file")
    
    args = parser.parse_args()
    
    try:
        print(f"Fetching certificates from {args.url}...")
        certificates = get_certificates_from_url(args.url)
        print(f"Found {len(certificates)} certificate(s) in the chain.")
        
        print(f"Parsing existing certificates from {args.cert_file}...")
        existing_fingerprints = parse_existing_certificates(args.cert_file)
        print(f"Found {len(existing_fingerprints)} existing certificate(s).")
        
        new_certificates = []
        for cert in certificates:
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            if fingerprint not in existing_fingerprints:
                new_certificates.append(cert)
        
        if not new_certificates:
            print("No new certificates found. All certificates are already present in the bundle.")
            return
        
        print(f"\nFound {len(new_certificates)} new certificate(s):")
        
        certificates_to_add = []
        for i, cert in enumerate(new_certificates, 1):
            # Get certificate subject for display
            subject_cn = "Unknown"
            for attribute in cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    subject_cn = attribute.value
                    break
            
            print(f"\nCertificate {i}: {subject_cn}")
            print(f"Issuer: {cert.issuer.rfc4514_string()}")
            print(f"Valid from: {cert.not_valid_before_utc}")
            print(f"Valid until: {cert.not_valid_after_utc}")
            
            while True:
                response = input("Add this certificate to the bundle? (y/n): ").lower().strip()
                if response in ['y', 'yes']:
                    certificates_to_add.append(cert)
                    break
                elif response in ['n', 'no']:
                    break
                else:
                    print("Please enter 'y' or 'n'")
        
        if not certificates_to_add:
            print("No certificates selected for addition.")
            return
        
        # Add certificates to the file
        print(f"\nAdding {len(certificates_to_add)} certificate(s) to {args.cert_file}...")
        
        with open(args.cert_file, 'a') as f:
            for cert in certificates_to_add:
                cert_block = format_certificate_info(cert)
                f.write('\n' + cert_block + '\n')
        
        print("Certificates added successfully!")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
