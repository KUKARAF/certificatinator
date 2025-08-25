# Certificatinator

A tool to manage SSL certificates in certifi-style bundles.

## Description

Certificatinator fetches SSL certificate chains from URLs and allows you to add them to certificate bundle files in the same format used by the `certifi` package. It helps you manage custom certificates that may not be included in standard certificate bundles.

## Features

- Fetch complete SSL certificate chains from any HTTPS URL
- Parse existing certificate bundles to avoid duplicates
- Interactive certificate selection and approval
- Format certificates in certifi-style with detailed metadata
- Support for MD5, SHA1, and SHA256 fingerprints

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python certificatinator.py <url> <cert_file_path>
```

### Examples

Add certificates from Google to a bundle file:
```bash
python certificatinator.py https://google.com certificates.pem
```

Add certificates from a custom domain:
```bash
python certificatinator.py https://example.com:8443 my_certs.pem
```

## How it works

1. Connects to the specified URL and retrieves the SSL certificate chain
2. Parses any existing certificates in the target file to avoid duplicates
3. Presents new certificates for interactive approval
4. Adds approved certificates to the bundle file with detailed metadata

## Testing

Run the test suite:

```bash
pytest
```

## Requirements

- Python 3.6+
- cryptography >= 3.0.0
- See `requirements.txt` for full dependency list
