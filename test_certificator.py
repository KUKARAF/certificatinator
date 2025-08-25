#!/usr/bin/env python3
"""
Tests for the certificator module.
"""

import unittest
from unittest.mock import patch, mock_open, MagicMock
import tempfile
import os
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

import certificator


class TestCertificator(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a test certificate for testing
        self.test_cert = self._create_test_certificate()
        self.test_cert_pem = self.test_cert.public_bytes(serialization.Encoding.PEM).decode()
        
    def _create_test_certificate(self):
        """Create a test certificate for testing purposes."""
        # Generate a private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        return cert

    def test_get_certificates_from_url_invalid_url(self):
        """Test get_certificates_from_url with invalid URL."""
        with self.assertRaises(ValueError):
            certificator.get_certificates_from_url("invalid-url")

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_get_certificates_from_url_success(self, mock_ssl_context, mock_socket):
        """Test successful certificate retrieval from URL."""
        # Mock SSL socket
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = self.test_cert.public_bytes(serialization.Encoding.DER)
        mock_ssock.getpeercert_chain.return_value = [self.test_cert.public_bytes(serialization.Encoding.DER)]
        
        # Mock socket and context
        mock_sock = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssock
        mock_ssl_context.return_value = mock_context
        
        # Test the function
        certs = certificator.get_certificates_from_url("https://example.com")
        
        self.assertEqual(len(certs), 1)
        self.assertIsInstance(certs[0], x509.Certificate)

    @patch('socket.create_connection')
    def test_get_certificates_from_url_connection_error(self, mock_socket):
        """Test connection error handling."""
        mock_socket.side_effect = socket.error("Connection failed")
        
        with self.assertRaises(socket.error):
            certificator.get_certificates_from_url("https://example.com")

    def test_parse_existing_certificates_file_not_found(self):
        """Test parsing when certificate file doesn't exist."""
        result = certificator.parse_existing_certificates("nonexistent_file.pem")
        self.assertEqual(result, set())

    def test_parse_existing_certificates_with_valid_certs(self):
        """Test parsing existing certificates from file."""
        cert_content = f"""# Test certificate
# Issuer: CN=Test
# Subject: CN=Test
{self.test_cert_pem}

# Another comment
{self.test_cert_pem}"""
        
        with patch('builtins.open', mock_open(read_data=cert_content)):
            result = certificator.parse_existing_certificates("test.pem")
            
        # Should find 2 certificates (same cert twice)
        self.assertEqual(len(result), 1)  # Same fingerprint, so only 1 unique
        
        # Verify the fingerprint is correct
        expected_fingerprint = self.test_cert.fingerprint(hashes.SHA256()).hex()
        self.assertIn(expected_fingerprint, result)

    def test_parse_existing_certificates_with_invalid_certs(self):
        """Test parsing file with invalid certificate data."""
        invalid_content = """# Test certificate
-----BEGIN CERTIFICATE-----
INVALID_CERTIFICATE_DATA
-----END CERTIFICATE-----"""
        
        with patch('builtins.open', mock_open(read_data=invalid_content)):
            result = certificator.parse_existing_certificates("test.pem")
            
        self.assertEqual(result, set())

    def test_format_certificate_info(self):
        """Test certificate formatting."""
        formatted = certificator.format_certificate_info(self.test_cert)
        
        # Check that all required fields are present
        self.assertIn("# Issuer:", formatted)
        self.assertIn("# Subject:", formatted)
        self.assertIn("# Label:", formatted)
        self.assertIn("# Serial:", formatted)
        self.assertIn("# MD5 Fingerprint:", formatted)
        self.assertIn("# SHA1 Fingerprint:", formatted)
        self.assertIn("# SHA256 Fingerprint:", formatted)
        self.assertIn("-----BEGIN CERTIFICATE-----", formatted)
        self.assertIn("-----END CERTIFICATE-----", formatted)
        
        # Check specific values
        self.assertIn("CN=test.example.com", formatted)
        self.assertIn("O=Test Org", formatted)
        self.assertIn('"test.example.com"', formatted)

    def test_format_certificate_info_minimal_cert(self):
        """Test formatting certificate with minimal information."""
        # Create a certificate with minimal fields
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "minimal.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            12345
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        formatted = certificator.format_certificate_info(cert)
        
        self.assertIn("CN=minimal.example.com", formatted)
        self.assertIn("# Serial: 12345", formatted)

    @patch('builtins.input')
    @patch('builtins.print')
    @patch('certificator.get_certificates_from_url')
    @patch('certificator.parse_existing_certificates')
    @patch('builtins.open', new_callable=mock_open)
    def test_main_no_new_certificates(self, mock_file, mock_parse, mock_get_certs, mock_print, mock_input):
        """Test main function when no new certificates are found."""
        # Setup mocks
        mock_get_certs.return_value = [self.test_cert]
        fingerprint = self.test_cert.fingerprint(hashes.SHA256()).hex()
        mock_parse.return_value = {fingerprint}
        
        # Mock command line arguments
        with patch('sys.argv', ['certificator', 'https://example.com', 'test.pem']):
            certificator.main()
        
        # Verify that the "no new certificates" message was printed
        mock_print.assert_any_call("No new certificates found. All certificates are already present in the bundle.")

    @patch('builtins.input')
    @patch('builtins.print')
    @patch('certificator.get_certificates_from_url')
    @patch('certificator.parse_existing_certificates')
    @patch('builtins.open', new_callable=mock_open)
    def test_main_user_accepts_certificate(self, mock_file, mock_parse, mock_get_certs, mock_print, mock_input):
        """Test main function when user accepts a new certificate."""
        # Setup mocks
        mock_get_certs.return_value = [self.test_cert]
        mock_parse.return_value = set()  # No existing certificates
        mock_input.return_value = 'y'  # User accepts
        
        # Mock command line arguments
        with patch('sys.argv', ['certificator', 'https://example.com', 'test.pem']):
            certificator.main()
        
        # Verify file was opened for appending
        mock_file.assert_called_with('test.pem', 'a')
        
        # Verify success message
        mock_print.assert_any_call("Certificates added successfully!")

    @patch('builtins.input')
    @patch('builtins.print')
    @patch('certificator.get_certificates_from_url')
    @patch('certificator.parse_existing_certificates')
    def test_main_user_rejects_certificate(self, mock_parse, mock_get_certs, mock_print, mock_input):
        """Test main function when user rejects a new certificate."""
        # Setup mocks
        mock_get_certs.return_value = [self.test_cert]
        mock_parse.return_value = set()  # No existing certificates
        mock_input.return_value = 'n'  # User rejects
        
        # Mock command line arguments
        with patch('sys.argv', ['certificator', 'https://example.com', 'test.pem']):
            certificator.main()
        
        # Verify rejection message
        mock_print.assert_any_call("No certificates selected for addition.")

    @patch('builtins.input')
    @patch('builtins.print')
    @patch('certificator.get_certificates_from_url')
    def test_main_connection_error(self, mock_get_certs, mock_print, mock_input):
        """Test main function with connection error."""
        # Setup mock to raise exception
        mock_get_certs.side_effect = Exception("Connection failed")
        
        # Mock command line arguments
        with patch('sys.argv', ['certificator', 'https://example.com', 'test.pem']):
            with self.assertRaises(SystemExit):
                certificator.main()

    def test_fingerprint_formatting(self):
        """Test that fingerprints are formatted correctly with colons."""
        formatted = certificator.format_certificate_info(self.test_cert)
        
        # Extract fingerprint lines
        lines = formatted.split('\n')
        md5_line = next(line for line in lines if line.startswith('# MD5 Fingerprint:'))
        sha1_line = next(line for line in lines if line.startswith('# SHA1 Fingerprint:'))
        sha256_line = next(line for line in lines if line.startswith('# SHA256 Fingerprint:'))
        
        # Check format (should have colons every 2 characters)
        md5_fp = md5_line.split(': ')[1]
        sha1_fp = sha1_line.split(': ')[1]
        sha256_fp = sha256_line.split(': ')[1]
        
        # MD5 should be 32 hex chars + 15 colons = 47 total
        self.assertEqual(len(md5_fp), 47)
        self.assertEqual(md5_fp.count(':'), 15)
        
        # SHA1 should be 40 hex chars + 19 colons = 59 total
        self.assertEqual(len(sha1_fp), 59)
        self.assertEqual(sha1_fp.count(':'), 19)
        
        # SHA256 should be 64 hex chars + 31 colons = 95 total
        self.assertEqual(len(sha256_fp), 95)
        self.assertEqual(sha256_fp.count(':'), 31)


class TestCertificateIntegration(unittest.TestCase):
    """Integration tests using temporary files."""
    
    def setUp(self):
        """Set up temporary files for testing."""
        self.temp_dir = tempfile.mkdtemp()
        self.cert_file = os.path.join(self.temp_dir, 'test_certs.pem')
        
    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_parse_and_format_roundtrip(self):
        """Test that parsing and formatting certificates works correctly."""
        # Create a test certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "roundtrip.example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        # Format and write certificate
        formatted = certificator.format_certificate_info(cert)
        with open(self.cert_file, 'w') as f:
            f.write(formatted)
        
        # Parse it back
        fingerprints = certificator.parse_existing_certificates(self.cert_file)
        
        # Verify the fingerprint matches
        expected_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        self.assertIn(expected_fingerprint, fingerprints)
        self.assertEqual(len(fingerprints), 1)


if __name__ == '__main__':
    unittest.main()
