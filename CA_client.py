# CA_client.py

import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import ldap3
import datetime

# Fonction pour générer les clés RSA
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

# Fonction pour générer le certificat x509
def generate_x509_certificate(private_key, public_key, common_name):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # This cert will be valid for 10 days
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    return cert

# Fonction pour enregistrer les données dans le serveur LDAP
def register_in_ldap(common_name, public_key_pem, certificate_pem):
    server = ldap3.Server('ldap://localhost:389')
    connection = ldap3.Connection(server, user='cn=admin,dc=nodomain,dc=com', password='kali', auto_bind=True)

    entry = {
        'objectClass': ['top', 'person'],
        'cn': common_name,
        'userCertificate;binary': [base64.b64decode(certificate_pem)],
        'userPKCS12;binary': [base64.b64encode(public_key_pem + certificate_pem)],
    }

    connection.add('cn={},dc=nodomain,dc=com'.format(common_name), attributes=entry)

    connection.unbind()

if __name__ == "__main__":
    common_name = input("Entrez votre nom commun : ")

    private_key, public_key = generate_rsa_key_pair()
    print(public_key,private_key)

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(public_key_pem)
    certificate = generate_x509_certificate(private_key, public_key, common_name)
    print(certificate)

    certificate_pem = certificate.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    print(certificate_pem)

    register_in_ldap(common_name, public_key_pem, certificate_pem)
