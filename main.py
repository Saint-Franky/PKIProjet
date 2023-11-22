# main.py

import CA_client
import CA_server

def main():
    # Générer les clés RSA et le certificat pour le client
    common_name = input("Entrez votre nom commun : ")

    private_key, public_key = CA_client.generate_rsa_key_pair()

    private_key_pem = private_key.private_bytes(
        encoding=CA_client.serialization.Encoding.PEM,
        format=CA_client.serialization.PrivateFormat.PKCS8,
        encryption_algorithm=CA_client.serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=CA_client.serialization.Encoding.PEM,
        format=CA_client.serialization.PublicFormat.SubjectPublicKeyInfo
    )

    certificate = CA_client.generate_x509_certificate(private_key, public_key, common_name)

    certificate_pem = certificate.public_bytes(
        encoding=CA_client.serialization.Encoding.PEM
    )

    # Enregistrer les données dans le serveur LDAP
    CA_client.register_in_ldap(common_name, public_key_pem, certificate_pem)

    # Lancer le serveur LDAP
    CA_server.main()

if __name__ == "__main__":
    main()
