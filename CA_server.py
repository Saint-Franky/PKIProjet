# CA_server.py

from ldap3 import Server, Connection, ALL
# from ldap3.utils.dn import escape_attribute_value
import ldap3

def handle_ldap_bind(request, response, ldap_server, user, password):
    connection = Connection(ldap_server, user=user, password=password, auto_bind=True)
    response['result'] = connection.result
    return response

def handle_ldap_add(request, response, ldap_server, user, password):
    dn = request['dn']
    attributes = request['attributes']

    # Vous pouvez ajouter votre logique personnalisée pour traiter les données ici

    response['result'] = ldap_server.modify(dn, {'userCertificate;binary': [(ldap3.MODIFY_ADD, attributes['userCertificate;binary'])]})
    return response

if __name__ == "__main__":
    # Configuration du serveur LDAP
    ldap_server = Server('ldap://localhost:389', get_info=ALL)
    ldap_user = 'cn=admin,dc=nodomain,dc=com'
    ldap_password = 'admin'

    # Configuration du serveur CA
    ca_server = Server('ldaps://localhost:636', get_info=ALL)
    ca_user = 'cn=server,dc=nodomain,dc=com'
    ca_password = 'ca_admin_password'

    # Gestion des requêtes LDAP
    ldap_server.bind()
    ldap_server.handle_bind = lambda req, res: handle_ldap_bind(req, res, ldap_server, ldap_user, ldap_password)
    ldap_server.handle_add = lambda req, res: handle_ldap_add(req, res, ldap_server, ldap_user, ldap_password)
    ldap_server.listen()
