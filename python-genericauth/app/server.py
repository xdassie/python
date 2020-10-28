from flask import Flask, g, request, send_from_directory, session, url_for, redirect, jsonify, Response, abort, redirect, make_response, render_template
from paste.translogger import TransLogger
from waitress import serve
import random
import os
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
from ldap3 import Tls, ALL
import ssl
from ldap3 import Server, Connection, ALL
import base64
import logging
import redis
import hashlib
import datetime
from threading import RLock

lock = RLock()
        
redis_host = "localhost"
redis_port = 6379
redis_password = ""

ldap_password = os.environ["LDAP_PASSWORD"].strip()
ldap_username = os.environ["LDAP_USERNAME"].strip()
ldap_host = os.environ["LDAP_HOST"].strip()

first = True

def expiring_salt():
    lock.acquire()
    global salt
    global salt_timestamp
    global first
    if first:
        first = False
        salt = os.urandom(32)
        salt_timestamp = datetime.datetime.now()        
    try:
        datetime_object = datetime.datetime.now() 
        difference = datetime_object - salt_timestamp
        if difference.total_seconds()>60:
            salt_timestamp = datetime.datetime.now() 
            salt = os.urandom(32)
    finally:
        lock.release()
        return salt

def ldap_auth(auth_username , auth_pass):
    key = hashlib.pbkdf2_hmac('sha256', auth_pass.encode('utf-8'), expiring_salt(), 100)
# check if the key is already in the cache. If so return true as if the authentication response was valid. Otherwise continue to authenticate and cache the actual response
    r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)
    cached = r.get(key)
    if cached:
        return True
    else:
        tls_ctx = Tls( validate=ssl.CERT_REQUIRED, ca_certs_file='/app/cacerts/cafile', version=ssl.PROTOCOL_TLSv1_2)
        server = Server('ldaps://' + ldap_host, use_ssl=True,tls=tls_ctx,port=636 )
        conn = Connection(server,user='cn=' + auth_username + ',ou=Users,o=AUTH', password=auth_pass,auto_bind=True)
        result = conn.bind()
        if result:
            r.set(key,1,ex=10)    # cached key will expire after 10 sec
            return True
        else:
            return False

def get_certificates(self):
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert
        
    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        # pycert._x509 = _lib.sk_X509_value(certs, i)
        # According to comment from @ Jari Turkia
        # to prevent segfaults use '_lib.X509_dup('
        pycert._x509 = _lib.X509_dup(_lib.sk_X509_value(certs, i))
        pycerts.append(pycert)
        
    if not pycerts:
        return None
    return tuple(pycerts)

app = Flask(__name__)
app.app_context().push()

with open("/var/run/secrets/tls/0", "rb") as file:
    p7 = crypto.load_pkcs7_data(crypto.FILETYPE_PEM,file.read())
    certs = get_certificates(p7)
    cafile = open("/app/cacerts/cafile","wb")
    for cert in certs:
        print('digest:{}'.format(cert.digest('sha256')))
        cafile.write(crypto.dump_certificate(crypto.FILETYPE_PEM,cert))
    cafile.close()
    
app.config['LDAP_BASE_DN'] = os.environ["LDAP_BASE_DN"]
app.config['LDAP_USERNAME'] = ldap_username
app.config['LDAP_PASSWORD'] = ldap_password
app.config['LDAP_HOST'] = ldap_host
app.config['LDAP_SCHEMA'] = "ldaps"
app.config['LDAP_PORT'] = 636
app.config['LDAP_USE_SSL'] = True
app.config['LDAP_USE_TLS'] = True
app.config['LDAP_USER_OBJECT_FILTER'] = '(sAMAccountName=%s)'
app.config['LDAP_REALM_NAME'] = 'This should be defined externally'
app.config['LDAP_REQUIRE_CERT'] = True
app.config['LDAP_CERT_PATH'] = '/app/cacerts/cafile'

# validate OS variables here

def require_auth():
    resp = Response()
    resp.headers['WWW-Authenticate'] = 'Basic'
    return resp, 401


@app.route('/', defaults={'u_path': ''},methods={"GET","POST"})
@app.route('/<path:u_path>',methods={"GET","POST"})
@app.route('/<string:u_path>',methods={"GET","POST"})
@app.route('/<path:u_path>/<string:u_string>',methods={"GET","POST"})
@app.route('/static/<path:u_path>/<string:u_string>',methods={"GET","POST"})
@app.route('/static/<string:u_string>',methods={"GET","POST"})
def index(u_path = None,u_string = None):
#    return Response(response="{}", status=200, mimetype="application/json")
#    return Response(response="", status=403,mimetype="application/json")
    authorization_header = request.headers.get('Authorization')
    if authorization_header:
        try:
            result = ldap_auth(request.authorization.username,request.authorization.password)
            if result:
                return Response(response="{auth}", status=200, mimetype="application/json"),200
            else:
                return require_auth()
        except Exception as e:
            logging.warning(e)
            return require_auth()
    else:
        return require_auth()
    
if __name__ == '__main__':
    serve(TransLogger(app, setup_console_handler=True), port=9999)

