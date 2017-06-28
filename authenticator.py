from __future__ import print_function

from PyKCS11 import *
import binascii
import base64

import requests
import re
import pyasn1

class authenticator:
    def __init__(self):
        self.auth_uri = 'http://10.211.55.3:5000'
        self.auth_uri = 'https://gas.nis1.national.ncrs.nhs.uk'

        self.user_agent = 'Mozilla/4.0(compatible;IE;GACv10. 0. 0. 1)'

        self.asn1_template = """MIIEuAYJKoZIhvcNAQcCoIIEqTCCBKUCAQExCzAJBgUrDgMCGgUAMD8GCSqGSIb3DQEHAaAyBDBm
        YjFjNWI1NzFhYWIzYzI3NTRmZTRkNDk3M2I3MjA5M2Q2MGMzY2M1OTQ1MzZjNzKgggNzMIIDbzCC
        AlegAwIBAgIEVzHBnDANBgkqhkiG9w0BAQUFADAtMQwwCgYDVQQKEwNuaHMxCzAJBgNVBAsTAkNB
        MRAwDgYDVQQDEwdTdWJDQTAyMB4XDTE2MTEyMjE2MTgxOVoXDTE4MTEyMjE2NDgxOVowNjEMMAoG
        A1UEChMDbmhzMQ8wDQYDVQQLEwZwZW9wbGUxFTATBgNVBAMTDDEwMjA0ODg0Mzk4MzCBnzANBgkq
        hkiG9w0BAQEFAAOBjQAwgYkCgYEAp/9RZ9baYvAj/LnBy8TaQeUrDJYYK7bbXj8l9IijmHbb+icA
        jbb0qkof+lrcqYLHShh5oUdStOO5i+u38VTsCaoZu6cwMls/XO2peJMJFFnwfLL9FIvGtC5Kg9p6
        5jAX0YvE/qlT4seeGQK7q6Nax1NrtUStX05n7cUuiu7Ji/cCAwEAAaOCARAwggEMMAsGA1UdDwQE
        AwIHgDAYBgNVHSAEETAPMA0GCyqGOgCJe2UAAwEBMFAGA1UdHwRJMEcwRaBDoEGkPzA9MQwwCgYD
        VQQKEwNuaHMxCzAJBgNVBAsTAkNBMRAwDgYDVQQDEwdTdWJDQTAyMQ4wDAYDVQQDEwVDUkw1NzAr
        BgNVHRAEJDAigA8yMDE2MTEyMjE2MTgxOVqBDzIwMTgxMTIyMTY0ODE5WjAfBgNVHSMEGDAWgBQS
        Soi3gsCYCcPcpsZpewnlLvD2BTAdBgNVHQ4EFgQUlQvtlbbgKoJmZVE2FszB4wJWP70wCQYDVR0T
        BAIwADAZBgkqhkiG9n0HQQAEDDAKGwRWOC4xAwIEsDANBgkqhkiG9w0BAQUFAAOCAQEAbEGtl/aH
        jbafhCyq7gSLq++wN5eCMvxBVZ8cbXR1qWDBr0EBkmq7AUr19HtR5OG+lCTA/uRcAMDqvKp4GgRd
        0MmdjwfJzqwZH2ztLcg9zqw1t4nfRUwa1kN1aXSNlgw59iBYqDr4w0MVY8ioGZyoIT6S6/DVgH32
        HLpKo1hkKXJSvd8H2R20FBdTR5D03Ka8yfIRftIsH74C5Ikl3Zaz58ifmLSUUdEjnRufKyf1OZ5R
        TzTub+ubD1C5Mdx2RB2zPbt3pR16YK3OXTnPMsbIaO9NKHrbZSqbHALsC7nBhEY4ipxr8UjFg2Zc
        EDPvdIQiHj+Z4U2xGn3kJ7Gmo91STTGB2jCB1wIBATA1MC0xDDAKBgNVBAoTA25oczELMAkGA1UE
        CxMCQ0ExEDAOBgNVBAMTB1N1YkNBMDICBFcxwZwwCQYFKw4DAhoFADANBgkqhkiG9w0BAQEFAASB
        gAbgiKgS9PTha28dW1Ll4UhSpAUAgOAkODAWhTyqhIEMg6PSJ3P6K4f1/0bTBMDmdNvVlvFnAQdc
        yqnqd4/IbZHVIdvriNCe+gYJDc717cKaXoRcIVNj89FU0irluXuu/QDqJE3hCpmVeVnA0d0Gqjab
        fe4adyyaTERYoUckKslF"""
        self.smime_header = """MIME-Version: 1.0
        Content-Disposition: attachment; filename="smime.p7m"
        Content-Type: application/x-pkcs7-mime; name="smime.p7m"
        Content-Transfer-Encoding: base64
        
        """
        self.auth_activate_template = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
        <gpOBJECT>
        <gpPARAM name="auth_method">3</gpPARAM>
        <gpPARAM name="app_url">NHST</gpPARAM>
        <gpPARAM name="log_session_id">ZtBJb9tU7T</gpPARAM>
        <gpPARAM name="device_id">b02edd24,ClientIP=172.20.16.255</gpPARAM>
        <gpPARAM name="service">ACTIVATION</gpPARAM>
        </gpOBJECT>"""
        self.auth_validate_template = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
        <gpOBJECT>
        <gpPARAM name="auth_method">3</gpPARAM>
        <gpPARAM name="app_url">NHST</gpPARAM>
        <gpPARAM name="log_session_id">Ao9qufl+uA</gpPARAM>
        <gpPARAM name="device_id">b02edd23,ClientIP=10.211.55.3</gpPARAM>
        <gpPARAM name="service">AUTHENTICATION</gpPARAM>
        <gpPARAM name="challenge">...challenge...</gpPARAM>
        <gpPARAM name="signature">...signature...</gpPARAM>
        <gpPARAM name="uid">...uid...</gpPARAM>
        <gpPARAM name="card_type">p11</gpPARAM>
        <gpPARAM name="response" encoding="base64">...response....</gpPARAM>
        <gpPARAM name="mobility">0</gpPARAM>
        </gpOBJECT>"""

    def authenticate(self, passcode):
        self._auth_activate()
        self._sign(passcode)
        validate_response = self._auth_validate()
        validate_params = self._parse_validate_response(validate_response)

        return validate_params

    def _build_asn1(self, challenge, cert, signature):
        from pyasn1.type import univ, char, tag
        from pyasn1.codec.ber import encoder, decoder

        outer = univ.Sequence()
        outer[0] = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
        outer[1] = univ.Set() # Needs to be A0
        outer[1][0] = univ.Sequence()
        outer[1][0][0] = univ.Integer(1)
        outer[1][0][1] = univ.Set()
        outer[1][0][1][0] = univ.Sequence()
        outer[1][0][1][0][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
        outer[1][0][1][0][1] = univ.Null()
        outer[1][0][2] = univ.Sequence()
        outer[1][0][2][0] = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
        outer[1][0][2][1] = univ.Set() # Needs to be A0
        outer[1][0][2][1][0] = univ.OctetString(base64.b64decode(challenge))
        outer[1][0][3] = univ.Set() # Needs to be A0

        cert_structure = decoder.decode(cert)

        # new_cert = encoder.encode(cert_structure)
        # new_cert_b64 = base64.b64encode(new_cert)

        outer[1][0][3][0] = cert_structure[0]


        outer[1][0][4] = univ.Set()
        outer[1][0][4][0] = univ.Sequence()
        outer[1][0][4][0][0] = univ.Integer(1)

        outer[1][0][4][0][1] = univ.Sequence()
        outer[1][0][4][0][1][0] = cert_structure[0][0][3]
        outer[1][0][4][0][1][1] = cert_structure[0][0][1]

        outer[1][0][4][0][2] = univ.Sequence()
        outer[1][0][4][0][2][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
        outer[1][0][4][0][2][1] = univ.Null()

        outer[1][0][4][0][3] = univ.Sequence()
        outer[1][0][4][0][3][0] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
        outer[1][0][4][0][3][1] = univ.Null()

        outer[1][0][4][0][4] = univ.OctetString(signature)

        encoded = encoder.encode(outer)


        arr = list(encoded)

        arr[15] = 160
        arr[104] = 160
        arr[52] = 160

        encoded = bytes(arr)

        b64 = base64.b64encode(encoded).decode('utf-8')

        return encoded


    def _auth_activate(self):
        auth_activate = requests.post('%s/login/authactivate' % self.auth_uri,
                                      verify=False,
                                      data=self.auth_activate_template,
                                      headers={'User-Agent': self.user_agent})

        body = auth_activate.content.decode('utf-8')
        print(body)



        # self.challenge = re.findall('(?:challenge\">)([a-z,A-Z,0-9,/+=]*)', body)[0]
        self.challenge = self._extract_parameter(body, 'challenge')
        # self.activate_signature = re.findall('(?:signature\">)([a-z,A-Z,0-9,/+=]*)', body)[0]
        self.activate_signature = self._extract_parameter(body, 'signature')

        print('Received challenge=%s' % self.challenge)


    def _sign(self, passcode):
        pkcs11 = PyKCS11Lib()
        pkcs11.load('/usr/lib/ClassicClient/libgclib.so')  # define environment variable PYKCS11LIB=YourPKCS11Lib

        # get 3rd slot
        slots = pkcs11.getSlotList()
        slot = slots[0]

        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(passcode, CKU_USER)

        private_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),])

        for private_key in private_keys:
          key_info = private_key.to_dict()
          if len(key_info['CKA_LABEL']) < 46:
            print(key_info['CKA_LABEL'])
            print(key_info['CKA_ID'])
            print(len(key_info['CKA_LABEL']))
            print("")

            keyID = key_info['CKA_ID']

        toSign = base64.b64decode(self.challenge) #'fb1c5b571aab3c2754fe4d4973b72093d60c3cc594536c72'

        print(len(toSign))

        print(''.join(format(x, '02x') for x in toSign))

        bytearr = []

        for b in toSign:
          bytearr.append(b) #int(format(b, '0')))

        card_objects = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_ID, keyID)])

        # find private key and compute signature
        print(session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)]))

        self.certificate = bytes(card_objects[0].to_dict()['CKA_VALUE'])
        label = card_objects[0].to_dict()['CKA_LABEL'].decode('utf-8')
        self.uid = re.findall('(?:CN=)(.*)', label)[0]


        privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)])[0]

        self.signature = session.sign(privKey, toSign, Mechanism(CKM_SHA1_RSA_PKCS, None))
        print("\nsignature: %s" % binascii.hexlify(bytearray(self.signature)))

        print(len(self.signature))

        # find public key and verify signature
        pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, keyID)])[0]
        result = session.verify(pubKey, toSign, self.signature, Mechanism(CKM_SHA1_RSA_PKCS, None))
        print("\nVerified: %s" % result)

        # logout
        session.logout()
        session.closeSession()

    def _auth_validate(self):
        # asn1 = self.asn1_template
        #
        # asn1l = list(base64.b64decode(asn1))
        # challengel = list(base64.b64decode(self.challenge))
        #
        # for n in range(0, len(challengel)):
        #   asn1l[56 + n] = challengel[n]
        #
        # for n in range(0, len(self.signature)):
        #   asn1l[1084 + n] = self.signature[n]
        #
        # asn1b = base64.b64encode(bytes(asn1l)).decode('utf-8')

        new_asn1 = base64.b64encode(self._build_asn1(self.challenge, self.certificate, self.signature)).decode('utf-8')

        # auth_validate_request_signature_raw = '%s%s' % (self.smime_header, asn1b)
        auth_validate_request_signature_raw = '%s%s' % (self.smime_header, new_asn1)
        auth_validate_request_signature_encoded = base64.b64encode(auth_validate_request_signature_raw.encode('utf-8'))

        auth_validate_request = self.auth_validate_template.replace('...challenge...', self.challenge)
        auth_validate_request = auth_validate_request.replace('...signature...', self.activate_signature)
        auth_validate_request = auth_validate_request.replace('...response...', auth_validate_request_signature_encoded.decode('utf-8'))
        auth_validate_request = auth_validate_request.replace('...uid...', self.uid)

        print(auth_validate_request)

        auth_validate_response = requests.post('%s/login/authvalidate' % self.auth_uri,
                                               verify=False,
                                               headers={'User-Agent': self.user_agent},
                                               data=auth_validate_request)

        body = auth_validate_response.content.decode('utf-8')
        print(body)

        return body


    def _parse_validate_response(self, auth_validate_response):
        ret = {'roles': []}

        ret['sso_ticket'] = re.findall('(?:sso_ticket\">)([^<]*)', auth_validate_response)[0]
        ret['cn'] = re.findall('(?:cn\">)([^<]*)', auth_validate_response)[0]
        ret['sso_logout_url'] = re.findall('(?:sso_logout_url\">)([^<]*)', auth_validate_response)[0]

        for l in auth_validate_response.split('\n'):
            if 'name="nhsjobrole' in l:
                ret['roles'].append(self._extract_role(l))

        return ret


    def _extract_parameter(self, body, parameter_name):
        return re.findall('(?:%s\">)([a-z,A-Z,0-9,/+=]*)' % parameter_name, body)[0]

    def _extract_role(self, role_line):
        ret = {}
        ret['org_code'] = re.findall('(?:orgcode=\")([a-z,A-Z,0-9,/+=]*)', role_line)[0]
        role_string = re.findall('(?:orgcode=\"\w*\">)([^<]*)', role_line)[0]

        role_parts_a = role_string.split(',')
        role_parts_b = role_parts_a[1].split(':')
        ret['org_name'] = role_parts_a[0]
        ret['name'] = role_parts_b[2].strip('"')
        ret['type'] = role_parts_b[0].strip('"')
        ret['sub_type'] = role_parts_b[1].strip('"')
        ret['id'] = re.findall('(?:id=\")([a-z,A-Z,0-9,/+=]*)', role_line)[0]
        return ret



