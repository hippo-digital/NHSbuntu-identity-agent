import base64
from PyKCS11 import *
import re

def sign(pkcs11lib, passcode, challenge):
    toSign = base64.b64decode(challenge)

    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11lib)

    slots = pkcs11.getSlotList()
    slot = slots[0]

    session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    session.login(passcode, CKU_USER)

    card_info = _get_card_info(session)

    card_info['signature'] = session.sign(card_info['private_key'], toSign, Mechanism(CKM_SHA1_RSA_PKCS, None))

    session.logout()
    session.closeSession()

    return card_info

def _get_card_info(session):
    info = {}

    private_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),])

    for private_key in private_keys:
      key_info = private_key.to_dict()
      if len(key_info['CKA_LABEL']) < 46:
        print(key_info['CKA_LABEL'])
        print(key_info['CKA_ID'])
        print(len(key_info['CKA_LABEL']))
        print("")

        info['key_id'] = key_info['CKA_ID']

    card_objects = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_ID, info['key_id'])])

    info['certificate'] = bytes(card_objects[0].to_dict()['CKA_VALUE'])
    info['label'] = card_objects[0].to_dict()['CKA_LABEL'].decode('utf-8')
    info['uid'] = re.findall('(?:CN=)(.*)', info['label'])[0]

    info['private_key'] = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, info['key_id'])])[0]
    info['public_key'] = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, info['key_id'])])[0]

    return info