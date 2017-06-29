import base64
from PyKCS11 import *
import re
from pyasn1.type import univ, char, tag
from pyasn1.codec.ber import encoder, decoder

def sign(pkcs11lib, passcode, auth_session):
    toSign = base64.b64decode(auth_session['challenge'])

    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11lib)

    slots = pkcs11.getSlotList()
    slot = slots[0]

    card_session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    card_session.login(passcode, CKU_USER)

    card_info = _get_card_info(card_session)

    auth_session['signature'] = bytes(card_session.sign(card_info['private_key'], toSign, Mechanism(CKM_SHA1_RSA_PKCS, None)))
    auth_session['uid'] = card_info['uid']
    auth_session['certificate'] = card_info['certificate']

    card_session.logout()
    card_session.closeSession()

    # return card_info

def _get_card_info(card_session):
    info = {}

    private_keys = card_session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),])

    for private_key in private_keys:
      key_info = private_key.to_dict()
      if len(key_info['CKA_LABEL']) < 46:
        print(key_info['CKA_LABEL'])
        print(key_info['CKA_ID'])
        print(len(key_info['CKA_LABEL']))
        print("")

        info['key_id'] = key_info['CKA_ID']

    card_objects = card_session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_ID, info['key_id'])])

    info['certificate'] = bytes(card_objects[0].to_dict()['CKA_VALUE'])
    info['label'] = card_objects[0].to_dict()['CKA_LABEL'].decode('utf-8')

    uid = _get_uid_from_subject(bytes(card_objects[0].to_dict()['CKA_SUBJECT']))

    if type(uid) is bytes:
        info['uid'] = uid.decode('utf-8')
    elif type(uid) is str:
        info['uid'] = uid
    else:
        info['uid'] = 'unknown'

    info['private_key'] = card_session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, info['key_id'])])[0]
    info['public_key'] = card_session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, info['key_id'])])[0]

    return info

def _get_uid_from_subject(asn1):
    subject_info = {}
    subject = decoder.decode(asn1)

    uid = subject[0][2][0][1]._value

    return uid
