import base64
from PyKCS11 import *
from pyasn1.codec.ber import decoder

def sign(pkcs11lib, passcode, auth_session):
    toSign = base64.b64decode(auth_session['challenge'])

    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11lib)
    pkcs11_info = pkcs11.getInfo().__dict__
    auth_session['analytics']['MiddlewareInstalled'] = '%s %s, libver %s, cryptokiver %s' \
                                                       % (pkcs11_info['manufacturerID'].decode('utf-8').strip(),
                                                          pkcs11_info['libraryDescription'].decode('utf-8').strip(),
                                                          pkcs11_info['libraryVersion'],
                                                          pkcs11_info['cryptokiVersion'])

    slots = pkcs11.getSlotList()
    slot = slots[0]

    for s in slots:
        slot_info = pkcs11.getSlotInfo(s)
        slot_description = slot_info.to_dict()['slotDescription'].decode('utf-8').strip()
        auth_session['analytics']['CardReaders'].append(slot_description)

        if s == slot:
            auth_session['analytics']['ActiveCardReader'] = slot_description

    card_session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
    card_session.login(passcode, CKU_USER)

    card_info = _get_card_info(card_session)

    auth_session['signature'] = bytes(card_session.sign(card_info['private_key'], toSign, Mechanism(CKM_SHA1_RSA_PKCS, None)))
    auth_session['uid'] = card_info['uid']
    auth_session['certificate'] = card_info['certificate']

    card_session.logout()
    card_session.closeSession()

def _get_card_info(card_session):
    info = {}
    private_keys = card_session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),])

    for private_key in private_keys:
        key_info = private_key.to_dict()

        if key_info['CKA_DECRYPT'] == True:
            info['key_id'] = key_info['CKA_ID']

    auth_cert = card_session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_ID, info['key_id'])])[0]

    info['certificate'] = bytes(auth_cert.to_dict()['CKA_VALUE'])
    info['label'] = auth_cert.to_dict()['CKA_LABEL'].decode('utf-8')

    uid = _get_uid_from_subject(bytes(auth_cert.to_dict()['CKA_SUBJECT']))

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
