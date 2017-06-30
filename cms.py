import base64
from pyasn1.type import univ, tag
from pyasn1.codec.ber import encoder, decoder

def envelope(challenge, cert, signature):
    user_certificate = decoder.decode(cert)

    version_section = univ.Integer(1)

    digest_section = univ.Set()
    digest_section[0] = univ.Sequence()
    digest_section[0][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
    digest_section[0][1] = univ.Null()

    challenge_section = univ.Sequence()
    challenge_section[0] = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
    challenge_section[1] = univ.OctetString(value=base64.b64decode(challenge),
                                            tagSet=tag.TagSet((), tag.Tag(0, 0, 4), tag.Tag(128, 32, 0)))

    cert_section = univ.Sequence(tagSet=tag.TagSet((), tag.Tag(0, 32, 16), tag.Tag(128, 32, 0)))
    cert_section[0] = user_certificate[0][0]
    cert_section[1] = user_certificate[0][1]
    cert_section[2] = user_certificate[0][2]

    response_section = univ.Set()
    response_section[0] = univ.Sequence()
    response_section[0][0] = univ.Integer(1)
    response_section[0][1] = univ.Sequence()
    response_section[0][1][0] = user_certificate[0][0][3]
    response_section[0][1][1] = user_certificate[0][0][1]
    response_section[0][2] = univ.Sequence()
    response_section[0][2][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
    response_section[0][2][1] = univ.Null()
    response_section[0][3] = univ.Sequence()
    response_section[0][3][0] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
    response_section[0][3][1] = univ.Null()
    response_section[0][4] = univ.OctetString(signature)

    outer = univ.Sequence()
    outer[0] = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
    outer[1] = univ.Sequence(tagSet=tag.TagSet((), tag.Tag(0, 32, 16), tag.Tag(128, 32, 0)))
    outer[1][0] = version_section
    outer[1][1] = digest_section
    outer[1][2] = challenge_section
    outer[1][3] = cert_section
    outer[1][4] = response_section

    encoded = encoder.encode(outer)

    b64 = base64.b64encode(encoded).decode('utf-8')

    return encoded
