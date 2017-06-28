import unittest
import base64
from authenticator import authenticator


class tests_authenticator(unittest.TestCase):
    def setUp(self):
        self.test_validate_response = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE USER SYSTEM "https://gas.nis1.national.ncrs.nhs.uk/login/dtd">
<gpOBJECT>
<gpPARAM name="log_session_id">Ao9qufl+uA</gpPARAM>
<gpPARAM name="error_url">https://gas.nis1.national.ncrs.nhs.uk/login/error</gpPARAM>
<gpPARAM name="server_ip">192.168.118.105</gpPARAM>
<gpPARAM name="cn">RA_A00394 RA A</gpPARAM>
<gpPARAM name="nhsjobrole0" id="887389426511" orgcode="B81012">STIRLING MEDICAL CENTRE (S KUMAR), "Admin & Clerical":"Admin":"Demographic Administrator"</gpPARAM>
<gpPARAM name="nhsjobrole1" id="555008642106" orgcode="B81012">STIRLING MEDICAL CENTRE (S KUMAR), "Admin & Clerical":"Management - A & C":"Registration Authority Manager"</gpPARAM>
<gpPARAM name="nhsjobrole2" id="102048848984" orgcode="B81016">PELHAM MEDICAL GROUP, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole3" id="102048850986" orgcode="B81108">SAHA SN & DE G, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole4" id="102048852982" orgcode="B81603">ASHWOOD SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole5" id="107620875545" orgcode="B81603">ASHWOOD SURGERY, "Admin & Clerical":"Admin":"Demographic Administrator"</gpPARAM>
<gpPARAM name="nhsjobrole6" id="102048854989" orgcode="B81606">STIRLING MEDICAL CENTRE (SINGH), "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole7" id="102048856985" orgcode="B82099">GRASSINGTON MEDICAL CENTRE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole8" id="102048858981" orgcode="B82609">AMPLEFORTH SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole9" id="102048861981" orgcode="B82611">PEASHOLM SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole10" id="102048864986" orgcode="B83001">DR K HICKEY'S PRACTICE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole11" id="102048866982" orgcode="C81006">CHARNWOOD SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole12" id="102048868989" orgcode="D82010">GRIMSTON MEDICAL CENTRE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole13" id="102048870980" orgcode="D82015">BRIDGE STREET SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole14" id="102048872987" orgcode="D82021">HUNSTANTON SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole15" id="102048874983" orgcode="D82027">HEACHAM GROUP SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole16" id="102048877988" orgcode="D82099">SOUTHGATES, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole17" id="102048879984" orgcode="D82105">ST CLEMENT'S SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole18" id="102048881986" orgcode="RKF">THE PRINCESS ROYAL HOSPITAL NHS TRUST, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole19" id="102048883982" orgcode="Y00221">VEDUTLA RDP, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole20" id="102048885989" orgcode="Y00452">OPHTHALMOLOGY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole21" id="102048887985" orgcode="Y00483">NELPCT OUT OF HOURS SERVICE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole22" id="102054174981" orgcode="FA079">KING STREET PHARMACY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole23" id="905002982510" orgcode="5AN">NORTH EAST LINCOLNSHIRE PCT, "Admin & Clerical":"Admin":"Demographic Administrator"</gpPARAM>
<gpPARAM name="nhsjobrole24" id="384817818519" orgcode="5CY">WEST NORFOLK PCT, "Admin & Clerical":"Admin":"Demographic Administrator"</gpPARAM>
<gpPARAM name="nhsjobrole25" id="404523906513" orgcode="RMM">COMMUNITY HEALTHCARE BOLTON NHS TRUST, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole26" id="880415398515" orgcode="RCJ">SOUTH TEES HOSPITALS NHS TRUST, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole27" id="555006762108" orgcode="Y00167">DERMATOLOGY CLINIC, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole28" id="555006782102" orgcode="C81115">GLADSTONE HOUSE SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole29" id="555006859104" orgcode="A20074">GP PRACTICE EMIS CG001 001, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole30" id="555006863100" orgcode="A20079">GP PRACTICE EMIS CG003 001, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole31" id="555012026108" orgcode="RHY">TWO SHIRES AMBULANCE NHS TRUST, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole32" id="555048763107" orgcode="L83137">SOUTH MOLTON HEALTH CENTRE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole33" id="555048767101" orgcode="P84064">ANCOATS PRIMARY CARE CENTRE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole34" id="555048771107" orgcode="J81646">GROVE SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole35" id="555050250101" orgcode="C84043">LEEN VIEW SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole36" id="555050252103" orgcode="C81611">DR GI JONES' PRACTICE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole37" id="555050254105" orgcode="B85036">DR BOULTON AND PARTNERS, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole38" id="555052310107" orgcode="C81040">PARK LANE SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="nhsjobrole39" id="555055071105" orgcode="Y00999">ST CLEMENTS HEALTH CENTRE, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>
<gpPARAM name="gas_version">5.2.7</gpPARAM>
<gpPARAM name="sso_ticket">AQIC5wM2LY4SfcwrRGMHiyxMR3suYWqcF+B1j56GJ4xGut4=@AAJTSQACMDE=#</gpPARAM>
<gpPARAM name="sso_domain">.nis.nhs.uk</gpPARAM>
<gpPARAM name="sso_session_url">http://192.168.62.13:8093/sessionmanager/session/update</gpPARAM>
<gpPARAM name="sso_max_session_time">600</gpPARAM>
<gpPARAM name="sso_keep_alive">false</gpPARAM>
<gpPARAM name="sso_session_time">600</gpPARAM>
<gpPARAM name="sso_logout_url">https://gas.nis1.national.ncrs.nhs.uk/login/authlogout</gpPARAM>
<gpPARAM name="auth_method">3</gpPARAM>
<gpPARAM name="app_url">NHST</gpPARAM>
<gpPARAM name="service">AUTHENTICATION</gpPARAM>
</gpOBJECT>"""
        self.test_role_line = '<gpPARAM name="nhsjobrole34" id="555048771107" orgcode="J81646">GROVE SURGERY, "Admin & Clerical":"Admin":"Registration Authority Agent"</gpPARAM>'
        self.test_challenge = base64.b64decode('MlJN9BVjTdKtTpKrSz3Jvq0sONIAAAFc7yH6TYe8NK6GHS7F7t2tGnmcost76xk7')
        self.test_cert = base64.b64decode('MIIDbzCCAlegAwIBAgIEVzHBnDANBgkqhkiG9w0BAQUFADAtMQwwCgYDVQQKEwNuaHMxCzAJBgNVBAsTAkNBMRAwDgYDVQQDEwdTdWJDQTAyMB4XDTE2MTEyMjE2MTgxOVoXDTE4MTEyMjE2NDgxOVowNjEMMAoGA1UEChMDbmhzMQ8wDQYDVQQLEwZwZW9wbGUxFTATBgNVBAMTDDEwMjA0ODg0Mzk4MzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAp/9RZ9baYvAj/LnBy8TaQeUrDJYYK7bbXj8l9IijmHbb+icAjbb0qkof+lrcqYLHShh5oUdStOO5i+u38VTsCaoZu6cwMls/XO2peJMJFFnwfLL9FIvGtC5Kg9p65jAX0YvE/qlT4seeGQK7q6Nax1NrtUStX05n7cUuiu7Ji/cCAwEAAaOCARAwggEMMAsGA1UdDwQEAwIHgDAYBgNVHSAEETAPMA0GCyqGOgCJe2UAAwEBMFAGA1UdHwRJMEcwRaBDoEGkPzA9MQwwCgYDVQQKEwNuaHMxCzAJBgNVBAsTAkNBMRAwDgYDVQQDEwdTdWJDQTAyMQ4wDAYDVQQDEwVDUkw1NzArBgNVHRAEJDAigA8yMDE2MTEyMjE2MTgxOVqBDzIwMTgxMTIyMTY0ODE5WjAfBgNVHSMEGDAWgBQSSoi3gsCYCcPcpsZpewnlLvD2BTAdBgNVHQ4EFgQUlQvtlbbgKoJmZVE2FszB4wJWP70wCQYDVR0TBAIwADAZBgkqhkiG9n0HQQAEDDAKGwRWOC4xAwIEsDANBgkqhkiG9w0BAQUFAAOCAQEAbEGtl/aHjbafhCyq7gSLq++wN5eCMvxBVZ8cbXR1qWDBr0EBkmq7AUr19HtR5OG+lCTA/uRcAMDqvKp4GgRd0MmdjwfJzqwZH2ztLcg9zqw1t4nfRUwa1kN1aXSNlgw59iBYqDr4w0MVY8ioGZyoIT6S6/DVgH32HLpKo1hkKXJSvd8H2R20FBdTR5D03Ka8yfIRftIsH74C5Ikl3Zaz58ifmLSUUdEjnRufKyf1OZ5RTzTub+ubD1C5Mdx2RB2zPbt3pR16YK3OXTnPMsbIaO9NKHrbZSqbHALsC7nBhEY4ipxr8UjFg2ZcEDPvdIQiHj+Z4U2xGn3kJ7Gmo91STQ==')
        self.test_signature = b'=*\xf5\x81\xc7\x15_\x0f\xd9\xf8L\xcdhr\xde\x84M\xfdd\x89\x9fG\xa4\xe4\xe7V\xe2a\x1d+\xfbD\xbc`\xe8p\xaf\xa7JZ\x1d\xb25\xa1\x9a\\\xdap@\x96\xa4s\x1dh\xba\x13)]\x014n\x93\x13\x07\x1e\xe5&DwG#Zo;\xad\xae\x14\xb3e\xf7=\x1fj\x01\x8cZ\x1crs\xb1N\x8eWd\x9c\x1f8qcl\xaf\xd7~\xa8\x9dmP\x95\x84?]\xf8A\\\xe4\x11\t\xbb>\x10X\x8a|\xd5+\xe0\xaf('

    def test_authenticate_whenCalledWithValidPasscodeAndInsertedSmartcard_authenticatesAndReturnsUserDetails(self):
        atn = authenticator()

        res = atn.authenticate("1234")

        self.assertIn('sso_ticket', res)
        self.assertIn('roles', res)

    def test__parse_validate_response_whenCalledWithValidAuthValidateResponse(self):
        atn = authenticator()
        res = atn._parse_validate_response(self.test_validate_response)

        self.assertIn('sso_ticket', res)

    def test__extract_role_whenCalledWithValidRoleLine_returnsRoleDetailInDict(self):
        atn = authenticator()
        role = atn._extract_role(self.test_role_line)

        self.assertIn('id', role)
        self.assertIn('org_code', role)
        self.assertIn('org_name', role)
        self.assertIn('name', role)
        self.assertIn('type', role)
        self.assertIn('sub_type', role)

    def test_build_asn1(self):
        atn = authenticator()
        atn._build_asn1(self.test_challenge, self.test_cert, self.test_signature)




