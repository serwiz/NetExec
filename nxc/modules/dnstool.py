import socket
import datetime

from collections import defaultdict
from pyasn1.type.univ import OctetString


from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes

from ldap3.protocol.microsoft import security_descriptor_control

from impacket.ldap.ldapasn1 import AddRequest, ResultCode
from impacket.ldap import ldaptypes
from impacket.structure import Structure
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED 
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )


class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )



class NXCModule:
    """

    Inspired by:
      https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py

    Author:
      @serwiz
    """

    def options(self, context, module_options):
        r"""
        METHOD          Method to use: ADD, CLEAR, UPDATE, PERM (permissions check), PERM_ALL
        DATA            OPTIONAL: DNS entry IP address 
        RECORD          OPTIONAL: DNS entry name
        ZONE            OPTIONAL: DNZ Zone : DOMAIN, FOREST, LEGACY (Default: DOMAIN)
        ZNAME           OPTIONAL: DNZ zone where to add the entry (Default: domain name)

        Example:
        -------
        nxc smb <dc_ip> -u <user> -p <password> -M dnstool -o METHOD=ADD DATA=<ip> RECORD=<entry name>
        nxc smb <dc_ip> -u <user> -p <password> -M dnstool -o METHOD=ADD DATA=<ip> RECORD=<entry name> ZONE=DOMAIN/FOREST/LEGACY ZNAME=<zone name>

        nxc smb <dc_ip> -u <user> -p <password> -M dnstool -o METHOD=UDAPTE DATA=<ip> RECORD=<entry name>
        # Remove an entry on zone
        nxc smb <dc_ip> -u <user> -p <password> -M dnstool -o METHOD=CLEAR RECORD=<entry name> ZONE=
        # Permission check on DNS Zone
        nxc smb <dc_ip> -u <user> -p <password> -M dnstool -o METHOD=PERM
        nxc smb <dc_ip> -u <user> -p <password> -M dnstool -o METHOD=PERM_ALL
        """
        self.logger = context.log
        self.method = module_options.get("METHOD").upper()
        if not self.method or self.method not in ["ADD", "CLEAR", "UPDATE", "PERM", "PERM_ALL"]:
            self.logger.fail("You need to specify a method: ADD, CLEAR, UPDATE, PERM")
            exit(1)

        self.data = module_options.get("DATA")
        self.record = module_options.get("RECORD")
        self.zone = module_options.get("ZONE") or "DOMAIN"
        self.zname = module_options.get("ZNAME") or ""

        if self.zone not in ["DOMAIN", "FOREST", "LEGACY"]:
            self.logger.fail("Invalid zone. Please choose between: DOMAIN, FOREST, LEGACY. (Default: DOMAIN)")
            exit(1)

        if self.method in ["ADD", "UPDATE"] and not self.data:
            self.logger.fail("Methods ADD/UPDATE need DATA=<ip>")
            exit(1)

        if self.method in ["ADD", "UPDATE", "CLEAR"] and not self.record:
            self.logger.fail("Methods ADD/UPDATE/CLEAR need RECORD=<entry name>")
            exit(1)


    name = "dnstool"
    description = "Manipulate DNS entry: add, clear, update and check permissions"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    def add_entry(self, context, connection):
        search_bases = {
            "DOMAIN": f"CN=MicrosoftDNS,DC=DomainDnsZones,{connection.baseDN}",
            "FOREST": f"CN=MicrosoftDNS,DC=ForestDnsZones,{connection.forestDN}",
            "LEGACY": f"CN=MicrosoftDNS,CN=System,{connection.baseDN}"
        }

        # entry_base = f"DC={self.record},DC={connction.domain},search_bases[self.zone]"
        search_base = search_bases[self.zone]
        if self.zname == "":
            self.zname = connection.domain

        zone_base = f"DC={self.zname},{search_base}"

        try:
            resp = connection.search(
                searchFilter=f"(&(objectClass=dnsNode)(name={self.record}))",
                attributes=["name"],
                baseDN=zone_base,
            )
            result = parse_result_attributes(resp)
        except Exception as e:
            self.logger.debugger(f"Failed to query {search_base} :{e}")
            self.logger.fail(f"Failed to search record inside {search_base}")
            exit(1)

        if result and len(result) > 0:
            self.logger.fail(f"Record {self.record} already exists: try method UPDATE instead")
            exit(1)
        
        record = DNS_RECORD()
        record["Type"] = 1
        record["Serial"] = int(datetime.datetime.now().timestamp())
        record["TtlSeconds"] = 180
        record["Rank"] = 240
        record["Data"] = DNS_RPC_RECORD_A()
        record["Data"]["address"] = socket.inet_aton(self.data)

        record_dn = f"DC={self.record},{zone_base}"

        self.logger.success(f"Record: {record_dn}")

        node_data = {
                "dNSTombstoned": False,
                "name": self.record,
                "dnsRecord": [record.getData()]
                }

        try:
            req = AddRequest()
            req['entry'] = record_dn

            i = 0

            req['attributes'].setComponentByPosition(i)
            req['attributes'][i]['type'] = 'objectClass'
            req['attributes'][i]['vals'].setComponentByPosition(0, 'top')
            req['attributes'][i]['vals'].setComponentByPosition(1, 'dnsNode')
            i += 1

            for name, values in node_data.items():
                req['attributes'].setComponentByPosition(i)
                req['attributes'][i]['type'] = name

                if not isinstance(values, list):
                    values = [values]

                j = 0
                for v in values:
                    if isinstance(v, bytes):
                        req['attributes'][i]['vals'].setComponentByPosition(j, v)
                    elif isinstance(v, bool):
                        req['attributes'][i]['vals'].setComponentByPosition(j, 'TRUE' if v else 'FALSE')
                    else:
                        req['attributes'][i]['vals'].setComponentByPosition(j, str(v))
                    j += 1

                i += 1


            resp = connection.ldap_connection.sendReceive(req)[0]['protocolOp']['addResponse']
            if resp['resultCode'] != ResultCode('success'):
                self.logger.fail(f"Error: {resp['resultCode'].prettyPrint()} - {resp['diagnosticMessage']}")
            else:
                self.logger.success(f"DNS record {self.record} ({self.data}) added")

        except Exception as e:
            self.logger.debug(f"Error adding DNS record: {e}")
            exit(1)

        return

    def clear_entry(self, context, connection):
        return

    def update_entry(self, context, connection):
        return
    
    def get_permission_name(self, mask):
        """Convert permission mask to readable names"""
        permissions = []
        
        if mask & 0x10000000:  # GENERIC_ALL
            permissions.append("Full Control")
        if mask & 0x40000000:  # GENERIC_WRITE
            permissions.append("Generic Write")
        if mask & 0x20000000:  # GENERIC_READ
            permissions.append("Generic Read")
        if mask & 0x00040000:  # WRITE_DACL
            permissions.append("Write DACL")
        if mask & 0x00080000:  # WRITE_OWNER
            permissions.append("Write Owner")
        if mask & 0x00000020:  # ADS_RIGHT_DS_WRITE_PROP
            permissions.append("Write Property")
        if mask & 0x00000001:  # ADS_RIGHT_DS_CREATE_CHILD
            permissions.append("Create Child")
        # if mask & 0x00000002:  # ADS_RIGHT_DS_DELETE_CHILD
        #     permissions.append("Delete Child")
        
        return ", ".join(permissions) if permissions else f"Unknown"
    
    def lookup_sids(self, connection, sids):
        """Lookup SIDs to get friendly names"""
        sid_to_name = {}
        
        if not sids:
            return sid_to_name
        
        try:
            string_binding = rf"ncacn_np:{connection.host}[\pipe\lsarpc]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(
                connection.username,
                connection.password,
                connection.domain,
                connection.lmhash,
                connection.nthash
            )
            rpctransport.set_connect_timeout(15)
            dce = rpctransport.get_dce_rpc()
            
            if connection.kerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            
            dce.connect()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.bind(lsat.MSRPC_UUID_LSAT)
        except Exception as e:
            self.logger.debug(f"Error connecting to {string_binding}: {e}")
            return sid_to_name
        
        try:
            policy_handle = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)["PolicyHandle"]
        except Exception as e:
            self.logger.debug(f"Unable to get policy handle: {e}")
            dce.disconnect()
            return sid_to_name
        
        try:
            resp = lsat.hLsarLookupSids(dce, policy_handle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        except DCERPCException as e:
            if str(e).find("STATUS_SOME_NOT_MAPPED") >= 0:
                resp = e.get_packet()
                self.logger.debug(f"Could not resolve some SIDs: {e}")
            else:
                resp = None
                self.logger.debug(f"Could not resolve SID(s): {e}")
        
        if resp:
            domains = resp["ReferencedDomains"]["Domains"]
            for sid, item in zip(sids, resp["TranslatedNames"]["Names"], strict=False):
                if item["DomainIndex"] >= 0:
                    domain_name = domains[item["DomainIndex"]]["Name"]
                    account_name = item["Name"]
                    sid_to_name[sid] = f"{domain_name}\\{account_name}"
                else:
                    sid_to_name[sid] = sid
        
        try:
            dce.disconnect()
        except:
            pass
        
        return sid_to_name
    
    def check_permissions(self, context, connection, perm_all=False):
        search_bases = {
            "DOMAIN": f"CN=MicrosoftDNS,DC=DomainDnsZones,{connection.baseDN}", # 90% use case
            "FOREST": f"CN=MicrosoftDNS,DC=ForestDnsZones,{connection.forestDN}", # multi domain
            "LEGACY": f"CN=MicrosoftDNS,CN=System,{connection.baseDN}" # old AD
        }

        for dns_type, search_base in search_bases.items():
            zones = []
            try:
                # Looking for every dnsZone object using 0x07 (owner, group, Dacl, Sacl)
                resp = connection.search(
                    searchFilter="(objectClass=dnsZone)",
                    attributes=["name", "nTSecurityDescriptor"],
                    baseDN=search_base,
                    searchControls=security_descriptor_control(sdflags=0x07)
                )
                zones += parse_result_attributes(resp)
            except Exception as e:
                self.logger.debug(f"Error during dnsZone ldap search : {e}")
                exit(1)

            for zone in zones:
                if zone is None:
                    continue
                zone_name = zone.get("name", "Unknown")
                self.logger.success(f"[{dns_type.upper()}] Zone: {zone_name}")

                if "nTSecurityDescriptor" in zone and zone["nTSecurityDescriptor"]:
                    nt_sec_desc = zone["nTSecurityDescriptor"]
                    
                    if isinstance(nt_sec_desc, list) and len(nt_sec_desc) > 0:
                        nt_sec_desc = nt_sec_desc[0]

                    try:
                        nt_sec = ldaptypes.SR_SECURITY_DESCRIPTOR(data=nt_sec_desc)
                        sid_permissions = defaultdict(list)
                        all_sids = []

                        if nt_sec["Dacl"]:
                            for ace in nt_sec["Dacl"].aces:
                                try:
                                    ace_mask = ace["Ace"]["Mask"]["Mask"]
                                    if ace_mask & (0x40000000 | 0x10000000 | 0x00040000 | 0x00000020 | 0x00000001):
                                        sid = ace["Ace"]["Sid"].formatCanonical()
                                        if sid not in all_sids:
                                            all_sids.append(sid)
                                        sid_permissions[sid].append(ace_mask)
                                except Exception as e:
                                    self.logger.debug(f"Error parsing Dacl : {e}")

                        # Lookup des SIDs
                        sid_names = self.lookup_sids(connection, all_sids)

                        # Display
                        for sid, masks in sid_permissions.items():
                            name = sid_names.get(sid, sid)
                            # 
                            combined_mask = 0
                            for mask in masks:
                                combined_mask |= mask
                            perms = self.get_permission_name(combined_mask)
                            if perm_all:
                                self.logger.highlight(f"\t- \"{name}\"")
                                self.logger.highlight(f"\t\t {perms}")
                            else:
                                self.logger.highlight(f"\t- \"{name}\"")

                    except Exception as e:
                        pass
        return

    def on_login(self, context, connection):

        if self.method == "PERM":
            self.logger.display("Getting DNS write permissions")
            self.check_permissions(context, connection)
        elif self.method == "PERM_ALL":
            self.logger.display("Getting DNS write permissions with display")
            self.check_permissions(context, connection, perm_all=True)
        elif self.method == "ADD":
            self.logger.display("Adding DNS entry")
            self.add_entry(context, connection)
        else:
            pass

        return
