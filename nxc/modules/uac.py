from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "uac"
    description = "Check, enable or disable UAC status"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        self.action = None

    def options(self, context, module_options):
        """
        ACTION      Action to perform: 'enable' or 'disable' (default: just check)

        Examples:
            -o ACTION=disable
            -o ACTION=enable
        """
        if "ACTION" in module_options:
            self.action = module_options["ACTION"].lower()
            if self.action not in ("enable", "disable"):
                context.log.fail("ACTION doit être 'enable' ou 'disable'")
                self.action = None

    def on_admin_login(self, context, connection):
        remoteOps = RemoteOperations(connection.conn, False)
        remoteOps.enableRegistry()

        ans = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
        regHandle = ans["phKey"]
        ans = rrp.hBaseRegOpenKey(
            remoteOps._RemoteOperations__rrp,
            regHandle,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            samDesired=rrp.MAXIMUM_ALLOWED
        )
        keyHandle = ans["phkResult"]
        dataType, uac_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "EnableLUA")

        status = "Enabled" if uac_value == 1 else "Disabled"
        context.log.highlight(f"UAC Status: {uac_value} (UAC {status})")

        if self.action == "disable":
            if uac_value == 0:
                context.log.warning("UAC already disable.")
            else:
                try:
                    rrp.hBaseRegSetValue(
                        remoteOps._RemoteOperations__rrp,
                        keyHandle,
                        "EnableLUA",
                        rrp.REG_DWORD,
                        0
                    )
                    context.log.success("UAC disabled.")
                except Exception as e:
                    context.log.fail(f"Error : {e}")

        elif self.action == "enable":
            if uac_value == 1:
                context.log.warning("UAC already enable.")
            else:
                try:
                    rrp.hBaseRegSetValue(
                        remoteOps._RemoteOperations__rrp,
                        keyHandle,
                        "EnableLUA",
                        rrp.REG_DWORD,
                        1
                    )
                    context.log.success("UAC enabled.")
                except Exception as e:
                    context.log.fail(f"Error : {e}")

        rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, keyHandle)
        remoteOps.finish()

