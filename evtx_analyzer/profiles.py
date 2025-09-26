from typing import Dict, Set


class Profile:
    def __init__(self, ids_by_channel: Dict[str, Set[str]]):
        self.ids_by_channel = ids_by_channel


def get_profile(name: str) -> Profile:
    name_l = name.lower()
    if name_l in ("ir-default", "default", "ir"):
        return Profile({
            'Security': {str(x) for x in [
                4624, 4625, 4634, 4647, 4648, 4672, 4719, 1102,
                4688, 4689, 4697,
                4698, 4699, 4700, 4701, 4702,
                4720, 4726, 4732, 4733, 4756, 4767,
                4768, 4769, 4771, 4776, 4779,
                4798, 4799,
                4820, 4821, 4822, 4823, 4824,
                4964,
                5140, 5145,
                7045,
            ]},
            'Microsoft-Windows-Sysmon/Operational': {str(x) for x in [1, 2, 3, 7, 8, 10, 11, 12, 13, 22, 23, 24, 25]},
            'Microsoft-Windows-PowerShell/Operational': {str(x) for x in [4103, 4104, 600]},
            'Microsoft-Windows-WMI-Activity/Operational': {str(x) for x in [5857, 5858, 5859, 5860, 5861]},
            'Microsoft-Windows-Windows Defender/Operational': {str(x) for x in [1116, 1117, 5007]},
            'Microsoft-Windows-TaskScheduler/Operational': {str(x) for x in [106, 140, 141]},
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': {str(x) for x in [21, 23, 24, 25]},
            'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational': {str(x) for x in [131, 140]},
            'Microsoft-Windows-WinRM/Operational': {str(x) for x in [91]},
            'Microsoft-Windows-AppLocker/EXE and DLL': {str(x) for x in [8002, 8003, 8004]},
            'Microsoft-Windows-AppLocker/MSI and Script': {str(x) for x in [8006, 8007]},
            'System': {str(x) for x in [7036, 7040, 7045]},
        })
    if name_l in ("ir-minimal", "minimal", "low-noise"):
        return Profile({
            'Security': {str(x) for x in [1102, 4719, 4672, 4648, 4625, 4697, 4698, 4702, 7045]},
            'Microsoft-Windows-Sysmon/Operational': {str(x) for x in [1, 3, 7, 10, 11, 13, 22]},
            'Microsoft-Windows-PowerShell/Operational': {str(x) for x in [4104]},
            'Microsoft-Windows-WMI-Activity/Operational': {str(x) for x in [5858, 5859]},
            'System': {str(x) for x in [7040, 7045]},
        })
    if name_l in ("forensics-all", "forensics", "all"):
        return Profile({
            # Security: a wide net including access, policy, auth, shares, registry, scheduled tasks
            'Security': {str(x) for x in [
                4624, 4625, 4634, 4647, 4648, 4672,
                4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702,
                4719, 4720, 4722, 4723, 4724, 4725, 4726,
                4732, 4733, 4738, 4740,
                4756, 4767,
                4768, 4769, 4771, 4776, 4779,
                4798, 4799,
                4818, 4820, 4821, 4822, 4823, 4824,
                4964,
                5140, 5142, 5143, 5144, 5145,
                1102, 7045,
            ]},
            # Sysmon: include most useful operational IDs
            'Microsoft-Windows-Sysmon/Operational': {str(x) for x in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 22, 23, 24, 25, 26]},
            # PowerShell comprehensive
            'Microsoft-Windows-PowerShell/Operational': {str(x) for x in [40961, 4100, 4103, 4104, 600]},
            # Script Block logs may appear under different providers on some systems
            'Microsoft-Windows-TaskScheduler/Operational': {str(x) for x in [100, 101, 102, 106, 140, 141, 200, 201]},
            'Microsoft-Windows-WMI-Activity/Operational': {str(x) for x in [5857, 5858, 5859, 5860, 5861]},
            'Microsoft-Windows-Windows Defender/Operational': {str(x) for x in [1006, 1013, 1116, 1117, 5001, 5007]},
            'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': {str(x) for x in [21, 23, 24, 25]},
            'Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational': {str(x) for x in [131, 140]},
            'Microsoft-Windows-WinRM/Operational': {str(x) for x in [6, 35, 91]},
            'Microsoft-Windows-AppLocker/EXE and DLL': {str(x) for x in [8002, 8003, 8004]},
            'Microsoft-Windows-AppLocker/MSI and Script': {str(x) for x in [8006, 8007]},
            'System': {str(x) for x in [5038, 7034, 7035, 7036, 7040, 7045]},
            # DNS Client events indicative of resolution anomalies
            'Microsoft-Windows-DNS-Client/Operational': {str(x) for x in [3008, 3009, 3010]},
            # PrintService often abused; include errors/installs
            'Microsoft-Windows-PrintService/Admin': {str(x) for x in [372, 808, 4909, 4910]},
        })
    return Profile({})
