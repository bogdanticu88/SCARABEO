/* Starter YARA rules for SCARABEO */

rule Scarabeo_Suspicious_Strings {
    meta:
        description = "Detects suspicious strings commonly found in malware"
        author = "SCARABEO Team"
        date = "2024-01-01"
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "WriteProcessMemory" ascii
    condition:
        any of them
}

rule Scarabeo_Network_Indicators {
    meta:
        description = "Detects network-related API calls"
        author = "SCARABEO Team"
    strings:
        $s1 = "InternetOpen" ascii
        $s2 = "URLDownloadToFile" ascii
        $s3 = "WinHttpOpen" ascii
    condition:
        any of them
}

rule Scarabeo_Registry_Access {
    meta:
        description = "Detects registry manipulation APIs"
        author = "SCARABEO Team"
    strings:
        $s1 = "RegSetValue" ascii
        $s2 = "RegCreateKey" ascii
        $s3 = "RegDeleteKey" ascii
    condition:
        any of them
}
