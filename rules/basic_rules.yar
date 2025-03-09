rule Basic_Malware_Detector  
{
    meta:
        description = "Detects a simple malware signature"
        author = "Mudit Sharma"
        date = "2025-03-01"

    strings:
        $malicious_string1 = "malicious_function"
        $malicious_string2 = "hacker_tool"

    condition:
        any of them
}