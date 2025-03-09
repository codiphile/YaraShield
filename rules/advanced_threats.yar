rule Backdoor_Detection {
    meta:
        name = "Backdoor Malware"
        description = "Detects common backdoor and remote access tools"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "Critical"
    
    strings:
        $backdoor_str1 = "cmd.exe /c" nocase
        $backdoor_str2 = "reverse shell" nocase
        $backdoor_str3 = "netcat" nocase
        $backdoor_str4 = "connect-back" nocase
        $backdoor_str5 = "bind shell" nocase
        $backdoor_cmd1 = "nc -e" nocase
        $backdoor_cmd2 = "rundll32.exe" nocase
        $network_cmd = "socket.connect" nocase
    
    condition:
        3 of them
}

rule Cryptominer_Detection {
    meta:
        name = "Cryptomining Malware"
        description = "Detects cryptominers and cryptocurrency mining code"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "High"
    
    strings:
        $miner_str1 = "stratum+tcp://" nocase
        $miner_str2 = "xmrig" nocase
        $miner_str3 = "cpuminer" nocase
        $miner_str4 = "cryptonight" nocase
        $miner_str5 = "monero" nocase
        $wallet_pattern = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ // Bitcoin/crypto wallet pattern
        $high_cpu = "SetThreadPriority" nocase
    
    condition:
        2 of them
}

rule Data_Exfiltration {
    meta:
        name = "Data Exfiltration Tool"
        description = "Detects tools used to steal and exfiltrate data"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "High"
    
    strings:
        $exfil_str1 = "upload" nocase
        $exfil_str2 = "ftp://" nocase
        $exfil_str3 = "sftp://" nocase
        $exfil_str4 = "PUT /" nocase
        $exfil_str5 = "POST /upload" nocase
        $exfil_str6 = ".zip password" nocase
        $exfil_str7 = "pastebin.com" nocase
        $exfil_func = "Base64Encode" nocase
    
    condition:
        3 of them
}

rule Rootkit_Detection {
    meta:
        name = "Rootkit Component"
        description = "Detects common rootkit components and techniques"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "Critical"
    
    strings:
        $root_str1 = "hide process" nocase
        $root_str2 = "hide file" nocase
        $root_str3 = "intercept syscall" nocase
        $root_str4 = "kernel mode" nocase
        $root_str5 = "hook system" nocase
        $root_func1 = "ZwQuerySystemInformation" nocase
        $root_func2 = "EnumProcesses" nocase
        $root_func3 = "NtCreateFile" nocase
    
    condition:
        2 of them
} 