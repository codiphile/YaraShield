rule Supply_Chain_Attack {
    meta:
        name = "Supply Chain Attack"
        description = "Detects modified packages that might be part of a supply chain attack"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "Critical"
    
    strings:
        $suspicious_npm = "npm.cmd install" nocase
        $suspicious_pip = "pip install -e" nocase
        $sus_package = "setup.py" nocase
        $sus_func1 = "os.system" nocase
        $sus_func2 = "subprocess.call" nocase
        $post_install = "postinstall" nocase
        $hidden_code = "eval(base64" nocase
    
    condition:
        $hidden_code or 
        ($post_install and 1 of ($sus_func*)) or
        (1 of ($suspicious_*) and 1 of ($sus_func*)) or
        ($sus_package and 1 of ($sus_func*))
}

rule Memory_Injection {
    meta:
        name = "Memory Injection Techniques"
        description = "Detects code attempting to inject payloads into process memory"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "Critical"
    
    strings:
        $inject_func1 = "VirtualAlloc" nocase
        $inject_func2 = "WriteProcessMemory" nocase
        $inject_func3 = "CreateRemoteThread" nocase
        $inject_func4 = "NtMapViewOfSection" nocase
        $inject_func5 = "mprotect" nocase
        $inject_tech1 = "process hollowing" nocase
        $inject_tech2 = "dll injection" nocase
        $shellcode = { 55 8B EC }  // Common x86 function prologue in shellcode
    
    condition:
        2 of ($inject_func*) or 
        1 of ($inject_tech*) or
        $shellcode
}

rule Fileless_Malware {
    meta:
        name = "Fileless Malware"
        description = "Detects fileless malware techniques that execute code without writing to disk"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "High"
    
    strings:
        $reg_run = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $wmi_exec = "wmic process call create" nocase
        $powershell_enc = "powershell -e" nocase
        $powershell_encoded = "powershell -EncodedCommand" nocase
        $reflective = "reflection.assembly" nocase
        $memory_exec = "IEX(" nocase wide
        $download_cradle = "New-Object Net.WebClient" nocase
    
    condition:
        2 of them
}

rule Advanced_Persistence {
    meta:
        name = "Advanced Persistence Mechanism"
        description = "Detects sophisticated persistence techniques"
        author = "YaraShield"
        date = "2023-03-09"
        severity = "High"
    
    strings:
        $schtask = "schtasks /create" nocase
        $wmi_persist = "Set-WmiInstance" nocase
        $startup_folder = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" nocase
        $service_create = "New-Service" nocase
        $backdoor_dll = "AppInit_DLLs" nocase
        $boot_execute = "bootexecute" nocase
        $registry_run = "CurrentVersion\\Run" nocase
    
    condition:
        2 of them
} 