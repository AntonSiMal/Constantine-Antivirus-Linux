rule Demons_EICAR_Standard_Test {
    meta:
        description = "Cadena estándar de prueba antivirus EICAR"
        threat_level = "Test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Demons_Reverse_Shell_Netcat {
    meta:
        description = "Detección de shell reversa netcat o ncat"
        threat_level = "High"
    strings:
        $nc1 = /nc(\.traditional|\.openbsd)?\s+-[e|c]\s+(\/bin\/)?(ba)?sh/ nocase
        $nc2 = /ncat\s+.*--exec\s+(\/bin\/)?(ba)?sh/ nocase
    condition:
        any of ($nc*)
}

rule Demons_Reverse_Shell_DevTcp {
    meta:
        description = "Shell reversa mediante /dev/tcp/"
        threat_level = "Critical"
    strings:
        $dt1 = "/dev/tcp/" ascii
        $dt2 = "0>&1" ascii
        $dt3 = "exec 5<>/dev/tcp/" ascii
    condition:
        ($dt1 and $dt2) or $dt3
}

rule Demons_Reverse_Shell_Python {
    meta:
        description = "Shell reversa en Python usando pty spawn y socket"
        threat_level = "High"
    strings:
        $py1 = "import socket" ascii
        $py2 = "pty.spawn" ascii
        $py3 = "os.dup2(s.fileno()" ascii
    condition:
        ($py1 and $py2) or ($py1 and $py3)
}

rule Demons_Ransomware_Extensions {
    meta:
        description = "Marcadores de extensiones y notas de rescate de ransomware"
        threat_level = "Critical"
    strings:
        $r1 = ".locked" ascii
        $r2 = ".lockbit" ascii
        $r3 = ".enc" ascii
        $r4 = "YOUR FILES ARE ENCRYPTED" nocase
        $r5 = "DECRYPT_FILES" nocase
    condition:
        2 of ($r*)
}

rule Demons_Cryptominer_Pools {
    meta:
        description = "Minero de criptomonedas no autorizado (XMRig / Stratum)"
        threat_level = "Medium"
    strings:
        $m1 = "stratum+tcp://" ascii
        $m2 = "stratum+ssl://" ascii
        $m3 = "xmrig" nocase
        $m4 = "donate.v2.xmrig.com" ascii
    condition:
        any of ($m*)
}
