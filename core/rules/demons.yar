rule Demons_Reverse_Shell_Netcat {
    meta:
        description = "Detección de shell reversa netcat o ncat"
        author = "Constantine Security Team"
        severity = "CRITICAL"
    strings:
        $nc1 = "nc -e" ascii wide nocase
        $nc2 = "ncat -e" ascii wide nocase
        $nc3 = "nc -c" ascii wide nocase
        $nc4 = "/bin/sh" ascii wide
        $nc5 = "/bin/bash" ascii wide
    condition:
        ($nc1 or $nc2 or $nc3) or ($nc4 and $nc1) or ($nc5 and $nc2) or ($nc4 and "nc ")
}

rule Demons_Reverse_Shell_DevTcp {
    meta:
        description = "Shell reversa mediante /dev/tcp/"
        author = "Constantine Security Team"
        severity = "CRITICAL"
    strings:
        $devtcp = "/dev/tcp/" ascii wide
        $bash = "bash -i" ascii wide
        $sh = "sh -i" ascii wide
    condition:
        $devtcp or ($bash and $devtcp) or ($sh and $devtcp)
}

rule Demons_Reverse_Shell_Python {
    meta:
        description = "Shell reversa en Python usando pty spawn y socket"
        author = "Constantine Security Team"
        severity = "CRITICAL"
    strings:
        $py1 = "pty.spawn" ascii wide
        $py2 = "socket.socket" ascii wide
        $py3 = "os.dup2" ascii wide
    condition:
        ($py1 and $py2) or ($py2 and $py3)
}

rule Demons_Cryptominer_Pools {
    meta:
        description = "Minero de criptomonedas no autorizado (XMRig / Stratum)"
        author = "Constantine Security Team"
        severity = "HIGH"
    strings:
        $s1 = "stratum+tcp://" ascii wide nocase
        $s2 = "stratum+ssl://" ascii wide nocase
        $s3 = "xmrig" ascii wide nocase
        $s4 = "cryptonight" ascii wide nocase
    condition:
        1 of ($s*)
}

rule Demons_EICAR_Standard_Test {
    meta:
        description = "Cadena estándar de prueba antivirus EICAR"
        author = "Constantine Security Team"
        severity = "INFORMATIONAL"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}
