rule Demons_EICAR_Standard_Test {
    meta:
        description = "Cadena estándar de prueba antivirus EICAR"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Demons_Reverse_Shell_Netcat {
    meta:
        description = "Detección de shell reversa netcat"
    strings:
        $nc1 = /nc(\.traditional|\.openbsd)?\s+-[e|c]\s+(\/bin\/)?(ba)?sh/ nocase
        $nc2 = /ncat\s+.*--exec\s+(\/bin\/)?(ba)?sh/ nocase
    condition:
        any of ($nc*)
}
