# ==============================================================================
# CONSTANTINE COMMUNITY YARA SIGNATURE FEED
# Sources: Neo23x0 Signature Base, YARA-Rules Project, AlienVault OTX
# Categories: Webshells, Ransomware Artifacts, C2 Frameworks, Privilege Escalation
# ==============================================================================

rule Community_Generic_PHP_Webshell {
    meta:
        description = "Detección comunitaria de webshells PHP (c99, r57, WSO, b374k, eval base64)"
        author = "Neo23x0 / Community Ruleset"
        severity = "CRITICAL"
        category = "Webshell"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $s1 = "eval(base64_decode(" ascii wide nocase
        $s2 = "eval(gzinflate(base64_decode(" ascii wide nocase
        $s3 = "assert(base64_decode(" ascii wide nocase
        $s4 = "c99shell" ascii wide nocase
        $s5 = "r57shell" ascii wide nocase
        $s6 = "b374k" ascii wide nocase
        $s7 = "WSOsetcookie" ascii wide
        $s8 = "passthru($_POST" ascii wide nocase
        $s9 = "system($_GET" ascii wide nocase
    condition:
        1 of ($s*)
}

rule Community_Ransomware_Note_Markers {
    meta:
        description = "Patrones de notas de rescate y artefactos característicos de ransomware"
        author = "Community Threat Research"
        severity = "CRITICAL"
        category = "Ransomware"
    strings:
        $r1 = "Your files have been encrypted" ascii wide nocase
        $r2 = "Todos sus archivos han sido cifrados" ascii wide nocase
        $r3 = "All your data has been locked" ascii wide nocase
        $r4 = "decrypt your files" ascii wide nocase
        $r5 = "Tor Browser" ascii wide nocase
        $r6 = ".onion" ascii wide nocase
        $r7 = "pay bitcoin to" ascii wide nocase
        $r8 = "restore your documents" ascii wide nocase
    condition:
        ($r1 or $r2 or $r3) and ($r4 or $r5 or $r6 or $r7 or $r8)
}

rule Community_C2_Framework_Sliver_Cobalt {
    meta:
        description = "Indicadores y artefactos de frameworks C2 populares (Cobalt Strike, Sliver, Havoc, Metasploit)"
        author = "AlienVault OTX / Community Feed"
        severity = "CRITICAL"
        category = "C2_Framework"
    strings:
        $cs1 = "%s as %s\\%s: %d" ascii
        $cs2 = "ReflectiveLoader" ascii
        $sl1 = "sliverpb.Envelope" ascii
        $sl2 = "github.com/bishopfox/sliver" ascii
        $hv1 = "HavocDemon" ascii
        $ms1 = "meterpreter" ascii wide nocase
        $ms2 = "metsrv.dll" ascii wide
    condition:
        1 of ($cs*) or 1 of ($sl*) or $hv1 or 1 of ($ms*)
}

rule Community_Linux_Rootkit_LKM_Hooking {
    meta:
        description = "Firmas de detección de rootkits Linux en espacio de kernel (LKM sys_call_table tampering)"
        author = "Constantine Community Defense"
        severity = "CRITICAL"
        category = "Rootkit"
    strings:
        $k1 = "sys_call_table" ascii
        $k2 = "kallsyms_lookup_name" ascii
        $k3 = "fh_install_hook" ascii
        $k4 = "module_hide" ascii
        $k5 = "rootkit_init" ascii
        $k6 = "/proc/buddyinfo" ascii
    condition:
        ($k1 and $k2) or ($k3 and $k4) or ($k5 and $k1)
}

rule Community_Privilege_Escalation_LinPEAS {
    meta:
        description = "Scripts automatizados de enumeración y elevación de privilegios hostil (LinPEAS / LinEnum)"
        author = "Constantine Security Team"
        severity = "HIGH"
        category = "Privilege_Escalation"
    strings:
        $lp1 = "LinPEAS" ascii wide
        $lp2 = "carlospolop" ascii wide nocase
        $lp3 = "PEASS-ng" ascii wide
        $le1 = "LinEnum.sh" ascii wide
        $le2 = "rebootroot" ascii wide
    condition:
        1 of ($lp*) or 1 of ($le*)
}
