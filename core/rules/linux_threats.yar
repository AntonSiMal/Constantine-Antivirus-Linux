/*
   Constantine Antivirus - Linux Threats & Rootkit Signatures (core/rules/linux_threats.yar)
   Reglas YARA de alta precisión para amenazas avanzadas en entornos Linux.
*/

rule Linux_Rootkit_LdPreload_Tampering {
    meta:
        description = "Intento de secuestro de llamadas de sistema mediante /etc/ld.so.preload"
        threat_level = "Critical"
        author = "Constantine Security Team"
    strings:
        $preload = "/etc/ld.so.preload" ascii
        $dlopen = "dlsym" ascii
        $intercept1 = "sys_call_table" ascii
        $intercept2 = "__libc_dlopen" ascii
    condition:
        $preload and ($dlopen or $intercept1 or $intercept2)
}

rule Linux_Reptile_Rootkit_Signatures {
    meta:
        description = "Firmas del rootkit kernel Reptile LKM"
        threat_level = "Critical"
        author = "Constantine Security Team"
    strings:
        $rep1 = "reptile" nocase ascii
        $rep2 = "reptile_cmd" ascii
        $rep3 = "r00t" ascii
        $rep4 = "/reptile/reptile" ascii
    condition:
        2 of ($rep*)
}

rule Linux_Diamorphine_Rootkit_Signatures {
    meta:
        description = "Módulo de kernel malicioso LKM Diamorphine"
        threat_level = "Critical"
        author = "Constantine Security Team"
    strings:
        $dia1 = "diamorphine" nocase ascii
        $dia2 = "diamorphine_init" ascii
        $dia3 = "hiding_proc" ascii
        $dia4 = "give_root" ascii
    condition:
        2 of ($dia*)
}

rule Linux_Backdoor_AuthorizedKeys_Injection {
    meta:
        description = "Script de inyección encubierta en authorized_keys de SSH"
        threat_level = "High"
        author = "Constantine Security Team"
    strings:
        $ssh1 = ".ssh/authorized_keys" ascii
        $ssh2 = "ssh-rsa AAAAB3NzaC1yc2E" ascii
        $curl = /curl\s+-[sSLfk].*\|\s*(ba)?sh/ ascii
        $wget = /wget\s+-[qO].*\|\s*(ba)?sh/ ascii
    condition:
        $ssh1 and ($ssh2 or $curl or $wget)
}

rule Linux_Persistence_Cron_Backdoor {
    meta:
        description = "Persistencia maliciosa en tareas programadas cron / spool"
        threat_level = "High"
        author = "Constantine Security Team"
    strings:
        $cron1 = "/etc/cron.d/" ascii
        $cron2 = "/var/spool/cron/" ascii
        $sh1 = "* * * * *" ascii
        $rev1 = "/dev/tcp/" ascii
        $rev2 = "nc -e" ascii
        $rev3 = "python -c 'import socket" ascii
    condition:
        ($cron1 or $cron2) and $sh1 and ($rev1 or $rev2 or $rev3)
}

rule Linux_Botnet_Mirai_Mozi_Patterns {
    meta:
        description = "Comportamiento del gusano botnet Mirai o Mozi para Linux IoT/Servers"
        threat_level = "Critical"
        author = "Constantine Security Team"
    strings:
        $m1 = "/bin/busybox" ascii
        $m2 = "POST /cdn-cgi/" ascii
        $m3 = "dvrHelper" ascii
        $m4 = "echo -e '\\x" ascii
        $m5 = "iptables -F" ascii
    condition:
        3 of ($m*)
}
