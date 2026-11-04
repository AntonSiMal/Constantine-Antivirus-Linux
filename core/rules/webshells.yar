/*
   Constantine Antivirus - Web Shells & Application Backdoors (core/rules/webshells.yar)
*/

rule WebShell_PHP_Dynamic_Execution {
    meta:
        description = "Web shell PHP con ofuscación y ejecución dinámica eval/assert/base64"
        threat_level = "Critical"
        author = "Constantine Security Team"
    strings:
        $eval = "eval(" ascii nocase
        $assert = "assert(" ascii nocase
        $b64 = "base64_decode(" ascii nocase
        $gz = "gzinflate(" ascii nocase
        $post = "$_POST[" ascii
        $req = "$_REQUEST[" ascii
    condition:
        ($eval or $assert) and ($b64 or $gz) and ($post or $req)
}

rule WebShell_Generic_Admin_Panel {
    meta:
        description = "Panel de control de webshell común (c99, b374k, r57, WSO)"
        threat_level = "High"
        author = "Constantine Security Team"
    strings:
        $s1 = "c99shell" nocase ascii
        $s2 = "b374k" nocase ascii
        $s3 = "WSOset" ascii
        $s4 = "FilesMan" ascii
        $s5 = "Sec. Info" ascii
    condition:
        2 of ($s*)
}

rule WebShell_JSP_Exec_Backdoor {
    meta:
        description = "Web shell JSP para servidores Apache Tomcat / Jetty"
        threat_level = "Critical"
        author = "Constantine Security Team"
    strings:
        $jsp1 = "<%@ page import=" ascii
        $jsp2 = "Runtime.getRuntime().exec(" ascii
        $jsp3 = "ProcessBuilder" ascii
        $jsp4 = "request.getParameter(" ascii
    condition:
        $jsp1 and ($jsp2 or $jsp3) and $jsp4
}
