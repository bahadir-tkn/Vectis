/*
 ==============================================================================
 CoreSync USB Gatekeeper - Gömülü YARA Kural Seti
 ------------------------------------------------------------------------------
 Air-Gapped Korumalı Harici Depolama Zararlı Taraması
 Hedefler:
   1. USB Kısayol Solucanları (LNK Droppers / Raspberry Robin / Houdini)
   2. VBScript ve JScript Solucan / Taşıyıcıları
   3. Kötü Amaçlı Autorun.inf Direktifleri
   4. Gizlenmiş ve Sahte Uzantılı PE İkilileri
   5. Batch / PowerShell Gizli İndirici (Stager) Kalıpları
   6. RTLO (Right-to-Left Override - \u202E) Dosya Adı Aldatmacası
 ==============================================================================
*/

rule USB_Shortcut_Dropper_LNK {
    meta:
        description = "Zararlı komut satırı (CMD/PowerShell/WScript) çalıştıran LNK kısayol solucanı"
        severity = "CRITICAL"
        threat_type = "Shortcut_Worm_Dropper"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "%comspec%" nocase
        $ps1 = "powershell" nocase
        $ps2 = "pwsh" nocase
        $ws1 = "wscript.exe" nocase
        $ws2 = "cscript.exe" nocase
        $mshta = "mshta" nocase
        $rundll = "rundll32" nocase
        $certutil = "certutil" nocase

        $arg_hidden1 = "-windowstyle hidden" nocase
        $arg_hidden2 = "-w hidden" nocase
        $arg_enc1 = "-enc " nocase
        $arg_enc2 = "-encodedcommand" nocase
        $arg_b64 = "frombase64string" nocase
        $arg_iex = "iex" nocase
        $arg_start = "/c start" nocase
    condition:
        $lnk_magic and ($cmd1 or $cmd2 or $ps1 or $ps2 or $ws1 or $ws2 or $mshta or $rundll or $certutil) and ($arg_hidden1 or $arg_hidden2 or $arg_enc1 or $arg_enc2 or $arg_b64 or $arg_iex or $arg_start)
}

rule USB_RaspberryRobin_LNK_Worm {
    meta:
        description = "Raspberry Robin ve türevi USB yayılan MSIEXEC/Rundll32 LNK solucanı"
        severity = "CRITICAL"
        threat_type = "RaspberryRobin_Variant"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $msi1 = "msiexec" nocase
        $msi2 = "/q /i" nocase
        $msi3 = "-q -i" nocase
        $shell_run = "ShellExec_RunDLL" nocase
        $http = "http://" nocase
        $https = "https://" nocase
    condition:
        $lnk_magic and ($msi1 or $shell_run) and ($msi2 or $msi3 or $http or $https)
}

rule USB_VBS_JS_Worm_Dropper {
    meta:
        description = "USB sürücülere yayılan VBScript veya JScript tabanlı solucan/dropper"
        severity = "HIGH"
        threat_type = "Script_Worm"
    strings:
        $ws_shell = "wscript.shell" nocase
        $fso = "scripting.filesystemobject" nocase
        $drivetype1 = "drivetype = 1" nocase
        $drivetype2 = "drivetype == 1" nocase
        $removable = "removable" nocase
        $attrib = "attrib +h +s" nocase
        $autorun = "autorun.inf" nocase
        $run_reg = "currentversion\\run" nocase
        $copy_file = "copyfile" nocase
    condition:
        ($ws_shell or $fso) and ($drivetype1 or $drivetype2 or $removable or $attrib) and ($run_reg or $autorun or $copy_file)
}

rule USB_Autorun_Malware_Inf {
    meta:
        description = "USB kök dizininde otomatik yürütme (AutoRun) tetikleyen şüpheli yönerge"
        severity = "HIGH"
        threat_type = "Autorun_Execution"
    strings:
        $sec1 = "[autorun]" nocase
        $sec2 = "[AutoRun]"
        $open = "open=" nocase
        $shellexec = "shellexecute=" nocase
        $action = "action=" nocase
        $cmd = "shell\\open\\command=" nocase

        $target_exe = ".exe" nocase
        $target_vbs = ".vbs" nocase
        $target_bat = ".bat" nocase
        $target_cmd = ".cmd" nocase
        $target_scr = ".scr" nocase
        $target_pif = ".pif" nocase
    condition:
        ($sec1 or $sec2) and ($open or $shellexec or $action or $cmd) and ($target_exe or $target_vbs or $target_bat or $target_cmd or $target_scr or $target_pif)
}

rule USB_Batch_Powershell_Stager {
    meta:
        description = "Gizli PowerShell veya Certutil çalıştıran şüpheli Batch stager scripti"
        severity = "HIGH"
        threat_type = "Batch_Stager"
    strings:
        $echo_off = "@echo off" nocase
        $ps_bypass = "-executionpolicy bypass" nocase
        $ps_ep = "-ep bypass" nocase
        $ps_w = "-w hidden" nocase
        $certutil_dec = "certutil -decode" nocase
        $bits_trans = "bitsadmin /transfer" nocase
        $curl_o = "curl -o" nocase
        $mshta_vbs = "mshta vbscript:" nocase
    condition:
        ($echo_off or $mshta_vbs) and ($ps_bypass or $ps_ep or $ps_w or $certutil_dec or $bits_trans or $curl_o)
}

rule USB_RTLO_Filename_Spoofing {
    meta:
        description = "Dosya uzantısını ters çevirmek için kullanılan RTLO (Right-to-Left Override) Unicode karakteri"
        severity = "CRITICAL"
        threat_type = "RTLO_Spoofing"
    strings:
        // Unicode U+202E (E2 80 AE)
        $rtlo_utf8 = { E2 80 AE }
        // Unicode U+202E UTF-16LE (2E 20)
        $rtlo_utf16 = { 2E 20 }
    condition:
        $rtlo_utf8 or $rtlo_utf16
}

rule USB_Suspicious_PowerShell_Encoded {
    meta:
        description = "Base64 veya gzip ile sıkıştırılmış gizli PowerShell yükü"
        severity = "HIGH"
        threat_type = "Encoded_PowerShell"
    strings:
        $b64_from = "FromBase64String" nocase
        $gzip = "IO.Compression.GzipStream" nocase
        $decompress = "Decompress" nocase
        $down_str = "DownloadString" nocase
        $down_file = "DownloadFile" nocase
        $webclient = "Net.WebClient" nocase
    condition:
        ($b64_from or $gzip or $decompress) and ($down_str or $down_file or $webclient)
}

rule EICAR_Standard_Test_File {
    meta:
        description = "EICAR Standart Antivirüs Test İmzası (Doğrulama ve Sentetik Test)"
        severity = "CRITICAL"
        threat_type = "EICAR_Test_Virus"
    strings:
        $eicar_full = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase
        $eicar_sub = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase
    condition:
        $eicar_full or $eicar_sub
}

