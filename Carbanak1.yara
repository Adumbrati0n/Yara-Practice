/*
	wide for unicode str
*/
rule carbanak
{
	meta:
		description = "Yara Rule for Carbanak Malware Samples"
		author = "Ben Lee"
	strings:
		$mz = "MZ"
		$s0 = "wdigest.dll" wide
		$s1 = "dpapisrv.dll" wide                     
		$s2 = "f0531199_He68889o57J5.exe" 
		$s3 = "CryptProtectMemory" 
		$s4 = "Authentication Id : %u ; %u (%08x:%08x)" wide 
		$s5 = " * Username : %s" wide
		$s6 = " * Password : " wide
		$s7 = " * RootKey  : " wide
		$s8 = "NewCredentials" wide
		$s9 = "NetworkCleartext" wide 
		$s10 = "logonPasswords" wide 
		$s11 = "BAsXCFNZbVpfD14KAQ.bin"
	
	condition:
		$mz at 0 and 10 of ($s*)
		// can test with any of them, all of them, 2 of them, etc.
}
