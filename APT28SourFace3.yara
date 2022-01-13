rule SourFace
{
	meta:
		description = "APT28 SourFace FirstYaraRule"
		author = "Ben Lee"
		date = "2022-14-01"
	strings:
		$mz = "MZ"
		$IsPE32bits = { B8 4D 5A 00 00 [10-20] 81 38 50 45 00 00 [10-25] C3 }
		// Removed all instruc besides mov eax, 54Dh and compare dword ptr [eax],4550h to make more generic
	condition:
        $mz and $IsPE32bits
}
