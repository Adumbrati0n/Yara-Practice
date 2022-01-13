rule SourFace
{
	meta:
		description = "APT28 SourFace FirstYaraRule"
		author = "Ben Lee"
		date = "2022-14-01"
	strings:
		$mz = "MZ"
		$IsPE32bits = {8B FF 55 8B EC 8B 4D 08 B8 4D 5A 00 00 66 39 01 74 04 33 C0 5D C3 8B 41 3C 03 C1 81 38 50 45 00
		00 75 EF 33 D2 B9 0B 01 00 00 66 39 48 18 0F 94 C2 8B C2 5D C3 }  
	condition:
        $mz and $IsPE32bits
}
