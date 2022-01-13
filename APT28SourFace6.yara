rule SourFace
{
	meta:
		description = "APT28 SourFace FirstYaraRule"
		author = "Ben Lee"
		date = "2022-14-01"
	strings:
		$mz = "MZ"
		$applicate = { 68 10 27 00 00 FF 15 ?? ?? 00 10 E8 ?? ?? FF FF A1 EC B0 00 10 6A FF 50 FF 15 ?? ?? 00 10 33 C0}
		$s0 = "coreshell.dll"
		$s1 = "Applicate"
	condition:
        $mz at 0 and 2 of them
}
