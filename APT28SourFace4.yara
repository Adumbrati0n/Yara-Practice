/* 
Ida --> View --> Open Subviews --> Strings for distinctive in malware, e.g: Coreshell.dll
*/
rule SourFace
{
	meta:
		description = "APT28 SourFace FirstYaraRule"
		author = "Ben Lee"
		date = "2022-14-01"
	strings:
		$mz = "MZ"
		$IsPE32bits = { B8 4D 5A 00 00 [10-20] 81 38 50 45 00 00 [10-25] C3 }
		$s0 = "coreshell.dll"
		$s1 = "Applicate"
	condition:
        $mz at 0 and ( $IsPE32bits or (all of ($s*)))
}
