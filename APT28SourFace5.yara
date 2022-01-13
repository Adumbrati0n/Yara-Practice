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
		$s0 = "coreshell.dll"
		$s1 = "Applicate"
	condition:
        $mz at 0 and all of ($s*)
}
