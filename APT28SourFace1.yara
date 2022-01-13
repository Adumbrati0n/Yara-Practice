rule SourFace
{
	meta:
		description = "APT28 SourFace FirstYaraRule"
		author = "Ben Lee"
		date = "2022-14-01"
	
	strings:
		$mz = "MZ"
		
	
	condition:
        $mz at 0
}
