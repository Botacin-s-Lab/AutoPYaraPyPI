rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.570159765557392 Found in 1 files
		$x0 = { 5B 64 78 67 4C 7A 01 57 7F 41 47 53 1A 63 04 79 59 51 61 50 7E 78 07 05 77 72 06 54 67 5C 4D 0C 62 0D 6F 45 07 5D 02 65 5E 46 7B 6D 50 5E 61 4C 07 5F 56 50 44 6C 42 03 53 71 7D 4F 59 5A 7D 41 } //This might be a string? Looks like:[dxgLzWAGScyYQaP~xwrTg\Mb\roE]e^F{mP^aL_VPDlBSq}OYZ}A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.382659765557392 Found in 2 files
		$x1 = { 47 50 01 40 57 44 02 43 79 07 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B 7E 4C 0D 4F 7B 4F 46 1A 64 05 51 79 61 04 7B 6D 62 04 0C 5F 6F 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 } //This might be a string? Looks like:GP@WDCyC\rqwBFepMVW}Lx[~L\rO{OFdQya{mb_oACVQSz}\aY

		condition:
(1 of ($x0,$x1) )}