rule testrules
{
	//Input TP Rate:
	//5/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x0 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x1 = { 72 63 4F 6C 06 7F 45 56 } //This might be a string? Looks like:rcOlEV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x2 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x3 = { 63 4C 56 07 59 43 57 5F } //This might be a string? Looks like:cLVYCW_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x4 = { 40 51 58 59 4C 57 07 00 } //This might be a string? Looks like:@QXYLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x5 = { 72 4D 45 6C 07 73 05 54 } //This might be a string? Looks like:rMElsT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x6 = { 57 42 77 4F 74 72 0D 74 } //This might be a string? Looks like:WBwOtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x7 = { 5B 6F 45 56 58 0C 40 57 } //This might be a string? Looks like:[oEVX@W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x8 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x9 = { 4C 6F 62 00 05 63 72 5D } //This might be a string? Looks like:Lobcr]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x10 = "wbtr`tVR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x11 = "OfClearB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x12 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x13 = { 00 45 51 72 59 5D 57 72 } //This might be a string? Looks like:EQrY]Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x14 = { 50 58 73 05 54 62 0C 40 } //This might be a string? Looks like:PXsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x15 = "Pr{YV}gE" ascii

		condition:
(11 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15) )}