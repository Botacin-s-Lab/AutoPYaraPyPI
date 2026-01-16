rule testrules
{
	//Input TP Rate:
	//2/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x13 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x14 = { 47 00 02 07 01 03 52 1E } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 63 1E 79 4D 59 00 57 42 } //This might be a string? Looks like:cyMYWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x1 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x15 = { 04 41 54 62 7B 4C 57 06 } //This might be a string? Looks like:ATb{LW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x4 = { 40 51 58 59 4C 57 07 00 } //This might be a string? Looks like:@QXYLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x10 = { 7F 43 6C 07 63 4F 56 05 } //This might be a string? Looks like:ClcOV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x11 = "arYATmdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x12 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x2 = { 00 45 51 72 59 5D 57 72 } //This might be a string? Looks like:EQrY]Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x3 = "t}Q`@RFs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x5 = "RwEtrBto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x6 = "_dbg^VXc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x7 = { 72 01 74 54 64 77 05 74 } //This might be a string? Looks like:rtTdwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x16 = { 40 63 72 5D 4C 57 06 51 } //This might be a string? Looks like:@cr]LWQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x8 = "r]Lobs^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x9 = "cr]Lobs^" ascii

		condition:
(12 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11) ) or (5 of ($x12,$x13,$x14,$x15,$x16) )}