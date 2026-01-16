rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x0 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x1 = { 0D 04 40 01 10 5F 5E C9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x2 = { 63 1E 79 4D 59 00 57 42 } //This might be a string? Looks like:cyMYWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x3 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x4 = { 04 41 54 62 7B 4C 57 06 } //This might be a string? Looks like:ATb{LW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x5 = { 40 51 58 59 4C 57 07 00 } //This might be a string? Looks like:@QXYLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x6 = { 72 4D 45 6C 07 73 05 54 } //This might be a string? Looks like:rMElsT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x7 = "arYATmdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x8 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x9 = { 4F 6C 06 7F 45 56 7D 67 } //This might be a string? Looks like:OlEV}g
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x10 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x11 = { 00 45 51 72 59 5D 57 72 } //This might be a string? Looks like:EQrY]Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x12 = "_dbg^VXc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x13 = { 72 01 74 54 64 77 05 74 } //This might be a string? Looks like:rtTdwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x14 = { 40 63 72 5D 4C 57 06 51 } //This might be a string? Looks like:@cr]LWQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x15 = "RwEtrBto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x16 = { 50 58 73 05 54 62 0C 40 } //This might be a string? Looks like:PXsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x17 = "r]Lobs^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x18 = "]VXsAomg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x19 = { 01 7C 5C 77 4F 51 72 73 } //This might be a string? Looks like:|\wOQrs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x20 = "Pr{YV}gE" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x21 = "cr]Lobs^" ascii

		condition:
(14 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21) )}