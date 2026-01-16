rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x1 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x2 = { 0D 04 40 01 10 5F 5E C9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x3 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 2 files
		$x4 = { 77 04 74 72 78 74 51 74 } //This might be a string? Looks like:wtrxtQt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x5 = { 00 45 51 72 59 5D 57 72 } //This might be a string? Looks like:EQrY]Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x6 = { 72 01 74 54 64 77 05 74 } //This might be a string? Looks like:rtTdwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x7 = { 40 63 72 5D 4C 57 06 51 } //This might be a string? Looks like:@cr]LWQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x8 = "RwEtrBto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x9 = { 50 58 73 05 54 62 0C 40 } //This might be a string? Looks like:PXsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x10 = "cr]Lobs^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x11 = { 56 58 73 05 54 62 0C 40 } //This might be a string? Looks like:VXsTb@

		condition:
(9 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11) )}