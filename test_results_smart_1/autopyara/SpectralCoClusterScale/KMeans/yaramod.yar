rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x10 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x11 = { 0D 04 40 01 10 5F 5E C9 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 63 1E 79 4D 59 00 57 42 } //This might be a string? Looks like:cyMYWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x13 = { 04 41 54 62 7B 4C 57 06 } //This might be a string? Looks like:ATb{LW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x15 = { 72 4D 45 6C 07 73 05 54 } //This might be a string? Looks like:rMElsT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x9 = { 7F 43 6C 07 63 4F 56 05 } //This might be a string? Looks like:ClcOV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x16 = "arYATmdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x17 = { 4F 6C 06 7F 45 56 7D 67 } //This might be a string? Looks like:OlEV}g
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x18 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x19 = { 00 45 51 72 59 5D 57 72 } //This might be a string? Looks like:EQrY]Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x20 = "t}Q`@RFs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x7 = "Pr{YV}gE" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x24 = "cr]Lobs^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x25 = { 60 01 77 5C 0D 72 6F 52 } //This might be a string? Looks like:`w\\rroR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x12 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x14 = { 40 51 58 59 4C 57 07 00 } //This might be a string? Looks like:@QXYLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x1 = { 50 58 73 05 54 62 0C 40 } //This might be a string? Looks like:PXsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x2 = { 72 01 74 54 64 77 05 74 } //This might be a string? Looks like:rtTdwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x21 = "_dbg^VXc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x22 = "RwEtrBto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x23 = "]VXsAomg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x3 = { 67 45 57 07 00 72 54 62 } //This might be a string? Looks like:gEWrTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x4 = { 59 5E 47 42 6D 64 5C 7E } //This might be a string? Looks like:Y^GBmd\~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x5 = { 72 6C 7E 46 70 0D 7A 5C } //This might be a string? Looks like:rl~Fp\rz\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x6 = { 01 7C 5C 77 4F 51 72 73 } //This might be a string? Looks like:|\wOQrs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x8 = { 56 58 73 05 54 62 0C 40 } //This might be a string? Looks like:VXsTb@

		condition:
(8 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9) ) or (11 of ($x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25) )}