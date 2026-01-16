rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 4F 6C 06 7F 45 56 7D 67 } //This might be a string? Looks like:OlEV}g
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x3 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x4 = "_dbg^VXc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x1 = { 67 45 57 07 00 72 54 62 } //This might be a string? Looks like:gEWrTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x2 = { 59 5E 47 42 6D 64 5C 7E } //This might be a string? Looks like:Y^GBmd\~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x5 = { 01 7C 5C 77 4F 51 72 73 } //This might be a string? Looks like:|\wOQrs

		condition:
(3 of ($x0,$x1,$x2) ) or (2 of ($x3,$x4,$x5) )}