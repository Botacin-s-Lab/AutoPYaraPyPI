rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 63 1E 79 4D 59 00 57 42 } //This might be a string? Looks like:cyMYWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x1 = "_dbg^VXc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x2 = { 67 45 57 07 00 72 54 62 } //This might be a string? Looks like:gEWrTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x3 = { 7F 43 6C 07 63 4F 56 05 } //This might be a string? Looks like:ClcOV

		condition:
(3 of ($x0,$x1,$x2,$x3) )}