rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x1 = { 50 58 73 05 54 62 0C 40 } //This might be a string? Looks like:PXsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x2 = { 72 01 74 54 64 77 05 74 } //This might be a string? Looks like:rtTdwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x3 = "Pr{YV}gE" ascii

		condition:
(3 of ($x0,$x1,$x2,$x3) )}