rule testrules
{
	//Input TP Rate:
	//2/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x0 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x1 = { 4C 6F 62 00 05 63 72 5D } //This might be a string? Looks like:Lobcr]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 2 files
		$x2 = { 77 04 74 72 78 74 51 74 } //This might be a string? Looks like:wtrxtQt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x3 = "r]Lobs^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x4 = { 56 59 5A 1A 66 5C 64 72 } //This might be a string? Looks like:VYZf\dr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x5 = { 0D 73 7B 64 03 7E 79 47 } //This might be a string? Looks like:\rs{d~yG
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x6 = { 7F 43 6C 07 63 4F 56 05 } //This might be a string? Looks like:ClcOV

		condition:
(5 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6) )}