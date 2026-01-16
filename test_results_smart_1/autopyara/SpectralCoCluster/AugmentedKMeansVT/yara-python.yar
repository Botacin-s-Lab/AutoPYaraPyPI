rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.366729296672175 Found in 3 files
		$x0 = { 00 4F 65 66 7F 04 56 58 01 03 56 07 7B 5A 6F 62 04 5D 56 4C 04 41 54 62 7B 4C 57 06 7B 43 6F 5B } //This might be a string? Looks like:OefVXV{Zob]VLATb{LW{Co[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.788909765557392 Found in 2 files
		$x1 = { 7A 1E 02 43 4F 42 1A 50 72 04 46 7C 7D 6F 59 56 5B 7B 45 57 07 01 0C 7C 5F 70 40 78 76 7C 52 6F } //This might be a string? Looks like:zCOBPrF|}oYV[{EW|_p@xv|Ro
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.663909765557392 Found in 2 files
		$x2 = { 72 59 05 50 66 77 07 6F 6D 7F 4F 54 62 0C 40 65 66 7C 4D 79 5F 74 40 78 76 01 42 7C 5C 77 40 6C } //This might be a string? Looks like:rYPfwomOTb@ef|My_t@xvB|\w@l

		condition:
(2 of ($x0,$x1,$x2) )}