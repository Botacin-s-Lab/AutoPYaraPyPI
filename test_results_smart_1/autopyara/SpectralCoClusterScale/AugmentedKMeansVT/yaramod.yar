rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x4 = { 07 0C 4C 67 6D 5D 59 61 62 73 45 57 52 77 41 56 } //This might be a string? Looks like:Lgm]YabsEWRwAV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 2 files
		$x5 = { 56 5B 67 04 6C 62 4D 64 56 58 0C 05 6F 62 7B 05 } //This might be a string? Looks like:V[glbMdVXob{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x8 = { 45 6C 07 73 46 60 07 63 5F 51 72 59 43 57 52 74 } //This might be a string? Looks like:ElsF`c_QrYCWRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x6 = { 6C 6D 7B 4F 6F 62 04 5C 57 7D 59 7F 6F 72 63 40 } //This might be a string? Looks like:lm{Oob\W}Yorc@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x0 = { 5C 05 64 5E 70 65 53 58 74 0C 73 4C 71 5F 41 60 } //This might be a string? Looks like:\d^peSXtsLq_A`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2475562489182657 Found in 3 files
		$x9 = { 74 74 74 74 74 74 74 74 74 65 1A 1A 1A 1A 1A 1A } //This might be a string? Looks like:ttttttttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x1 = { 6F 5A 6C 57 05 7A 01 51 64 03 06 73 61 76 7B 5D } //This might be a string? Looks like:oZlWzQdsav{]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x2 = { 67 74 02 0D 06 60 70 5C 77 5F 47 07 5A 43 64 7A } //This might be a string? Looks like:gt\r`p\w_GZCdz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x7 = { 03 7B 44 1A 71 5B 77 4D 61 65 7A 0C 52 50 47 58 } //This might be a string? Looks like:{Dq[wMaezRPGX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x10 = { 47 75 69 64 73 57 00 45 74 77 52 65 70 6C 79 4E } //This might be a string? Looks like:GuidsWEtwReplyN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x3 = { 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 } //This might be a string? Looks like:<?xml versi

		condition:
(4 of ($x0,$x1,$x2,$x3) ) or (4 of ($x4,$x5,$x6,$x7) ) or (3 of ($x8,$x9,$x10) )}