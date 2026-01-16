rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.521782221599798 Found in 3 files
		$x0 = { 52 74 74 74 74 74 01 53 40 52 01 74 41 74 5B 7B } //This might be a string? Looks like:RtttttS@RtAt[{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 2 files
		$x6 = { 56 5B 67 04 6C 62 4D 64 56 58 0C 05 6F 62 7B 05 } //This might be a string? Looks like:V[glbMdVXob{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x1 = { 45 6C 07 73 46 60 07 63 5F 51 72 59 43 57 52 74 } //This might be a string? Looks like:ElsF`c_QrYCWRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x7 = { 6C 6D 7B 4F 6F 62 04 5C 57 7D 59 7F 6F 72 63 40 } //This might be a string? Looks like:lm{Oob\W}Yorc@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x3 = { 5C 05 64 5E 70 65 53 58 74 0C 73 4C 71 5F 41 60 } //This might be a string? Looks like:\d^peSXtsLq_A`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 3 files
		$x4 = { 64 77 65 74 70 01 74 6D 42 77 7F 74 70 01 74 67 } //This might be a string? Looks like:dwetptmBwtptg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x5 = { 6F 5A 6C 57 05 7A 01 51 64 03 06 73 61 76 7B 5D } //This might be a string? Looks like:oZlWzQdsav{]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x2 = { 47 75 69 64 73 57 00 45 74 77 52 65 70 6C 79 4E } //This might be a string? Looks like:GuidsWEtwReplyN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x8 = { 03 7B 44 1A 71 5B 77 4D 61 65 7A 0C 52 50 47 58 } //This might be a string? Looks like:{Dq[wMaezRPGX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x9 = { 66 7F 64 5E 50 05 47 51 74 5C 5B 0D 0C 70 5F 06 } //This might be a string? Looks like:fd^PGQt\[\rp_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x10 = { 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 } //This might be a string? Looks like:<?xml versi

		condition:
(3 of ($x0,$x1,$x2) ) or (3 of ($x3,$x4,$x5) ) or (3 of ($x6,$x7,$x8) ) or (2 of ($x9,$x10) )}