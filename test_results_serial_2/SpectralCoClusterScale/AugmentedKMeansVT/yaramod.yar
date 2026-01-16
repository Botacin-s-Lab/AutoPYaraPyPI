rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x4 = { 07 0C 4C 67 6D 5D 59 61 62 73 45 57 52 77 41 56 } //This might be a string? Looks like:Lgm]YabsEWRwAV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x8 = { 04 3B F7 72 F1 5F 5E C3 56 57 BE 70 33 00 10 BF } //This might be a string? Looks like:;r_^VWp3
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 2 files
		$x5 = { 56 5B 67 04 6C 62 4D 64 56 58 0C 05 6F 62 7B 05 } //This might be a string? Looks like:V[glbMdVXob{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x0 = { 6F 5C 1A 5F 4F 45 6C 78 52 74 73 71 5A 41 43 02 } //This might be a string? Looks like:o\_OElxRtsqZAC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x6 = { 6C 6D 7B 4F 6F 62 04 5C 57 7D 59 7F 6F 72 63 40 } //This might be a string? Looks like:lm{Oob\W}Yorc@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2475562489182657 Found in 3 files
		$x9 = { 74 74 74 74 74 74 74 74 74 65 1A 1A 1A 1A 1A 1A } //This might be a string? Looks like:ttttttttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x1 = { 6F 5A 6C 57 05 7A 01 51 64 03 06 73 61 76 7B 5D } //This might be a string? Looks like:oZlWzQdsav{]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x2 = { 66 0C 1A 72 79 07 7C 41 70 7F 74 5F 06 0D 6C 43 } //This might be a string? Looks like:fry|Apt_\rlC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x7 = { 03 7B 44 1A 71 5B 77 4D 61 65 7A 0C 52 50 47 58 } //This might be a string? Looks like:{Dq[wMaezRPGX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x10 = { 7A 06 40 02 1A 71 4D 0D 43 65 05 0C 53 57 06 1E } //This might be a string? Looks like:z@qM\rCeSW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x3 = { 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 } //This might be a string? Looks like:<?xml versi

		condition:
(4 of ($x0,$x1,$x2,$x3) ) or (4 of ($x4,$x5,$x6,$x7) ) or (3 of ($x8,$x9,$x10) )}