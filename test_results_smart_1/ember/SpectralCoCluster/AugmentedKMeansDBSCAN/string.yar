rule testrules
{
	//Input TP Rate:
	//2/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0243974703476995 Found in 2 files
		$x5 = { 04 74 72 78 74 51 74 77 62 74 72 60 74 56 52 77 } //This might be a string? Looks like:trxtQtwbtr`tVRw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x6 = { 45 6C 07 73 46 60 07 63 5F 51 72 59 43 57 52 74 } //This might be a string? Looks like:ElsF`c_QrYCWRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2475562489182657 Found in 3 files
		$x9 = { 74 74 74 74 74 74 74 74 74 65 1A 1A 1A 1A 1A 1A } //This might be a string? Looks like:ttttttttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x11 = { 67 74 02 0D 06 60 70 5C 77 5F 47 07 5A 43 64 7A } //This might be a string? Looks like:gt\r`p\w_GZCdz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x3 = { 46 67 5C 05 60 7C 64 7F 5E 47 42 41 7D 01 03 4F } //This might be a string? Looks like:Fg\`|d^GBA}O
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.521782221599798 Found in 3 files
		$x0 = { 52 74 74 74 74 74 01 53 40 52 01 74 41 74 5B 7B } //This might be a string? Looks like:RtttttS@RtAt[{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 2 files
		$x1 = { 52 77 59 74 7D 7C 74 56 42 77 45 74 72 0D 74 57 } //This might be a string? Looks like:RwYt}|tVBwEtr\rtW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x7 = { 5C 05 64 5E 70 65 53 58 74 0C 73 4C 71 5F 41 60 } //This might be a string? Looks like:\d^peSXtsLq_A`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 2 files
		$x2 = { 43 78 71 70 4C 78 4F 64 04 7B 5F 56 01 7A 61 5A } //This might be a string? Looks like:CxqpLxOd{_VzaZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 3 files
		$x8 = { 64 77 65 74 70 01 74 6D 42 77 7F 74 70 01 74 67 } //This might be a string? Looks like:dwetptmBwtptg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x10 = { 6F 5A 6C 57 05 7A 01 51 64 03 06 73 61 76 7B 5D } //This might be a string? Looks like:oZlWzQdsav{]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x4 = { 47 75 69 64 73 57 00 45 74 77 52 65 70 6C 79 4E } //This might be a string? Looks like:GuidsWEtwReplyN
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x12 = { 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 } //This might be a string? Looks like:<?xml versi

		condition:
(5 of ($x0,$x1,$x2,$x3,$x4) ) or (8 of ($x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12) )}