rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.688307235905091 Found in 3 files
		$x0 = { 52 67 70 0C 61 7C 72 04 43 6F 72 60 40 71 64 05 7E 7F 74 74 74 74 74 74 74 74 74 77 64 67 64 74 } //This might be a string? Looks like:Rgpa|rCor`@qd~tttttttttwdgdt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7015976555739165 Found in 2 files
		$x7 = { 08 00 00 00 00 00 00 00 00 00 61 63 44 64 74 74 78 74 74 74 74 70 74 74 74 74 1A 1A 0D 74 74 79 } //This might be a string? Looks like:acDdttxttttptttt\rtty
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 1 files
		$x8 = { 03 61 53 05 40 5E 62 72 66 6F 54 5C 04 78 5B 7E 4C 6D 57 46 5D 56 02 79 50 0C 41 65 47 51 1E 71 } //This might be a string? Looks like:aS@^brfoT\x[~LmWF]VyPAeGQq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 5 files
		$x1 = { F1 5F 5E C3 56 57 BE 70 33 00 10 BF 70 33 00 10 EB 0B 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.9375 Found in 1 files
		$x2 = { 4C 61 05 72 1E 45 79 51 6D 65 46 4D 7C 59 4C 71 40 6F 47 77 76 5B 53 67 5F 5A 57 58 7A 56 07 06 } //This might be a string? Looks like:LarEyQmeFM|YLq@oGwv[Sg_ZWXzV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.8125 Found in 2 files
		$x4 = { 05 06 5A 0D 03 66 79 67 64 5F 47 60 4F 43 65 51 61 6D 06 07 6C 65 77 70 7C 59 7B 00 7C 41 04 71 } //This might be a string? Looks like:Z\rfygd_G`OCeQamlewp|Y{|Aq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.601409765557392 Found in 2 files
		$x3 = { 0C 73 4C 71 5F 41 60 7F 74 4D 06 76 7D 7C 65 7A 05 64 5E 76 7D 6C 7F 61 5C 41 70 7F 77 74 57 63 } //This might be a string? Looks like:sLq_A`tMv}|ezd^v}la\ApwtWc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 1 files
		$x5 = { 4D 76 7C 51 00 63 73 03 56 01 77 60 0D 61 78 7B 06 70 46 5F 50 7F 41 40 7D 52 47 43 0C 04 53 65 } //This might be a string? Looks like:Mv|QcsVw`\rax{pF_PA@}RGCSe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 3 files
		$x6 = { 7F 5F 6F 72 63 58 6F 07 5D 45 54 58 41 46 57 62 00 43 56 7D 73 4C 56 06 67 04 51 5B 51 01 50 6D } //This might be a string? Looks like:_orcXo]ETXAFWbCV}sLVgQ[QPm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.663909765557392 Found in 2 files
		$x9 = { 72 59 05 50 66 77 07 6F 6D 7F 4F 54 62 0C 40 65 66 7C 4D 79 5F 74 40 78 76 01 42 7C 5C 77 40 6C } //This might be a string? Looks like:rYPfwomOTb@ef|My_t@xvB|\w@l

		condition:
(4 of ($x0,$x1,$x2,$x3) ) or (3 of ($x4,$x5,$x6) ) or (3 of ($x7,$x8,$x9) )}