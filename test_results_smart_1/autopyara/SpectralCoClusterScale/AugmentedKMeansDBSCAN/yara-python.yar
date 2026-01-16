rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 1 files
		$x6 = { 42 60 77 59 45 76 61 06 54 64 05 78 44 02 5D 56 7A 4C 7B 62 63 57 7E 41 79 5E 0C 65 6D 46 5F 53 } //This might be a string? Looks like:B`wYEvaTdxD]VzL{bcW~Ay^emF_S
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 5 files
		$x0 = { F1 5F 5E C3 56 57 BE 70 33 00 10 BF 70 33 00 10 EB 0B 8B 06 85 C0 74 02 FF D0 83 C6 04 3B F7 72 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.5625 Found in 2 files
		$x7 = { 71 74 05 7A 71 4D 74 67 70 5D 78 60 73 67 6C 6D 72 77 5E 54 72 4D 42 51 7D 5D 0D 52 7C 66 7C 5F } //This might be a string? Looks like:qtzqMtgp]x`sglmrw^TrMBQ}]\rR|f|_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.9375 Found in 1 files
		$x1 = { 4C 61 05 72 1E 45 79 51 6D 65 46 4D 7C 59 4C 71 40 6F 47 77 76 5B 53 67 5F 5A 57 58 7A 56 07 06 } //This might be a string? Looks like:LarEyQmeFM|YLq@oGwv[Sg_ZWXzV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.788909765557392 Found in 2 files
		$x8 = { 7A 1E 02 43 4F 42 1A 50 72 04 46 7C 7D 6F 59 56 5B 7B 45 57 07 01 0C 7C 5F 70 40 78 76 7C 52 6F } //This might be a string? Looks like:zCOBPrF|}oYV[{EW|_p@xv|Ro
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.0 Found in 1 files
		$x3 = { 4D 76 7C 51 00 63 73 03 56 01 77 60 0D 61 78 7B 06 70 46 5F 50 7F 41 40 7D 52 47 43 0C 04 53 65 } //This might be a string? Looks like:Mv|QcsVw`\rax{pF_PA@}RGCSe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.601409765557392 Found in 2 files
		$x4 = { 0C 73 4C 71 5F 41 60 7F 74 4D 06 76 7D 7C 65 7A 05 64 5E 76 7D 6C 7F 61 5C 41 70 7F 77 74 57 63 } //This might be a string? Looks like:sLq_A`tMv}|ezd^v}la\ApwtWc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.75 Found in 3 files
		$x2 = { 7F 5F 6F 72 63 58 6F 07 5D 45 54 58 41 46 57 62 00 43 56 7D 73 4C 56 06 67 04 51 5B 51 01 50 6D } //This might be a string? Looks like:_orcXo]ETXAFWbCV}sLVgQ[QPm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5625 Found in 3 files
		$x5 = { 73 6C 74 67 64 77 66 74 73 78 74 66 64 77 65 74 70 01 74 6D 42 77 7F 74 70 01 74 67 52 77 65 74 } //This might be a string? Looks like:sltgdwftsxtfdwetptmBwtptgRwet

		condition:
(3 of ($x0,$x1,$x2) ) or (3 of ($x3,$x4,$x5) ) or (3 of ($x6,$x7,$x8) )}