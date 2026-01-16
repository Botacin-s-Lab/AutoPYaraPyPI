rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.581954882778696 Found in 1 files
		$x0 = { 7F 66 6C 5B 7E 76 5E 44 7E 4C 42 41 79 5C 0D 42 78 61 7C 4F 7B 71 60 07 7B 4F 52 00 7A 5F 46 0D 65 61 01 1A 64 72 73 5C 6C 07 67 59 6F 58 51 5A 54 62 45 47 57 72 04 40 57 06 77 4D 56 5B 7B 05 } //This might be a string? Looks like:fl[~v^D~LBAy\\rBxa|O{q`{ORz_F\readrs\lgYoXQZTbEGWr@WwMV[{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.316024413893479 Found in 5 files
		$x6 = { C0 F7 D8 59 48 5D C3 55 8B EC 83 EC 14 A1 00 40 01 10 83 65 F4 00 83 65 F8 00 56 57 BF 4E E6 40 BB BE 00 00 FF FF 3B C7 74 0D 85 C6 74 09 F7 D0 A3 04 40 01 10 EB 66 8D 45 F4 50 FF 15 08 30 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.550704882778696 Found in 1 files
		$x7 = { 64 5D 01 52 43 5C 53 52 5E 54 41 70 76 1A 7C 62 59 44 70 64 63 51 1E 7E 7F 40 5A 00 1A 05 79 45 44 00 6D 1E 56 71 7A 50 65 04 4D 02 52 5B 0C 6F 1E 74 1E 7B 78 40 6C 58 60 5F 0D 77 7E 4F 03 04 } //This might be a string? Looks like:d]RC\SR^TApv|bYDpdcQ~@ZyEDmVqzPeMR[ot{x@lX`_\rw~O
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.570159765557392 Found in 1 files
		$x2 = { 5B 64 78 67 4C 7A 01 57 7F 41 47 53 1A 63 04 79 59 51 61 50 7E 78 07 05 77 72 06 54 67 5C 4D 0C 62 0D 6F 45 07 5D 02 65 5E 46 7B 6D 50 5E 61 4C 07 5F 56 50 44 6C 42 03 53 71 7D 4F 59 5A 7D 41 } //This might be a string? Looks like:[dxgLzWAGScyYQaP~xwrTg\Mb\roE]e^F{mP^aL_VPDlBSq}OYZ}A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.581954882778696 Found in 1 files
		$x4 = { 73 7E 50 5F 58 1A 64 60 5F 5D 04 1A 63 5B 06 40 4D 65 46 7B 71 4F 1E 43 62 5C 1E 0C 50 07 51 41 5C 51 7C 56 62 41 4C 47 5A 74 76 00 6D 7C 7A 78 71 03 01 6F 74 0D 70 79 7F 63 67 57 42 62 53 77 } //This might be a string? Looks like:s~P_Xd`_]c[@MeF{qOCb\PQA\Q|VbALGZtvm|zxqot\rpycgWBbSw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.158214015923012 Found in 2 files
		$x3 = { 66 7F 7B 50 60 73 42 56 72 4D 45 6C 07 73 05 54 62 0C 40 79 58 73 42 56 76 7C 43 65 52 05 7E 7C 76 74 0D 51 7D 7F 04 56 06 67 7F 57 58 6F 43 7C 7D 5D 41 57 72 00 4F 65 66 7F 04 56 58 01 03 56 } //This might be a string? Looks like:f{P`sBVrMElsTb@yXsBVv|CeR~|vt\rQ}VgWXoC|}]AWrOefVXV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.892283547037795 Found in 3 files
		$x8 = { 74 74 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 22 79 65 73 22 3F 3E 0D 0A } //This might be a string? Looks like:tt<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.382659765557392 Found in 2 files
		$x1 = { 47 50 01 40 57 44 02 43 79 07 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B 7E 4C 0D 4F 7B 4F 46 1A 64 05 51 79 61 04 7B 6D 62 04 0C 5F 6F 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 } //This might be a string? Looks like:GP@WDCyC\rqwBFepMVW}Lx[~L\rO{OFdQya{mb_oACVQSz}\aY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.725798827786958 Found in 3 files
		$x5 = { 74 74 52 74 74 74 74 74 01 53 40 52 01 74 41 74 5B 7B 7C 57 52 77 61 78 05 5D 63 72 5D 45 56 4C 77 42 56 58 0C 5B 56 58 73 41 7C 72 7B 5D 57 58 00 43 51 76 77 5C 6F 66 77 4C 51 62 01 52 54 62 } //This might be a string? Looks like:ttRtttttS@RtAt[{|WRwax]cr]EVLwBVX[VXsA|r{]WXCQvw\ofwLQbRTb

		condition:
(2 of ($x0,$x1) ) or (2 of ($x2,$x3) ) or (2 of ($x4,$x5) ) or (3 of ($x6,$x7,$x8) )}