rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.581954882778696 Found in 1 files
		$x2 = { 7F 66 6C 5B 7E 76 5E 44 7E 4C 42 41 79 5C 0D 42 78 61 7C 4F 7B 71 60 07 7B 4F 52 00 7A 5F 46 0D 65 61 01 1A 64 72 73 5C 6C 07 67 59 6F 58 51 5A 54 62 45 47 57 72 04 40 57 06 77 4D 56 5B 7B 05 } //This might be a string? Looks like:fl[~v^D~LBAy\\rBxa|O{q`{ORz_F\readrs\lgYoXQZTbEGWr@WwMV[{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.316024413893479 Found in 5 files
		$x3 = { C0 F7 D8 59 48 5D C3 55 8B EC 83 EC 14 A1 00 40 01 10 83 65 F4 00 83 65 F8 00 56 57 BF 4E E6 40 BB BE 00 00 FF FF 3B C7 74 0D 85 C6 74 09 F7 D0 A3 04 40 01 10 EB 66 8D 45 F4 50 FF 15 08 30 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.495864648336088 Found in 1 files
		$x0 = { 53 76 7A 5C 5E 02 51 01 1E 47 4D 7D 0D 5D 66 6F 05 70 46 4C 78 4C 6C 42 72 0D 0D 5A 76 71 40 58 4F 73 65 40 7C 62 5A 5C 4F 61 07 52 52 44 5C 54 6D 43 56 43 77 4F 64 79 59 66 03 51 7F 7D 50 06 } //This might be a string? Looks like:Svz\^QGM}\r]fopFLxLlBr\r\rZvq@XOse@|bZ\OaRRD\TmCVCwOdyYfQ}P
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.570159765557392 Found in 1 files
		$x5 = { 5B 64 78 67 4C 7A 01 57 7F 41 47 53 1A 63 04 79 59 51 61 50 7E 78 07 05 77 72 06 54 67 5C 4D 0C 62 0D 6F 45 07 5D 02 65 5E 46 7B 6D 50 5E 61 4C 07 5F 56 50 44 6C 42 03 53 71 7D 4F 59 5A 7D 41 } //This might be a string? Looks like:[dxgLzWAGScyYQaP~xwrTg\Mb\roE]e^F{mP^aL_VPDlBSq}OYZ}A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.892283547037795 Found in 3 files
		$x4 = { 74 74 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 22 79 65 73 22 3F 3E 0D 0A } //This might be a string? Looks like:tt<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.158214015923012 Found in 2 files
		$x6 = { 66 7F 7B 50 60 73 42 56 72 4D 45 6C 07 73 05 54 62 0C 40 79 58 73 42 56 76 7C 43 65 52 05 7E 7C 76 74 0D 51 7D 7F 04 56 06 67 7F 57 58 6F 43 7C 7D 5D 41 57 72 00 4F 65 66 7F 04 56 58 01 03 56 } //This might be a string? Looks like:f{P`sBVrMElsTb@yXsBVv|CeR~|vt\rQ}VgWXoC|}]AWrOefVXV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.167434179450871 Found in 2 files
		$x1 = { 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 40 53 5A 03 50 47 47 02 7A 06 40 02 1A 71 4D 0D 43 65 05 0C 53 57 06 1E 65 5B 03 1E 1A 4F 0C 1A 43 0D 74 74 64 7C 71 77 74 60 72 77 42 52 7F } //This might be a string? Looks like:ACVQSz}\aY@SZPGGz@qM\rCeSWe[OC\rttd|qwt`rwBR

		condition:
(2 of ($x0,$x1) ) or (3 of ($x2,$x3,$x4) ) or (2 of ($x5,$x6) )}