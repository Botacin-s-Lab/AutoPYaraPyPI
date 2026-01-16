rule testrules
{
	//Input TP Rate:
	//4/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.316024413893479 Found in 5 files
		$x2 = { C0 F7 D8 59 48 5D C3 55 8B EC 83 EC 14 A1 00 40 01 10 83 65 F4 00 83 65 F8 00 56 57 BF 4E E6 40 BB BE 00 00 FF FF 3B C7 74 0D 85 C6 74 09 F7 D0 A3 04 40 01 10 EB 66 8D 45 F4 50 FF 15 08 30 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.064464015923013 Found in 2 files
		$x4 = { 02 43 4F 42 1A 50 72 04 46 7C 7D 6F 59 56 5B 7B 45 57 07 01 0C 7C 5F 70 40 78 76 7C 52 6F 62 00 5F 57 07 67 45 57 58 56 0C 7C 59 63 60 67 5C 05 01 7C 5C 77 4F 51 72 73 40 6F 72 73 46 57 07 00 } //This might be a string? Looks like:COBPrF|}oYV[{EW|_p@xv|Rob_WgEWXV|Yc`g\|\wOQrs@orsFW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.495864648336088 Found in 1 files
		$x0 = { 53 76 7A 5C 5E 02 51 01 1E 47 4D 7D 0D 5D 66 6F 05 70 46 4C 78 4C 6C 42 72 0D 0D 5A 76 71 40 58 4F 73 65 40 7C 62 5A 5C 4F 61 07 52 52 44 5C 54 6D 43 56 43 77 4F 64 79 59 66 03 51 7F 7D 50 06 } //This might be a string? Looks like:Svz\^QGM}\r]fopFLxLlBr\r\rZvq@XOse@|bZ\OaRRD\TmCVCwOdyYfQ}P
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.581954882778696 Found in 1 files
		$x5 = { 73 7E 50 5F 58 1A 64 60 5F 5D 04 1A 63 5B 06 40 4D 65 46 7B 71 4F 1E 43 62 5C 1E 0C 50 07 51 41 5C 51 7C 56 62 41 4C 47 5A 74 76 00 6D 7C 7A 78 71 03 01 6F 74 0D 70 79 7F 63 67 57 42 62 53 77 } //This might be a string? Looks like:s~P_Xd`_]c[@MeF{qOCb\PQA\Q|VbALGZtvm|zxqot\rpycgWBbSw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.892283547037795 Found in 3 files
		$x6 = { 74 74 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 22 79 65 73 22 3F 3E 0D 0A } //This might be a string? Looks like:tt<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.382659765557392 Found in 2 files
		$x3 = { 47 50 01 40 57 44 02 43 79 07 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B 7E 4C 0D 4F 7B 4F 46 1A 64 05 51 79 61 04 7B 6D 62 04 0C 5F 6F 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 } //This might be a string? Looks like:GP@WDCyC\rqwBFepMVW}Lx[~L\rO{OFdQya{mb_oACVQSz}\aY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.167434179450871 Found in 2 files
		$x1 = { 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 40 53 5A 03 50 47 47 02 7A 06 40 02 1A 71 4D 0D 43 65 05 0C 53 57 06 1E 65 5B 03 1E 1A 4F 0C 1A 43 0D 74 74 64 7C 71 77 74 60 72 77 42 52 7F } //This might be a string? Looks like:ACVQSz}\aY@SZPGGz@qM\rCeSWe[OC\rttd|qwt`rwBR

		condition:
(2 of ($x0,$x1) ) or (2 of ($x2,$x3) ) or (3 of ($x4,$x5,$x6) )}