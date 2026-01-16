rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.316024413893479 Found in 5 files
		$x0 = { C0 F7 D8 59 48 5D C3 55 8B EC 83 EC 14 A1 00 40 01 10 83 65 F4 00 83 65 F8 00 56 57 BF 4E E6 40 BB BE 00 00 FF FF 3B C7 74 0D 85 C6 74 09 F7 D0 A3 04 40 01 10 EB 66 8D 45 F4 50 FF 15 08 30 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.382659765557392 Found in 2 files
		$x1 = { 47 50 01 40 57 44 02 43 79 07 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B 7E 4C 0D 4F 7B 4F 46 1A 64 05 51 79 61 04 7B 6D 62 04 0C 5F 6F 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 } //This might be a string? Looks like:GP@WDCyC\rqwBFepMVW}Lx[~L\rO{OFdQya{mb_oACVQSz}\aY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.167434179450871 Found in 2 files
		$x2 = { 07 41 43 56 06 51 02 53 01 7A 7D 5C 01 1E 61 59 00 40 53 5A 03 50 47 47 02 7A 06 40 02 1A 71 4D 0D 43 65 05 0C 53 57 06 1E 65 5B 03 1E 1A 4F 0C 1A 43 0D 74 74 64 7C 71 77 74 60 72 77 42 52 7F } //This might be a string? Looks like:ACVQSz}\aY@SZPGGz@qM\rCeSWe[OC\rttd|qwt`rwBR

		condition:
(2 of ($x0,$x1,$x2) )}