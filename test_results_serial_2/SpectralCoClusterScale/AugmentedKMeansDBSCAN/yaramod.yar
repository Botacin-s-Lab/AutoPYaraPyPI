rule testrules
{
	//Input TP Rate:
	//3/5
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.827514062229568 Found in 1 files
		$x0 = { 02 5B 63 7A 4F 58 0D 66 5A 54 7E 40 5B 64 41 45 7F 5F 78 58 67 6D 40 5A 1A 52 0D 60 41 4F 56 72 7C 53 6C 6D 51 01 56 5A 4C 63 73 03 54 6C 7D 1E 74 70 00 44 1E 7A 46 78 61 0C 73 40 5D 06 7E 41 71 74 43 7F 5B 06 4D 07 7B 4C 7C 73 4D 71 47 71 7B 62 53 0C 51 7D 59 46 7C 1A 44 76 40 6D 57 7D 6F 60 60 77 5D 7E 41 1E 5C 5E 62 00 66 43 42 06 65 46 52 61 6F 05 5B 50 1A 61 02 54 63 56 64 57 } //This might be a string? Looks like:[czOX\rfZT~@[dAE_xXgm@ZR\r`AOVr|SlmQVZLcsTl}tpDzFxas@]~AqtC[M{L|sMqGq{bSQ}YF|Dv@mW}o``w]~A\^bfCBeFRao[PaTcVdW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.934581853438969 Found in 2 files
		$x1 = { 74 74 74 74 74 74 08 08 EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 20 65 6E 63 6F 64 69 6E 67 3D 22 55 54 46 2D 38 22 20 73 74 61 6E 64 61 6C 6F 6E 65 3D 22 79 65 73 22 3F 3E 0D 0A 3C 61 73 73 65 6D 62 6C 79 20 78 6D 6C 6E 73 3D 22 75 72 6E 3A 73 63 68 65 6D 61 73 2D 6D 69 63 72 6F 73 6F 66 74 2D 63 6F 6D 3A 61 73 6D 2E 76 31 22 20 6D 61 6E 69 66 65 73 74 56 } //This might be a string? Looks like:tttttt<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestV

		condition:
(1 of ($x0,$x1) )}