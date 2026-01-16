rule 040.dll.patched_SpectralCoClusterScale_KMeans_k3
{
	//Input TP Rate:
	//10/15
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x0 = { 62 79 02 7C 41 73 71 73 } //This might be a string? Looks like:by|Asqs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x1 = { 63 6C 43 46 5C 0D 72 79 } //This might be a string? Looks like:clCF\\rry
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x2 = { 62 00 07 6C 62 4D 45 6F } //This might be a string? Looks like:blbMEo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x3 = "YtrFtTdw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x4 = { 59 1E 73 7D 7C 76 5C 4D } //This might be a string? Looks like:Ys}|v\M
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x5 = { 6C 43 46 5C 05 60 7C 52 } //This might be a string? Looks like:lCF\`|R
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x6 = { 1A 01 40 74 5C 74 74 74 } //This might be a string? Looks like:@t\ttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x7 = "Qr]Y|rsB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x8 = "vM_GRQd@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x9 = { 62 00 5E 57 06 56 74 61 } //This might be a string? Looks like:b^WVta
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x10 = { 7D 6F 6D 67 71 57 07 00 } //This might be a string? Looks like:}omgqW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x11 = { 02 7C 7B 0C 76 74 77 04 } //This might be a string? Looks like:|{vtw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x12 = "~^ttdrwQ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x13 = "rcAVrM]Q" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x14 = { 7F 77 64 4F 05 43 53 4D } //This might be a string? Looks like:wdOCSM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x15 = "{gS]d_`m" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x16 = { 79 5D 50 71 0D 1A 1A 1A } //This might be a string? Looks like:y]Pq\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x17 = { 05 6D 0D 74 74 74 74 74 } //This might be a string? Looks like:m\rttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x18 = { 63 5C 1E 4C 71 02 77 66 } //This might be a string? Looks like:c\Lqwf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 7 files
		$x19 = "t`swd`sw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x20 = { 54 62 00 5B 64 64 74 74 } //This might be a string? Looks like:Tb[ddtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 9 files
		$x21 = { 53 42 77 74 74 74 74 5C } //This might be a string? Looks like:SBwtttt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x22 = "barmdzef" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x23 = { 63 6C 43 46 52 1E 42 60 } //This might be a string? Looks like:clCFRB`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 5 files
		$x24 = { 65 1A 51 67 61 1A 51 67 } //This might be a string? Looks like:eQgaQg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x25 = { 05 06 01 5F 63 42 7C 74 } //This might be a string? Looks like:_cB|t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x26 = "epp|mtQt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x27 = "tptttxt@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x28 = { 65 03 7C 41 70 5F 40 4C } //This might be a string? Looks like:e|Ap_@L
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x29 = { 4C 77 46 57 07 00 5B 74 } //This might be a string? Looks like:LwFW[t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x30 = { 5C 0D 6F 50 42 01 43 1A } //This might be a string? Looks like:\\roPBC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x31 = { 51 6D 67 59 56 05 70 74 } //This might be a string? Looks like:QmgYVpt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x32 = { 72 5F 60 5C 1A 67 5A 65 } //This might be a string? Looks like:r_`\gZe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x587 = { 7B 4F 6F 62 04 5C 57 7D } //This might be a string? Looks like:{Oob\W}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x589 = { 7F 59 56 6D 63 59 56 06 } //This might be a string? Looks like:YVmcYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x33 = { 67 72 63 4F 51 7D 7F 43 } //This might be a string? Looks like:grcOQ}C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x34 = { 74 74 74 7C 7B 0C 71 74 } //This might be a string? Looks like:ttt|{qt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x35 = { 5E 78 5C 52 4C 79 71 7C } //This might be a string? Looks like:^x\RLyq|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x36 = "`svycdL{" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x37 = { 5C 77 59 56 5B 7F 43 56 } //This might be a string? Looks like:\wYV[CV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x38 = { 1A 63 6C 43 46 54 52 73 } //This might be a string? Looks like:clCFTRs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x39 = { 42 64 02 1A 5B 79 4D 6D } //This might be a string? Looks like:Bd[yMm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x40 = "t]Vte]lp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x41 = { 1A 74 70 74 74 74 76 71 } //This might be a string? Looks like:tptttvq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x42 = "tt|tttt}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x43 = { 73 7D 6F 6D 67 71 57 07 } //This might be a string? Looks like:s}omgqW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x44 = "ttttttvZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x45 = { 6F 66 77 5F 57 07 00 4F } //This might be a string? Looks like:ofw_WO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x46 = { 5C 43 4C 51 77 60 4F 05 } //This might be a string? Looks like:\CLQw`O
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x47 = { 74 7C 65 70 72 73 0C 50 } //This might be a string? Looks like:t|eprsP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 7 files
		$x48 = "tt|epp|m" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x49 = { 1A 1A 52 0D 64 60 5D 56 } //This might be a string? Looks like:R\rd`]V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x611 = "swLTmoEW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x612 = { 73 5E 6F 7D 7F 59 56 06 } //This might be a string? Looks like:s^o}YV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x50 = "gsW[oEVX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x51 = { 60 4D 43 6C 07 73 46 6F } //This might be a string? Looks like:`MClsFo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 8 files
		$x52 = { 67 71 57 07 00 4F 57 07 } //This might be a string? Looks like:gqWOW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x53 = { 74 74 7C 41 7B 1A 7C 5E } //This might be a string? Looks like:tt|A{|^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x54 = { 42 01 41 7B 0D 72 66 7F } //This might be a string? Looks like:BA{\rrf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x55 = "f`tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x56 = "tdtttt|t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x57 = { 04 77 6C 65 7C 1A 1E 46 } //This might be a string? Looks like:wle|F
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x58 = "}ltttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x59 = { 1A 0C 63 5C 1E 4D 44 76 } //This might be a string? Looks like:c\MDv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x60 = "t}|tTdw@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x625 = "ttttt|td" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x627 = { 1A 52 0D 64 70 5D 56 77 } //This might be a string? Looks like:R\rdp]Vw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x61 = { 01 41 59 03 78 51 73 1A } //This might be a string? Looks like:AYxQs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x62 = { 1E 4D 62 78 0D 77 64 60 } //This might be a string? Looks like:Mbx\rwd`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x63 = "WRwOtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x64 = "tttBtdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x65 = { 1A 64 63 6F 5C 6C 62 67 } //This might be a string? Looks like:dco\lbg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x66 = { 51 72 63 01 54 6D 64 52 } //This might be a string? Looks like:QrcTmdR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x67 = "ttttttrs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x68 = { 74 74 74 74 74 4D 05 6C } //This might be a string? Looks like:tttttMl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x69 = "wttttttd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x70 = { 04 62 79 02 7C 65 46 7D } //This might be a string? Looks like:by|eF}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x549 = "r`tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x71 = { 57 72 0C 5F 6C 6D 67 45 } //This might be a string? Looks like:Wr_lmgE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x72 = { 77 04 77 4F 65 74 03 6F } //This might be a string? Looks like:wwOeto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x73 = { 74 77 6F 6D 04 00 57 5C } //This might be a string? Looks like:twomW\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x74 = { 1A 01 65 70 76 7C 6D 74 } //This might be a string? Looks like:epv|mt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x75 = { 5C 74 01 65 00 76 7D 7C } //This might be a string? Looks like:\tev}|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x76 = { 65 46 76 73 7B 62 63 03 } //This might be a string? Looks like:eFvs{bc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x77 = { 74 7C 74 77 00 74 7D 60 } //This might be a string? Looks like:t|twt}`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x557 = { 7F 77 74 74 74 74 74 74 } //This might be a string? Looks like:wtttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x78 = { 71 4C 65 0C 53 6D 59 43 } //This might be a string? Looks like:qLeSmYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x79 = { 52 50 62 0C 04 56 5C 77 } //This might be a string? Looks like:RPbV\w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x80 = "OcXsFTbg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x563 = { 57 42 77 4F 74 72 0D 74 } //This might be a string? Looks like:WBwOtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x81 = { 5C 1E 4C 71 02 74 4C 79 } //This might be a string? Looks like:\LqtLy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x82 = { 04 62 79 02 7C 65 46 7C } //This might be a string? Looks like:by|eF|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x83 = { 05 64 5E 77 74 74 74 74 } //This might be a string? Looks like:d^wtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x84 = { 78 51 70 7F 74 64 74 74 } //This might be a string? Looks like:xQptdtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x567 = { 5D 5F 54 72 73 40 6F 07 } //This might be a string? Looks like:]_Trs@o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x85 = { 53 02 1A 1A 01 41 73 76 } //This might be a string? Looks like:SAsv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 10 files
		$x86 = { 05 6D 0D 74 64 74 74 74 } //This might be a string? Looks like:m\rtdttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x578 = "gdttatpp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x582 = { 04 5D 57 58 7B 59 64 07 } //This might be a string? Looks like:]WX{Yd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x87 = { 7B 05 66 62 00 58 57 06 } //This might be a string? Looks like:{fbXW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x88 = { 7D 6D 04 00 57 6D 56 7C } //This might be a string? Looks like:}mWmV|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x89 = { 5C 43 03 52 1E 56 65 78 } //This might be a string? Looks like:\CRVex
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x90 = { 7D 6F 6D 67 7B 57 07 67 } //This might be a string? Looks like:}omg{Wg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x91 = { 1A 04 62 79 02 7C 41 7B } //This might be a string? Looks like:by|A{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x92 = { 62 79 02 72 5A 77 54 52 } //This might be a string? Looks like:byrZwTR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x93 = { 7B 00 65 06 1A 1A 01 40 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x94 = { 61 1E 1A 01 65 70 73 7C } //This might be a string? Looks like:aeps|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x95 = { 43 00 05 7A 01 41 60 7F } //This might be a string? Looks like:CzA`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x96 = { 74 74 74 74 71 02 56 70 } //This might be a string? Looks like:ttttqVp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x97 = "s|YQvqCl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x98 = { 6C 62 04 59 64 64 74 74 } //This might be a string? Looks like:lbYddtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x592 = { 7D 77 4C 57 07 51 4C 6C } //This might be a string? Looks like:}wLWQLl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x99 = { 7A 1A 43 1A 1A 52 0D 64 } //This might be a string? Looks like:zCR\rd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 6 files
		$x100 = { 1A 1A 1A 0D 77 74 74 74 } //This might be a string? Looks like:\rwttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x101 = { 79 02 73 7B 62 63 07 5A } //This might be a string? Looks like:ys{bcZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x594 = { 6C 07 0C 4C 56 58 63 5F } //This might be a string? Looks like:lLVXc_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x102 = { 61 53 67 5E 5C 64 05 74 } //This might be a string? Looks like:aSg^\dt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x103 = { 42 7A 46 71 78 0D 77 74 } //This might be a string? Looks like:BzFqx\rwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 7 files
		$x104 = "tRwoxott" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x105 = { 77 46 57 07 7B 5D 57 76 } //This might be a string? Looks like:wFW{]Wv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x106 = { 6D 67 64 56 58 0C 5F 6F } //This might be a string? Looks like:mgdVX_o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x107 = "ttt}|ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x108 = "ttRwoxot" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x602 = { 42 74 74 52 0D 64 78 52 } //This might be a string? Looks like:BttR\rdxR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x109 = { 60 78 1A 06 60 7C 1A 4D } //This might be a string? Looks like:`x`|M
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x110 = "edtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x606 = "|roEWr`R" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x111 = { 77 72 5C 52 71 42 74 74 } //This might be a string? Looks like:wr\RqBtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x112 = "tttdtRt~" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x113 = { 74 74 7C 43 7D 6D 04 00 } //This might be a string? Looks like:tt|C}m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x607 = "R|vttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x114 = { 56 06 78 74 74 74 74 74 } //This might be a string? Looks like:Vxttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x115 = { 56 7D 67 45 57 07 01 74 } //This might be a string? Looks like:V}gEWt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x610 = { 67 58 59 46 6F 60 00 5D } //This might be a string? Looks like:gXYFo`]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x116 = { 4F 78 63 6C 43 46 52 1E } //This might be a string? Looks like:OxclCFR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x117 = { 06 05 6F 7C 5E 7B 74 74 } //This might be a string? Looks like:o|^{tt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x118 = "gLom{Ott" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x119 = "d^p|^v@t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x120 = { 6C 7C 7F 00 52 5C 70 74 } //This might be a string? Looks like:l|R\pt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x121 = { 5C 1E 4C 71 53 64 52 74 } //This might be a string? Looks like:\LqSdRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x122 = "ds}omg{W" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x123 = "c]VpsFWr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x124 = { 5A 73 42 64 74 42 65 0D } //This might be a string? Looks like:ZsBdtBe\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x125 = { 78 74 74 74 74 5C 05 6D } //This might be a string? Looks like:xtttt\m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x619 = { 72 63 60 54 62 04 59 74 } //This might be a string? Looks like:rc`TbYt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x126 = "XYFocwCT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x127 = { 77 71 57 07 04 42 6C 6D } //This might be a string? Looks like:wqWBlm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x128 = "ttdtwtts" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x129 = { 06 01 74 7D 64 7D 5C 05 } //This might be a string? Looks like:t}d}\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 8 files
		$x130 = { 1A 71 4F 78 4F 78 4F 78 } //This might be a string? Looks like:qOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x131 = "ttttttvV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x631 = { 01 74 6C 64 77 41 74 72 } //This might be a string? Looks like:tldwAtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x132 = { 1A 1E 71 4D 74 4C 79 67 } //This might be a string? Looks like:qMtLyg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x133 = { 5F 60 6D 5A 60 7C 04 73 } //This might be a string? Looks like:_`mZ`|s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x134 = { 7C 04 73 0D 73 71 1A 51 } //This might be a string? Looks like:|s\rsqQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x544 = { 70 7F 77 74 57 63 76 64 } //This might be a string? Looks like:pwtWcvd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x135 = { 62 00 58 57 05 70 74 74 } //This might be a string? Looks like:bXWptt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x136 = "tttttvZt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x137 = { 0C 04 7D 65 0C 04 72 73 } //This might be a string? Looks like:}ers
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 9 files
		$x138 = { 74 74 74 74 74 52 0D 64 } //This might be a string? Looks like:tttttR\rd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x139 = "`tRttTR}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x140 = { 46 60 6C 7B 59 1A 74 77 } //This might be a string? Looks like:F`l{Ytw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x141 = { 63 6C 43 46 5C 05 60 78 } //This might be a string? Looks like:clCF\`x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x142 = { 7F 7D 6F 6D 67 61 50 6D } //This might be a string? Looks like:}omgaPm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 10 files
		$x143 = { 74 74 74 74 5C 05 6D 5E } //This might be a string? Looks like:tttt\m^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x144 = "tBttttlt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x145 = { 74 74 74 74 74 74 76 05 } //This might be a string? Looks like:ttttttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4056390622295665 Found in 7 files
		$x146 = { 7C 1A 1A 1A 1A 74 74 74 } //This might be a string? Looks like:|ttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x147 = { 0C 63 5C 1E 4C 77 02 76 } //This might be a string? Looks like:c\Lwv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 6 files
		$x148 = "|tt|epp|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x149 = { 73 0C 72 66 5F 74 74 74 } //This might be a string? Looks like:srf_ttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x150 = "`ttttt}g" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x555 = { 42 5C 7B 45 76 64 74 74 } //This might be a string? Looks like:B\{Evdtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x151 = { 4F 42 7C 59 73 00 71 05 } //This might be a string? Looks like:OB|Ysq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x152 = { 72 73 4C 6F 06 63 41 6F } //This might be a string? Looks like:rsLocAo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x153 = { 62 79 02 7C 65 46 73 7E } //This might be a string? Looks like:by|eFs~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x154 = { 76 56 5F 50 7B 67 71 0D } //This might be a string? Looks like:vV_P{gq\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x155 = "gZVXc]ot" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x156 = { 4C 54 6D 67 59 64 07 0C } //This might be a string? Looks like:LTmgYd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x157 = { 1E 71 4D 77 76 73 42 7D } //This might be a string? Looks like:qMwvsB}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x158 = { 77 04 76 56 51 72 6F 7C } //This might be a string? Looks like:wvVQro|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x159 = "t@dptttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x160 = "ttBtdttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x161 = { 78 63 5A 41 04 76 7C 5E } //This might be a string? Looks like:xcZAv|^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x562 = "t|tdtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x162 = { 52 1E 06 61 56 5F 47 74 } //This might be a string? Looks like:RaV_Gt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x163 = { 5C 6C 62 4D 77 57 72 4D } //This might be a string? Looks like:\lbMwWrM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x564 = "wtttdttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x569 = "dwtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x164 = "OxMacYPy" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x573 = "t}|tTdwB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x165 = { 65 73 5C 60 6D 0D 5C 05 } //This might be a string? Looks like:es\`m\r\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x576 = { 4F 78 5C 05 64 5E 77 7C } //This might be a string? Looks like:Ox\d^w|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x166 = "trxtWBwL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x167 = { 0C 63 5C 1E 4D 67 5C 60 } //This might be a string? Looks like:c\Mg\`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x168 = { 5D 04 76 5A 6D 74 53 64 } //This might be a string? Looks like:]vZmtSd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x169 = "xOszymvd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x170 = "EWXcwtq^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x171 = { 74 74 74 4F 42 73 06 71 } //This might be a string? Looks like:tttOBsq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x172 = "bMEPXcqV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x173 = { 7B 62 63 01 41 0C 71 7C } //This might be a string? Looks like:{bcAq|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x174 = { 5F 60 6D 05 60 65 0C 04 } //This might be a string? Looks like:_`m`e
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x175 = { 1E 73 01 42 74 74 74 7C } //This might be a string? Looks like:sBttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x176 = { 76 7F 6F 50 5F 1A 51 53 } //This might be a string? Looks like:voP_QS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x177 = "Qdtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x178 = { 1A 1A 1E 71 4D 74 42 4F } //This might be a string? Looks like:qMtBO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x593 = "wOtr^tWB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x179 = "d|wtRpdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x180 = { 00 57 42 52 52 74 4F 78 } //This might be a string? Looks like:WBRRtOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x181 = "tttrZtTR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x182 = { 78 0D 77 53 6D 59 43 7F } //This might be a string? Looks like:x\rwSmYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x597 = { 05 74 74 7C 65 70 77 7C } //This might be a string? Looks like:tt|epw|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x183 = "yp|A{v|^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x600 = { 04 59 56 06 7B 5D 6F 07 } //This might be a string? Looks like:YV{]o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x184 = "t|tt|Arv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x185 = { 00 05 60 06 67 4C 54 62 } //This might be a string? Looks like:`gLTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x186 = { 74 74 74 74 74 74 76 1E } //This might be a string? Looks like:ttttttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x187 = { 73 1A 74 70 74 74 74 77 } //This might be a string? Looks like:stptttw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x188 = { 43 1A 7D 74 76 5A 74 74 } //This might be a string? Looks like:C}tvZtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x189 = { 74 76 79 4D 59 00 51 42 } //This might be a string? Looks like:tvyMYQB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x190 = { 46 52 1E 42 64 60 04 54 } //This might be a string? Looks like:FRBd`T
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x191 = { 63 01 54 6D 67 64 56 58 } //This might be a string? Looks like:cTmgdVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x192 = { 74 74 7C 6D 74 71 01 61 } //This might be a string? Looks like:tt|mtqa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x193 = { 60 52 76 6F 5A 59 01 77 } //This might be a string? Looks like:`RvoZYw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x194 = "C~TV^ptR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x615 = "twtttdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x616 = { 73 42 64 62 4D 46 57 07 } //This might be a string? Looks like:sBdbMFW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x195 = "mtQdVOBz" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x196 = { 74 78 0D 63 64 5F 60 6D } //This might be a string? Looks like:tx\rcd_`m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x618 = "tttttsdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x197 = { 4D 63 5C 1E 4D 44 1A 07 } //This might be a string? Looks like:Mc\MD
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x198 = { 74 5C 60 64 5E 7D 7C 59 } //This might be a string? Looks like:t\`d^}|Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x199 = { 02 7C 65 46 76 73 7B 62 } //This might be a string? Looks like:|eFvs{b
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x626 = { 52 74 42 74 76 01 74 78 } //This might be a string? Looks like:RtBtvtx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x200 = { 1E 71 4D 77 64 4F 42 7A } //This might be a string? Looks like:qMwdOBz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x201 = { 41 70 7F 74 5C 79 63 76 } //This might be a string? Looks like:Apt\ycv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x630 = { 5E 74 74 74 74 74 7C 04 } //This might be a string? Looks like:^ttttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x202 = { 71 01 6D 7D 74 74 74 74 } //This might be a string? Looks like:qm}tttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x203 = { 58 79 4D 59 00 51 42 52 } //This might be a string? Looks like:XyMYQBR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x204 = { 74 74 74 71 74 79 5B 7F } //This might be a string? Looks like:tttqty[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x540 = { 77 45 74 72 01 74 6F 42 } //This might be a string? Looks like:wEtrtoB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x205 = "Xg]Qrptt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x542 = { 74 5C 1A 76 73 0C 52 1E } //This might be a string? Looks like:t\vsR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x206 = { 43 46 52 1E 42 52 5C 05 } //This might be a string? Looks like:CFRBR\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x207 = { 5C 05 60 7C 5C 05 05 78 } //This might be a string? Looks like:\`|\x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x208 = "t|twtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x209 = { 1E 71 4D 77 5C 79 61 53 } //This might be a string? Looks like:qMw\yaS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x210 = "`PmwYcBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x211 = { 79 02 7C 65 46 71 73 54 } //This might be a string? Looks like:y|eFqsT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x212 = { 71 01 62 74 74 74 74 74 } //This might be a string? Looks like:qbttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x213 = { 1A 0C 63 5C 1E 4C 71 65 } //This might be a string? Looks like:c\Lqe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x214 = { 07 63 05 63 72 59 41 6F } //This might be a string? Looks like:ccrYAo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x553 = { 6F 6D 7F 4F 54 62 0C 40 } //This might be a string? Looks like:omOTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x215 = "SBtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 8 files
		$x216 = { 62 1A 06 60 64 1A 06 60 } //This might be a string? Looks like:b`d`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 6 files
		$x217 = { 53 1A 1A 74 74 74 74 74 } //This might be a string? Looks like:Sttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x218 = { 46 71 5C 60 6C 70 6D 01 } //This might be a string? Looks like:Fq\`lpm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x219 = { 74 4F 7C 43 1A 63 6C 43 } //This might be a string? Looks like:tO|CclC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x220 = { 6D 67 45 57 07 00 77 74 } //This might be a string? Looks like:mgEWwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x221 = { 1A 0C 63 5C 1E 4D 67 52 } //This might be a string? Looks like:c\MgR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x222 = { 1A 0D 4F 42 73 0C 50 6D } //This might be a string? Looks like:\rOBsPm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x223 = { 0C 63 5C 1E 4D 44 77 72 } //This might be a string? Looks like:c\MDwr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 8 files
		$x224 = { 4F 78 4F 78 4C 79 1A 04 } //This might be a string? Looks like:OxOxLy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x225 = { 79 0D 7C 6D 07 71 01 67 } //This might be a string? Looks like:y\r|mqg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x226 = { 40 57 44 02 43 79 07 1E } //This might be a string? Looks like:@WDCy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x227 = { 06 63 42 56 72 0C 4C 51 } //This might be a string? Looks like:cBVrLQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x228 = { 61 72 0C 5F 6C 62 4D 59 } //This might be a string? Looks like:ar_lbMY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 6 files
		$x229 = { 1A 1A 1A 1A 4C 52 74 74 } //This might be a string? Looks like:LRtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x230 = { 1A 4F 60 74 74 74 74 74 } //This might be a string? Looks like:O`ttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x231 = { 67 07 63 05 61 72 73 4F } //This might be a string? Looks like:gcarsO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x571 = { 7B 59 56 5B 6F 45 6C 07 } //This might be a string? Looks like:{YV[oEl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x572 = "ttttttp]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x232 = { 76 7F 51 50 64 4F 42 71 } //This might be a string? Looks like:vQPdOBq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x233 = { 45 56 5B 67 04 6C 62 42 } //This might be a string? Looks like:EV[glbB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x234 = { 1E 63 51 42 04 62 79 02 } //This might be a string? Looks like:cQBby
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x235 = { 5C 1A 0C 63 5C 1E 4F 5A } //This might be a string? Looks like:\c\OZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x236 = { 04 58 79 1E 71 43 02 51 } //This might be a string? Looks like:XyqCQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x237 = "poLob`tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x238 = "sttttt|e" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x239 = { 60 7D 78 0D 71 45 1E 42 } //This might be a string? Looks like:`}x\rqEB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x585 = { 6C 6D 7F 00 64 64 74 74 } //This might be a string? Looks like:lmddtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x240 = { 05 64 5E 73 7C 41 78 7F } //This might be a string? Looks like:d^s|Ax
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x591 = "ttttvtpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x241 = "~Rtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x242 = { 74 74 74 1A 06 60 7C 03 } //This might be a string? Looks like:ttt`|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x243 = { 77 64 1A 0C 50 73 42 7D } //This might be a string? Looks like:wdPsB}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x595 = { 7F 43 6C 07 63 4F 56 05 } //This might be a string? Looks like:ClcOV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x244 = { 6C 43 46 63 5A 41 04 76 } //This might be a string? Looks like:lCFcZAv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x245 = "Btttttwt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x246 = { 73 07 65 4F 1A 1A 01 58 } //This might be a string? Looks like:seOX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x247 = { 7B 0C 72 66 7F 71 64 74 } //This might be a string? Looks like:{rfqdt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x248 = { 1A 0C 63 5C 1E 4D 62 03 } //This might be a string? Looks like:c\Mb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x249 = { 79 1A 04 62 79 02 65 0D } //This might be a string? Looks like:ybye\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x250 = { 76 7F 63 53 66 79 67 53 } //This might be a string? Looks like:vcSfygS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x251 = { 70 7F 74 67 62 60 7C 43 } //This might be a string? Looks like:ptgb`|C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x252 = "ygPLyv|F" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x603 = { 74 71 74 74 74 74 74 01 } //This might be a string? Looks like:tqttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x253 = { 70 63 4C 56 58 0C 4C 74 } //This might be a string? Looks like:pcLVXLt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x254 = { 63 5C 1E 4D 67 5C 60 06 } //This might be a string? Looks like:c\Mg\`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x255 = "`tVBwCt}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x256 = { 74 74 74 74 74 74 76 01 } //This might be a string? Looks like:ttttttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x257 = { 51 67 78 01 6D 53 4D 05 } //This might be a string? Looks like:QgxmSM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x258 = "~w_BRQtd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x259 = "tt|XrBtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x260 = { 0D 64 6C 6D 56 7A 79 1A } //This might be a string? Looks like:\rdlmVzy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x261 = { 78 4F 73 62 79 02 73 51 } //This might be a string? Looks like:xOsbysQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x262 = "yaSBOOP_" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 6 files
		$x263 = "tdpwtdpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x264 = { 1E 73 5E 64 74 74 74 7C } //This might be a string? Looks like:s^dttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x265 = { 4F 05 43 53 4D 5C 0C 5C } //This might be a string? Looks like:OCSM\\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x266 = { 77 5F 56 07 06 52 74 64 } //This might be a string? Looks like:w_VRtd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x629 = "pltTdwFt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x267 = { 77 62 54 6D 7B 04 6C 62 } //This might be a string? Looks like:wbTm{lb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x268 = { 63 4C 61 07 7F 44 6F 62 } //This might be a string? Looks like:cLaDob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x269 = { 62 79 02 7C 65 46 79 7C } //This might be a string? Looks like:by|eFy|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 7 files
		$x270 = { 74 74 1A 1A 1A 1A 1A 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x541 = "VRwOtr^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x271 = "XQ`PmwYc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x272 = "acYPySdL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x550 = "dtcRwYt}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x273 = { 57 78 1A 1A 1E 71 4D 77 } //This might be a string? Looks like:WxqMw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x274 = { 5C 1A 73 47 0C 52 42 71 } //This might be a string? Looks like:\sGRBq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x275 = "w]t}xtld" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x276 = "Edtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x277 = { 7D 6F 6D 67 63 56 07 63 } //This might be a string? Looks like:}omgcVc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x278 = "WBwLtr^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x279 = { 1E 1A 01 65 70 73 7C 65 } //This might be a string? Looks like:eps|e
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x280 = { 74 74 65 0D 74 74 74 71 } //This might be a string? Looks like:tte\rtttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x281 = { 62 7B 05 54 62 0C 40 74 } //This might be a string? Looks like:b{Tb@t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x282 = "toBw]trB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x283 = "gXYFo`pt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x284 = "Rptttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x285 = "Rt}xtldw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x286 = { 72 5D 46 56 7D 67 01 53 } //This might be a string? Looks like:r]FV}gS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x287 = { 5F 60 7C 78 5C 05 47 46 } //This might be a string? Looks like:_`|x\GF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x288 = "tZttttpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 8 files
		$x289 = { 74 52 06 06 5E 74 7D 60 } //This might be a string? Looks like:tR^t}`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x561 = { 74 74 74 76 01 74 74 74 } //This might be a string? Looks like:tttvttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x290 = { 62 00 5F 51 72 59 43 57 } //This might be a string? Looks like:b_QrYCW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x291 = { 7C 58 73 00 65 06 1A 1A } //This might be a string? Looks like:|Xse
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x292 = { 52 61 59 5F 56 07 06 52 } //This might be a string? Looks like:RaY_VR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x293 = { 78 0D 77 74 03 42 7C 4F } //This might be a string? Looks like:x\rwtB|O
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x294 = { 07 59 40 6F 72 0C 06 60 } //This might be a string? Looks like:Y@or`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x565 = { 6F 60 00 5D 57 62 63 6D } //This might be a string? Looks like:o`]Wbcm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x295 = { 73 7D 6F 6D 67 7B 57 07 } //This might be a string? Looks like:s}omg{W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 9 files
		$x570 = "yXgFWttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x296 = { 0C 70 71 42 46 7D 01 77 } //This might be a string? Looks like:pqBF}w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x297 = "YCWRw}om" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x298 = { 1A 1A 1E 71 40 7F 64 74 } //This might be a string? Looks like:q@dt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x299 = { 4F 6F 66 77 5F 57 07 00 } //This might be a string? Looks like:Oofw_W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x583 = "tttw`ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x300 = { 74 74 76 79 67 53 5C 7F } //This might be a string? Looks like:ttvygS\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x301 = { 1A 52 0D 64 7C 5C 05 60 } //This might be a string? Looks like:R\rd|\`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x302 = { 50 66 71 1A 4D 67 0D 7E } //This might be a string? Looks like:PfqMg\r~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x303 = { 1A 1A 52 0D 64 78 6D 56 } //This might be a string? Looks like:R\rdxmV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x304 = { 78 1A 06 60 7C 1A 4D 63 } //This might be a string? Looks like:x`|Mc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x305 = { 71 03 00 63 76 78 51 73 } //This might be a string? Looks like:qcvxQs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x306 = { 76 64 7C 5C 04 64 5E 70 } //This might be a string? Looks like:vd|\d^p
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x307 = "ttRttttp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x308 = { 02 1A 1A 01 65 70 71 7A } //This might be a string? Looks like:epqz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x309 = { 59 64 07 0C 40 56 07 0C } //This might be a string? Looks like:Yd@V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x310 = "`sr{gS]d" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x311 = { 6C 43 46 52 1E 42 60 5C } //This might be a string? Looks like:lCFRB`\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x312 = { 5B 1A 1A 01 65 70 73 7C } //This might be a string? Looks like:[eps|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x313 = "ygdMacZA" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x314 = "trptlBw]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x315 = { 1A 1A 1A 01 65 70 73 78 } //This might be a string? Looks like:epsx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x605 = { 4C 6C 6D 67 45 57 07 01 } //This might be a string? Looks like:LlmgEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x316 = { 74 03 42 7C 4F 42 73 00 } //This might be a string? Looks like:tB|OBs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x317 = { 1A 63 6C 43 46 54 52 77 } //This might be a string? Looks like:clCFTRw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 5 files
		$x318 = { 1A 74 65 1A 1A 1A 42 74 } //This might be a string? Looks like:teBt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x609 = "tWBw@ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x319 = { 6C 43 46 5C 05 60 7C 5A } //This might be a string? Looks like:lCF\`|Z
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x320 = { 53 1A 43 1A 1A 52 0D 64 } //This might be a string? Looks like:SCR\rd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x321 = "rTbMYdmg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x613 = "rdtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x322 = { 64 70 74 74 72 5A 70 03 } //This might be a string? Looks like:dpttrZp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x323 = { 1A 5D 56 77 05 76 72 5A } //This might be a string? Looks like:]VwvrZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x324 = "tvqMtdOB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x325 = { 76 7C 46 72 5C 05 74 70 } //This might be a string? Looks like:v|Fr\tp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x326 = { 01 41 7B 0C 72 66 7F 71 } //This might be a string? Looks like:A{rfq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x327 = { 77 51 42 07 5A 74 1A 06 } //This might be a string? Looks like:wQBZt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x328 = { 5C 0D 6F 50 42 52 64 74 } //This might be a string? Looks like:\\roPBRdt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x329 = { 01 5C 1E 63 51 42 01 43 } //This might be a string? Looks like:\cQBC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x330 = { 06 1E 71 07 4D 74 63 03 } //This might be a string? Looks like:qMtc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x331 = { 6C 43 46 52 1E 42 64 5C } //This might be a string? Looks like:lCFRBd\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x332 = { 43 67 07 51 7D 44 05 51 } //This might be a string? Looks like:CgQ}DQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x333 = { 51 67 71 1A 51 64 4F 5A } //This might be a string? Looks like:QgqQdOZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 7 files
		$x334 = { 1A 1A 1A 5C 05 60 7C 5C } //This might be a string? Looks like:\`|\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x335 = "ZwTRsDtz" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x633 = { 7F 59 56 07 0C 04 56 58 } //This might be a string? Looks like:YVVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x336 = { 6C 43 46 52 1E 42 64 60 } //This might be a string? Looks like:lCFRBd`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x539 = { 52 77 5D 74 72 05 74 6F } //This might be a string? Looks like:Rw]trto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x337 = "YmVexOxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x338 = { 71 01 62 6C 74 74 74 74 } //This might be a string? Looks like:qbltttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x339 = { 70 04 45 6C 06 7F 43 56 } //This might be a string? Looks like:pElCV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 4 files
		$x340 = "vtBxqtBx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x543 = "ttttttwB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x341 = { 54 52 77 44 74 7C 04 73 } //This might be a string? Looks like:TRwDt|s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x546 = { 59 67 58 59 46 6F 60 00 } //This might be a string? Looks like:YgXYFo`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x342 = "wto_^lQS" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x343 = "Wbc@Qso]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x344 = "}gVRwttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x345 = { 65 41 42 76 77 01 1A 0C } //This might be a string? Looks like:eABvw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x346 = "ttttttde" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x347 = { 5F 60 6D 05 60 7C 04 73 } //This might be a string? Looks like:_`m`|s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 7 files
		$x348 = { 70 74 6F 65 0D 04 74 74 } //This might be a string? Looks like:ptoe\rtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x554 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x349 = { 07 6C 58 73 4F 6F 66 77 } //This might be a string? Looks like:lXsOofw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x350 = { 72 0C 5D 6F 70 4D 45 6C } //This might be a string? Looks like:r]opMEl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x351 = "tpt|tvZp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x556 = { 4F 78 5C 04 64 5E 77 7C } //This might be a string? Looks like:Ox\d^w|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x352 = { 43 46 52 1E 42 56 60 04 } //This might be a string? Looks like:CFRBV`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 8 files
		$x353 = { 74 74 74 76 79 61 64 5C } //This might be a string? Looks like:tttvyad\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x354 = { 73 5B 6F 60 7F 43 50 70 } //This might be a string? Looks like:s[o`CPp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 7 files
		$x355 = "ttvqSSBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x356 = { 42 62 63 58 73 0C 5B 64 } //This might be a string? Looks like:BbcXs[d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x559 = "qRtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x357 = "epq|mtQd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x358 = { 1A 1A 1A 52 0D 64 60 52 } //This might be a string? Looks like:R\rd`R
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x359 = { 6C 64 77 06 74 7D 60 74 } //This might be a string? Looks like:ldwt}`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x360 = { 67 53 6C 62 4D 46 57 07 } //This might be a string? Looks like:gSlbMFW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x361 = { 63 5C 1E 4D 44 76 58 5A } //This might be a string? Looks like:c\MDvXZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x362 = { 1E 4C 77 02 76 52 71 74 } //This might be a string? Looks like:LwvRqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x363 = "`tlRwCt}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x364 = { 62 79 02 71 65 74 52 06 } //This might be a string? Looks like:byqetR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x365 = { 5C 7C 74 74 74 74 74 74 } //This might be a string? Looks like:\|tttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x566 = "ttttttZ~" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x366 = "tttRtxtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x568 = "ttttttvx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 9 files
		$x367 = "ttttvygd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x368 = "_et`swd`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 8 files
		$x369 = { 77 5E 5C 64 05 74 74 74 } //This might be a string? Looks like:w^\dttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 7 files
		$x579 = { 76 64 64 5C 05 64 5E 71 } //This might be a string? Looks like:vdd\d^q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x370 = "tttttwDt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x371 = { 07 63 05 61 72 73 4F 51 } //This might be a string? Looks like:carsOQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x372 = "OBpwSmYC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x373 = { 7F 43 6C 07 63 4F 56 04 } //This might be a string? Looks like:ClcOV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x374 = { 74 74 52 0D 64 78 6D 56 } //This might be a string? Looks like:ttR\rdxmV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x375 = { 05 74 74 74 74 60 65 0D } //This might be a string? Looks like:tttt`e\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x376 = { 7B 59 51 70 4D 5D 56 06 } //This might be a string? Looks like:{YQpM]V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x377 = "vwzr{OWP" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x378 = "B|tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x379 = { 7D 59 42 6F 63 0C 45 57 } //This might be a string? Looks like:}YBocEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x380 = "[}gSBwtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x381 = "xtWBwLtr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x382 = { 6F 60 7B 43 51 62 00 05 } //This might be a string? Looks like:o`{CQb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x596 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x383 = "EWXQmttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x598 = "@ttttttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x384 = { 41 60 7F 74 4C 79 61 76 } //This might be a string? Looks like:A`tLyav
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x385 = { 43 57 58 63 01 54 6D 64 } //This might be a string? Looks like:CWXcTmd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x386 = { 1A 1A 1A 1A 0D 4F 42 73 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x604 = { 05 64 62 7B 05 54 6D 6F } //This might be a string? Looks like:db{Tmo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x387 = "CrmF|ptx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x388 = { 05 78 74 74 74 74 74 74 } //This might be a string? Looks like:xtttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x389 = { 6C 43 46 5C 05 60 78 63 } //This might be a string? Looks like:lCF\`xc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x390 = { 71 01 62 54 74 74 74 74 } //This might be a string? Looks like:qbTtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x391 = { 63 5C 1E 4C 79 61 64 5D } //This might be a string? Looks like:c\Lyad]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 5 files
		$x392 = "`p`ttpBw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x393 = { 6D 67 61 50 6D 7B 05 6F } //This might be a string? Looks like:mgaPm{o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x394 = "qtttttRt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x395 = "V|xtxOxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.561278124459133 Found in 9 files
		$x396 = "ttOxOxOx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x620 = { 45 74 72 0D 74 57 52 74 } //This might be a string? Looks like:Etr\rtWRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x397 = { 72 59 5C 56 58 73 4C 50 } //This might be a string? Looks like:rY\VXsLP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 9 files
		$x398 = "ttdtwtt|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x399 = { 45 74 72 0D 74 57 52 77 } //This might be a string? Looks like:Etr\rtWRw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x622 = { 7D 7F 45 6C 5B 63 05 6F } //This might be a string? Looks like:}El[co
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x400 = "tvttPRw]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x623 = "ttw`tttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x401 = "E]WRwalm" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x402 = { 74 74 74 74 74 6C 07 0C } //This might be a string? Looks like:tttttl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x403 = { 65 7C 1A 1E 5E 43 74 64 } //This might be a string? Looks like:e|^Ctd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x404 = { 67 07 63 05 60 06 67 5D } //This might be a string? Looks like:gc`g]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x628 = { 77 05 74 72 5E 74 57 42 } //This might be a string? Looks like:wtr^tWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x405 = "tttSBttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x406 = "BQrYCW^o" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x407 = "tR}^sf|e" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x408 = { 56 77 04 77 71 65 74 03 } //This might be a string? Looks like:Vwwqet
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x409 = { 73 63 4F 6F 6D 7F 70 6F } //This might be a string? Looks like:scOompo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x410 = { 74 71 5E 76 67 07 63 05 } //This might be a string? Looks like:tq^vgc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x411 = { 1A 0D 4F 05 43 51 04 73 } //This might be a string? Looks like:\rOCQs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x412 = { 65 5D 7E 05 74 74 74 76 } //This might be a string? Looks like:e]~tttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x545 = { 5C 1A 5C 73 1A 42 1E 70 } //This might be a string? Looks like:\\sBp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x413 = "}dtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x547 = "RWbs@Pfw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x414 = "FocgEWb`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x415 = { 74 52 06 06 0D 74 7D 64 } //This might be a string? Looks like:tR\rt}d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x416 = { 0C 04 70 65 0C 04 71 7A } //This might be a string? Looks like:peqz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x417 = { 1A 1A 01 65 70 71 7C 41 } //This might be a string? Looks like:epq|A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x551 = "wttptttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x418 = { 71 65 74 6D 04 00 57 6D } //This might be a string? Looks like:qetmWm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x419 = { 1A 1E 71 4D 74 66 73 42 } //This might be a string? Looks like:qMtfsB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x420 = "rW}{}omg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x421 = "tGds}omg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x422 = { 62 73 58 7D 77 76 61 1A } //This might be a string? Looks like:bsX}wva
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x423 = "tt|epwrZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x424 = { 42 5E 77 76 43 7C 72 0D } //This might be a string? Looks like:B^wvC|r\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x425 = { 74 74 7C 43 72 6D 59 06 } //This might be a string? Looks like:tt|CrmY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x426 = { 4C 74 74 74 74 74 1E 06 } //This might be a string? Looks like:Lttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x427 = "tttttt|r" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x428 = { 07 63 5E 66 62 00 5F 56 } //This might be a string? Looks like:c^fb_V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x429 = { 74 52 06 05 7C 74 7D 64 } //This might be a string? Looks like:tR|t}d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x430 = "g`W}{aom" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x431 = "xotttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x432 = { 73 5C 05 56 70 03 42 7A } //This might be a string? Looks like:s\VpBz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x560 = { 74 61 62 59 5F 56 58 0C } //This might be a string? Looks like:tabY_VX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x433 = "ttttvtR|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x434 = "OtrxtWBw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x435 = "t|epwqet" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 7 files
		$x436 = { 0C 50 6D 56 7C 7C 74 7C } //This might be a string? Looks like:PmV||t|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x437 = "tRpttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x438 = { 74 52 0D 64 78 6D 56 7A } //This might be a string? Looks like:tR\rdxmVz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x439 = { 72 5A 74 54 52 71 1A 73 } //This might be a string? Looks like:rZtTRqs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x440 = { 60 77 64 54 52 71 1A 7B } //This might be a string? Looks like:`wdTRq{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x441 = "RSZ]woxo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 8 files
		$x442 = { 05 6D 01 74 64 74 74 74 } //This might be a string? Looks like:mtdttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x443 = "^sdfaxLy" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x575 = { 6F 45 56 06 63 5D 57 76 } //This might be a string? Looks like:oEVc]Wv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x577 = { 4F 78 5C 00 70 61 70 42 } //This might be a string? Looks like:Ox\papB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x444 = { 41 70 7F 77 76 7F 57 76 } //This might be a string? Looks like:ApwvWv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x445 = { 1A 42 74 74 74 74 71 7C } //This might be a string? Looks like:Bttttq|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x446 = { 1A 51 64 4D 44 74 65 0C } //This might be a string? Looks like:QdMDte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x447 = "gSg^ZBtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x448 = { 67 6D 56 58 59 05 6F 60 } //This might be a string? Looks like:gmVXYo`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x449 = "odwrW}{a" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 8 files
		$x581 = { 77 50 42 0D 4F 78 4F 78 } //This might be a string? Looks like:wPB\rOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x450 = "mV|ptxVw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x451 = { 07 42 67 77 05 74 01 65 } //This might be a string? Looks like:Bgwte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x452 = { 0D 04 74 74 74 74 74 7C } //This might be a string? Looks like:\rttttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x453 = "e]b`wttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x454 = { 0D 02 1A 59 00 53 51 64 } //This might be a string? Looks like:\rYSQd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x586 = { 74 54 64 77 43 74 72 01 } //This might be a string? Looks like:tTdwCtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x455 = { 71 01 66 44 74 74 74 74 } //This might be a string? Looks like:qfDtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x456 = { 05 4C 73 56 5E 70 61 1E } //This might be a string? Looks like:LsV^pa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x457 = { 74 5C 06 60 7C 5D 53 6F } //This might be a string? Looks like:t\`|]So
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x458 = { 4C 79 76 7C 46 7F 5C 60 } //This might be a string? Looks like:Lyv|F\`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x459 = "tt]Vte]{" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x460 = { 77 04 74 72 01 74 54 64 } //This might be a string? Looks like:wtrtTd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x461 = { 65 06 1A 1A 07 43 74 76 } //This might be a string? Looks like:eCtv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x462 = "Rtttt~tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x463 = { 71 64 5A 41 7C 72 00 43 } //This might be a string? Looks like:qdZA|rC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x464 = { 7F 77 66 79 67 76 64 64 } //This might be a string? Looks like:wfygvdd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x599 = { 63 01 6F 62 7B 04 51 72 } //This might be a string? Looks like:cob{Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x465 = "OxOxOszy" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x466 = { 04 73 03 73 76 7B 67 53 } //This might be a string? Looks like:ssv{gS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x467 = "tRtttttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x614 = "ttttZ~tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x468 = { 1A 63 6C 43 46 52 1E 4D } //This might be a string? Looks like:clCFRM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x617 = "ttttttsw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x469 = "tttttwtr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x470 = "]Lobs^|r" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x471 = { 40 65 1A 1A 1A 06 1A 45 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x472 = { 60 52 6C 07 0C 40 56 06 } //This might be a string? Looks like:`Rl@V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x473 = { 43 1A 1A 4D 42 74 62 74 } //This might be a string? Looks like:CMBtbt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x474 = "dBtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5 Found in 5 files
		$x475 = { 74 74 71 1A 74 74 71 1A } //This might be a string? Looks like:ttqttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x476 = { 7B 04 6C 62 42 52 64 4C } //This might be a string? Looks like:{lbBRdL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x477 = "t|tstttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x478 = "{gQMd_`m" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x479 = { 5A 6C 62 00 5E 57 72 63 } //This might be a string? Looks like:Zlb^Wrc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x480 = { 0D 71 42 46 7D 01 77 6C } //This might be a string? Looks like:\rqBF}wl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x548 = "xRtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x481 = "mgrTbMYc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x482 = "|eFrs{bc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x483 = { 79 02 7C 41 73 76 7E 78 } //This might be a string? Looks like:y|Asv~x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x484 = { 0C 42 6F 6D 7F 5D 51 72 } //This might be a string? Looks like:Bom]Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x485 = { 74 79 5B 7F 4F 56 58 78 } //This might be a string? Looks like:ty[OVXx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x486 = { 60 6D 0D 63 59 50 79 53 } //This might be a string? Looks like:`m\rcYPyS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x552 = { 6D 7F 00 74 74 74 74 74 } //This might be a string? Looks like:mttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x487 = { 1E 71 4D 77 66 7F 67 50 } //This might be a string? Looks like:qMwfgP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x488 = { 74 51 64 77 47 74 72 0D } //This might be a string? Looks like:tQdwGtr\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x489 = { 74 42 01 41 7B 0D 72 66 } //This might be a string? Looks like:tBA{\rrf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x490 = { 76 7C 59 70 5F 42 5C 79 } //This might be a string? Looks like:v|Yp_B\y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x491 = { 64 78 5D 56 77 04 76 5E } //This might be a string? Looks like:dx]Vwv^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x492 = { 58 63 71 56 58 59 05 54 } //This might be a string? Looks like:XcqVXYT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x493 = { 5C 1E 63 51 42 01 43 1A } //This might be a string? Looks like:\cQBC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x558 = { 01 07 5E 7F 74 74 74 74 } //This might be a string? Looks like:^tttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x494 = "wYtrFtTd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x495 = "ttptttxt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x496 = { 77 4F 4D 01 51 74 64 0D } //This might be a string? Looks like:wOMQtd\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x497 = { 62 0D 7A 79 61 76 64 70 } //This might be a string? Looks like:b\rzyavdp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x498 = "]]WXgFo`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x499 = { 5B 7F 59 6F 60 63 40 51 } //This might be a string? Looks like:[Yo`c@Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x500 = "Otttt|As" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x501 = { 58 52 0D 56 70 5C 57 06 } //This might be a string? Looks like:XR\rVp\W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x502 = "VXc@QsgZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x503 = { 67 61 50 6D 7B 05 6F 62 } //This might be a string? Looks like:gaPm{ob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x504 = { 65 74 62 04 0C 50 4C 56 } //This might be a string? Looks like:etbPLV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x574 = { 6F 64 77 01 74 72 60 74 } //This might be a string? Looks like:odwtr`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x505 = { 67 59 56 07 7B 4C 54 6D } //This might be a string? Looks like:gYV{LTm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x506 = { 73 78 0D 59 58 5C 64 52 } //This might be a string? Looks like:sx\rYX\dR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x580 = "rptWdwYt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 11 files
		$x507 = "}gSBwttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x508 = { 58 71 6F 53 42 74 5C 06 } //This might be a string? Looks like:XqoSBt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x584 = { 74 74 74 42 0D 4F 78 4F } //This might be a string? Looks like:tttB\rOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x588 = "]]WXgFod" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 8 files
		$x590 = { 4F 78 4F 78 4F 78 52 1E } //This might be a string? Looks like:OxOxOxR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x509 = "cMQbcOQr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x510 = { 63 05 64 07 0C 41 57 62 } //This might be a string? Looks like:cdAWb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x511 = { 74 5B 64 72 0D 03 40 73 } //This might be a string? Looks like:t[dr\r@s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x512 = { 7C 6D 59 1A 7F 42 01 43 } //This might be a string? Looks like:|mYBC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x513 = { 0D 7B 05 77 01 59 73 1A } //This might be a string? Looks like:\r{wYs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x514 = "ttttt^Rt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x515 = "vRttttBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x516 = { 5F 60 6D 05 6F 7E 78 74 } //This might be a string? Looks like:_`mo~xt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x517 = "LRttttlt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x601 = { 54 62 7B 4C 57 06 7B 43 } //This might be a string? Looks like:Tb{LW{C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x518 = "tt}Btttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x519 = { 72 0D 74 57 74 77 5D 74 } //This might be a string? Looks like:r\rtWtw]t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x520 = "Vtqtttt|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x608 = "XsFTbdRl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x521 = { 74 62 6C 43 72 6D 59 06 } //This might be a string? Looks like:tblCrmY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x522 = { 1A 1A 1E 71 4D 77 5D 51 } //This might be a string? Looks like:qMw]Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x523 = { 0C 5F 6C 62 42 52 56 06 } //This might be a string? Looks like:_lbBRV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x524 = { 64 7C 5F 60 7C 78 5C 05 } //This might be a string? Looks like:d|_`|x\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x525 = { 0C 50 62 0D 5B 76 71 74 } //This might be a string? Looks like:Pb\r[vqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x526 = { 1E 79 0D 7C 43 6D 52 56 } //This might be a string? Looks like:y\r|CmRV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 10 files
		$x621 = "wdgdttat" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x527 = "tQdwOtr^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x528 = { 6C 43 46 52 06 05 7C 74 } //This might be a string? Looks like:lCFR|t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x529 = { 41 6C 6D 67 45 57 07 01 } //This might be a string? Looks like:AlmgEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x530 = { 74 5C 7B 64 52 4C 79 66 } //This might be a string? Looks like:t\{dRLyf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x531 = "QbMYfrs@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 8 files
		$x532 = { 74 1A 06 60 60 1A 06 60 } //This might be a string? Looks like:t```
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x533 = { 5E 00 73 61 71 78 4C 74 } //This might be a string? Looks like:^saqxLt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x534 = { 74 74 74 74 74 1E 70 54 } //This might be a string? Looks like:tttttpT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x624 = "w`t}|tld" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x535 = { 63 5C 1E 4C 71 02 71 5D } //This might be a string? Looks like:c\Lqq]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x536 = "dwOtrxtW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x537 = "}twltttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x538 = "tWRwOttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x632 = "}|tldw@t" ascii

		condition:
(330 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83,$x84,$x85,$x86,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x106,$x107,$x108,$x109,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x133,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x198,$x199,$x200,$x201,$x202,$x203,$x204,$x205,$x206,$x207,$x208,$x209,$x210,$x211,$x212,$x213,$x214,$x215,$x216,$x217,$x218,$x219,$x220,$x221,$x222,$x223,$x224,$x225,$x226,$x227,$x228,$x229,$x230,$x231,$x232,$x233,$x234,$x235,$x236,$x237,$x238,$x239,$x240,$x241,$x242,$x243,$x244,$x245,$x246,$x247,$x248,$x249,$x250,$x251,$x252,$x253,$x254,$x255,$x256,$x257,$x258,$x259,$x260,$x261,$x262,$x263,$x264,$x265,$x266,$x267,$x268,$x269,$x270,$x271,$x272,$x273,$x274,$x275,$x276,$x277,$x278,$x279,$x280,$x281,$x282,$x283,$x284,$x285,$x286,$x287,$x288,$x289,$x290,$x291,$x292,$x293,$x294,$x295,$x296,$x297,$x298,$x299,$x300,$x301,$x302,$x303,$x304,$x305,$x306,$x307,$x308,$x309,$x310,$x311,$x312,$x313,$x314,$x315,$x316,$x317,$x318,$x319,$x320,$x321,$x322,$x323,$x324,$x325,$x326,$x327,$x328,$x329,$x330,$x331,$x332,$x333,$x334,$x335,$x336,$x337,$x338,$x339,$x340,$x341,$x342,$x343,$x344,$x345,$x346,$x347,$x348,$x349,$x350,$x351,$x352,$x353,$x354,$x355,$x356,$x357,$x358,$x359,$x360,$x361,$x362,$x363,$x364,$x365,$x366,$x367,$x368,$x369,$x370,$x371,$x372,$x373,$x374,$x375,$x376,$x377,$x378,$x379,$x380,$x381,$x382,$x383,$x384,$x385,$x386,$x387,$x388,$x389,$x390,$x391,$x392,$x393,$x394,$x395,$x396,$x397,$x398,$x399,$x400,$x401,$x402,$x403,$x404,$x405,$x406,$x407,$x408,$x409,$x410,$x411,$x412,$x413,$x414,$x415,$x416,$x417,$x418,$x419,$x420,$x421,$x422,$x423,$x424,$x425,$x426,$x427,$x428,$x429,$x430,$x431,$x432,$x433,$x434,$x435,$x436,$x437,$x438,$x439,$x440,$x441,$x442,$x443,$x444,$x445,$x446,$x447,$x448,$x449,$x450,$x451,$x452,$x453,$x454,$x455,$x456,$x457,$x458,$x459,$x460,$x461,$x462,$x463,$x464,$x465,$x466,$x467,$x468,$x469,$x470,$x471,$x472,$x473,$x474,$x475,$x476,$x477,$x478,$x479,$x480,$x481,$x482,$x483,$x484,$x485,$x486,$x487,$x488,$x489,$x490,$x491,$x492,$x493,$x494,$x495,$x496,$x497,$x498,$x499,$x500,$x501,$x502,$x503,$x504,$x505,$x506,$x507,$x508,$x509,$x510,$x511,$x512,$x513,$x514,$x515,$x516,$x517,$x518,$x519,$x520,$x521,$x522,$x523,$x524,$x525,$x526,$x527,$x528,$x529,$x530,$x531,$x532,$x533,$x534,$x535,$x536,$x537,$x538) ) or (61 of ($x539,$x540,$x541,$x542,$x543,$x544,$x545,$x546,$x547,$x548,$x549,$x550,$x551,$x552,$x553,$x554,$x555,$x556,$x557,$x558,$x559,$x560,$x561,$x562,$x563,$x564,$x565,$x566,$x567,$x568,$x569,$x570,$x571,$x572,$x573,$x574,$x575,$x576,$x577,$x578,$x579,$x580,$x581,$x582,$x583,$x584,$x585,$x586,$x587,$x588,$x589,$x590,$x591,$x592,$x593,$x594,$x595,$x596,$x597,$x598,$x599,$x600,$x601,$x602,$x603,$x604,$x605,$x606,$x607,$x608,$x609,$x610,$x611,$x612,$x613,$x614,$x615,$x616,$x617,$x618,$x619,$x620,$x621,$x622,$x623,$x624,$x625,$x626,$x627,$x628,$x629,$x630,$x631,$x632,$x633) )}