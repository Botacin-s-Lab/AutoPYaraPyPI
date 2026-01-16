rule 040.dll.patched_SpectralCoCluster_KMeans_k3
{
	//Input TP Rate:
	//10/15
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9669171866886992 Found in 10 files
		$x0 = "tt|ttRtpRtpttdtw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 9 files
		$x1 = { 7E 7C 67 42 7E 79 67 64 5D 50 6D 0D 5B 71 5E 7C } //This might be a string? Looks like:~|gB~ygd]Pm\r[q^|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4913146570363986 Found in 7 files
		$x2 = { 70 74 74 74 74 74 74 74 74 74 1A 1A 1A 1A 1A 42 } //This might be a string? Looks like:ptttttttttB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.271782221599798 Found in 8 files
		$x3 = { 4F 65 1A 1A 1A 42 74 74 74 74 71 1E 1A 1A 1A 1A } //This might be a string? Looks like:OeBttttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4237949406953985 Found in 7 files
		$x4 = { 74 77 74 74 74 74 74 74 74 74 74 65 1A 1A 1A 1A } //This might be a string? Looks like:twttttttttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 7 files
		$x5 = { 74 72 73 5C 6C 07 67 59 6F 58 51 5A 54 62 45 47 } //This might be a string? Looks like:trs\lgYoXQZTbEG
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 8 files
		$x6 = { 62 4D 59 51 72 63 71 56 58 59 05 54 62 7B 5D 57 } //This might be a string? Looks like:bMYQrcqVXYTb{]W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6084585933443494 Found in 7 files
		$x7 = "ZaBtdtvw@tttdtwd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 8 files
		$x8 = { 7B 59 51 70 4D 5D 56 06 67 73 56 5B 7F 43 56 52 } //This might be a string? Looks like:{YQpM]VgsV[CVR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x9 = { 6F 60 7B 4C 54 6D 67 45 6C 07 73 46 60 07 63 5F } //This might be a string? Looks like:o`{LTmgElsF`c_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 7 files
		$x10 = { 73 42 7D 64 76 1A 0C 76 71 4D 42 64 02 1A 5B 79 } //This might be a string? Looks like:sB}dvvqMBd[y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 7 files
		$x11 = "OxOxOxOxOxOxOxcl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.271782221599798 Found in 9 files
		$x12 = "xOxOxOxOxOxOxOxR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5052408149441479 Found in 7 files
		$x13 = { 1A 1A 1A 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:xOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293645 Found in 9 files
		$x14 = { 74 42 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:tB\rOxOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 10 files
		$x15 = { 58 59 05 54 62 7B 5D 57 73 7B 59 6C 06 67 45 57 } //This might be a string? Looks like:XYTb{]Ws{YlgEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 10 files
		$x16 = { 01 41 7B 0D 72 66 7F 71 64 74 74 74 74 77 6F 6D } //This might be a string? Looks like:A{\rrfqdttttwom
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x17 = { 7F 4C 6F 62 00 05 60 7D 7F 43 6C 07 63 4F 56 42 } //This might be a string? Looks like:Lob`}ClcOVB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x18 = { 46 57 62 00 43 56 7D 73 4C 56 06 67 04 51 5B 51 } //This might be a string? Looks like:FWbCV}sLVgQ[Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9197367178034823 Found in 9 files
		$x19 = { 5E 74 74 74 74 74 74 74 65 02 1A 1A 1A 0D 74 74 } //This might be a string? Looks like:^ttttttte\rtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 8 files
		$x20 = { 74 78 4F 1A 1A 1A 0D 74 74 74 74 74 1A 43 1A 1A } //This might be a string? Looks like:txO\rtttttC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 9 files
		$x21 = { 7F 04 6C 06 67 43 56 5C 77 5F 57 72 0C 4F 51 6D } //This might be a string? Looks like:lgCV\w_WrOQm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.305036532577266 Found in 9 files
		$x22 = "xOxOxOxOxOxLygvd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 7 files
		$x23 = { 57 58 56 52 6F 72 63 4F 51 7D 7F 04 6C 06 67 43 } //This might be a string? Looks like:WXVRorcOQ}lgC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x24 = { 45 6C 07 73 46 60 07 63 5F 51 72 59 43 57 52 74 } //This might be a string? Looks like:ElsF`c_QrYCWRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x25 = { 57 58 73 46 54 62 51 40 6F 62 64 74 6D 04 0C 4C } //This might be a string? Looks like:WXsFTbQ@obdtmL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 7 files
		$x26 = { 02 71 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:qOxOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.548794940695399 Found in 7 files
		$x27 = { 78 4F 78 4F 78 4F 78 4F 78 4F 7C 41 70 7F 74 67 } //This might be a string? Looks like:xOxOxOxOxO|Aptg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 7 files
		$x28 = { 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4C 79 1A 04 } //This might be a string? Looks like:OxOxOxOxOxOxLy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 7 files
		$x29 = { 4D 43 6C 62 67 78 54 62 7F 4C 6C 6D 7F 00 64 64 } //This might be a string? Looks like:MClbgxTbLlmdd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 11 files
		$x30 = "wtdpwtdpwtdpwtdp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 7 files
		$x31 = { 42 74 51 74 50 79 61 53 5C 71 6C 6D 71 0C 4C 56 } //This might be a string? Looks like:BtQtPyaS\qlmqLV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 8 files
		$x32 = { 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 5C 05 64 5E } //This might be a string? Looks like:OxOxOxOxOxOx\d^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 10 files
		$x33 = "qOxOxOxOxOxOxOxL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 9 files
		$x34 = { 5E 6C 76 5C 70 56 76 5C 05 60 7C 6D 59 1A 7F 42 } //This might be a string? Looks like:^lv\pVv\`|mYB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9772170014624826 Found in 7 files
		$x35 = "ttdpwtdpwtdpwtdp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 9 files
		$x36 = { 05 63 66 61 5E 63 78 78 4F 7C 40 6F 72 4D 46 74 } //This might be a string? Looks like:cfa^cxxO|@orMFt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x37 = "tMgSROMcv{gSw^ZB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x38 = { 7C 7D 6F 59 6C 06 67 43 56 5C 77 5E 6F 6D 7B 05 } //This might be a string? Looks like:|}oYlgCV\w^om{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x39 = { 50 47 67 07 74 43 7F 51 53 61 06 0D 01 43 42 0C } //This might be a string? Looks like:PGgtCQSa\rCB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0461796919474975 Found in 9 files
		$x40 = { 74 1A 43 1A 1A 1A 42 74 74 74 74 71 78 1A 1A 1A } //This might be a string? Looks like:tCBttttqx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 8 files
		$x41 = { 42 1E 79 77 01 6D 74 51 74 79 1A 05 7C 65 7D 77 } //This might be a string? Looks like:BywmtQty|e}w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4237949406953985 Found in 7 files
		$x42 = { 74 74 74 74 74 74 74 64 74 74 74 65 1A 1A 1A 1A } //This might be a string? Looks like:tttttttdttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.396782221599798 Found in 7 files
		$x43 = { 0C 05 70 70 77 52 74 74 74 79 52 77 74 74 74 74 } //This might be a string? Looks like:ppwRtttyRwtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.271782221599798 Found in 8 files
		$x44 = { 1A 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:OxOxOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4913146570363986 Found in 7 files
		$x45 = { 0D 74 74 74 74 74 1A 1A 1A 1A 1A 42 74 74 74 74 } //This might be a string? Looks like:\rtttttBtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x46 = { 67 53 4F 1E 1A 1A 1A 1A 03 74 5E 74 74 74 76 79 } //This might be a string? Looks like:gSOt^tttvy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 10 files
		$x47 = { 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4D 63 5C } //This might be a string? Looks like:xOxOxOxOxOxOxMc\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.3050365325772657 Found in 10 files
		$x48 = { 02 1A 1A 1A 0D 74 74 74 74 74 07 65 1A 1A 1A 42 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x49 = { 58 63 71 56 58 59 05 54 62 7B 5D 57 73 7B 59 6C } //This might be a string? Looks like:XcqVXYTb{]Ws{Yl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9772170014624826 Found in 8 files
		$x50 = "ttpwtdpwtdpwtdpw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.423794940695399 Found in 9 files
		$x51 = { 4F 78 4F 78 4F 78 4F 78 4F 78 5C 1A 0C 63 5C 1E } //This might be a string? Looks like:OxOxOxOxOx\c\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x52 = { 57 58 59 05 54 62 73 46 54 6D 45 59 64 06 7F 45 } //This might be a string? Looks like:WXYTbsFTmEYdE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 8 files
		$x53 = { 72 00 43 51 76 77 59 57 58 0C 04 6F 07 52 52 56 } //This might be a string? Looks like:rCQvwYWXoRRV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 12 files
		$x54 = "tR|vtR|vtR|vtR|v" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x55 = { 51 74 79 1A 05 7C 65 7D 77 71 43 1E 56 43 73 53 } //This might be a string? Looks like:Qty|e}wqCVCsS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x56 = { 46 6F 62 67 73 50 72 7B 59 56 7D 67 45 57 07 00 } //This might be a string? Looks like:FobgsPr{YV}gEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 8 files
		$x57 = { 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B } //This might be a string? Looks like:C\rqwBFepMVW}Lx[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 9 files
		$x58 = { 61 70 04 7A 61 04 77 67 60 59 7B 60 63 63 6F 6D } //This might be a string? Looks like:apzawg`Y{`ccom
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x59 = { 04 77 1A 5A 41 78 7F 74 64 47 42 56 7A 7B 64 53 } //This might be a string? Looks like:wZAxtdGBVz{dS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 8 files
		$x60 = { 51 58 59 4C 57 07 00 41 6F 62 00 05 60 06 67 4C } //This might be a string? Looks like:QXYLWAob`gL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 9 files
		$x61 = { 7A 06 40 02 1A 71 4D 0D 43 65 05 0C 53 57 06 1E } //This might be a string? Looks like:z@qM\rCeSW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7169171866886992 Found in 9 files
		$x62 = { 74 74 74 74 71 1E 1A 1A 1A 1A 74 74 74 74 74 7C } //This might be a string? Looks like:ttttqttttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x63 = { 05 61 62 0C 5E 51 62 4D 59 66 72 73 40 6F 72 4D } //This might be a string? Looks like:ab^QbMYfrs@orM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x64 = { 62 73 07 6F 60 7B 4C 54 6D 67 45 6C 07 73 46 60 } //This might be a string? Looks like:bso`{LTmgElsF`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293645 Found in 11 files
		$x65 = { 51 42 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:QB\rOxOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9237949406953985 Found in 7 files
		$x66 = { 74 74 74 74 74 74 74 74 74 74 76 00 05 6F 6D 5D } //This might be a string? Looks like:ttttttttttvom]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 9 files
		$x67 = "|ptxOxOxOxOxOxOx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9197367178034823 Found in 8 files
		$x68 = { 70 74 74 74 74 74 74 74 65 02 1A 1A 1A 0D 74 74 } //This might be a string? Looks like:pttttttte\rtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 8 files
		$x69 = { 5C 0D 72 79 05 64 65 72 7A 1A 00 07 76 71 43 01 } //This might be a string? Looks like:\\rryderzvqC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 7 files
		$x70 = { 64 60 63 7F 61 63 73 63 62 63 04 5D 6F 62 52 74 } //This might be a string? Looks like:d`cacscbc]obRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6774212838293645 Found in 7 files
		$x71 = "]ttOxOxOxOxOxOxO" ascii

		condition:
(44 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71) )}