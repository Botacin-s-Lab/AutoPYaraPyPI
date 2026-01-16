rule 040.dll.patched_SpectralCoClusterScale_AugmentedKMeansDBSCAN_k15
{
	//Input TP Rate:
	//6/15
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x191 = "YWXgfoms" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x6 = "mwrVXcYt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x378 = { 70 59 40 6F 58 0C 4C 57 } //This might be a string? Looks like:pY@oXLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x7 = { 62 63 4F 65 07 78 1A 1E } //This might be a string? Looks like:bcOex
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x194 = "gElXYFTm" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x382 = { 74 74 74 74 74 74 71 05 } //This might be a string? Looks like:ttttttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x13 = { 73 1A 06 60 7C 1A 0C 77 } //This might be a string? Looks like:s`|w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x383 = { 6F 06 63 41 6F 62 00 05 } //This might be a string? Looks like:ocAob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x385 = { 58 59 40 6F 04 56 74 74 } //This might be a string? Looks like:XY@oVtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x386 = { 4D 01 6D 52 1A 53 1A 1A } //This might be a string? Looks like:MmRS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x203 = { 58 0C 05 6F 62 7B 05 74 } //This might be a string? Looks like:Xob{t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x332 = "Btttt|mt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x333 = { 63 5C 1E 4D 67 60 04 6F } //This might be a string? Looks like:c\Mg`o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x209 = { 57 52 77 58 74 72 0D 74 } //This might be a string? Looks like:WRwXtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x389 = { 0D 64 78 52 06 05 7C 74 } //This might be a string? Looks like:\rdxR|t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x20 = { 64 74 76 79 67 7C 02 5E } //This might be a string? Looks like:dtvyg|^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x660 = { 7F 77 64 4F 05 43 53 4D } //This might be a string? Looks like:wdOCSM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x392 = { 0C 5D 51 72 63 01 54 6D } //This might be a string? Looks like:]QrcTm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x213 = { 74 64 07 0C 40 57 58 63 } //This might be a string? Looks like:td@WXc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x394 = { 74 74 74 74 78 0D 76 71 } //This might be a string? Looks like:ttttx\rvq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x344 = { 79 5D 50 71 0D 1A 1A 1A } //This might be a string? Looks like:y]Pq\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 7 files
		$x27 = "t`swd`sw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x29 = { 73 1A 1A 1E 71 4D 74 4C } //This might be a string? Looks like:sqMtL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x32 = "ttt|wBtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x215 = { 60 74 77 4C 74 72 0D 74 } //This might be a string? Looks like:`twLtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 9 files
		$x33 = { 53 42 77 74 74 74 74 5C } //This might be a string? Looks like:SBwtttt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 9 files
		$x400 = { 1A 1A 1A 42 70 74 74 74 } //This might be a string? Looks like:Bpttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x34 = { 6F 6D 7F 00 60 72 63 4C } //This might be a string? Looks like:om`rcL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x35 = "ttwBtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x216 = { 0C 5C 54 58 63 5F 51 74 } //This might be a string? Looks like:\TXc_Qt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x217 = "tQtwbtr`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x38 = { 63 07 59 40 6F 72 0C 06 } //This might be a string? Looks like:cY@or
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x401 = { 78 4F 78 5C 05 64 5E 76 } //This might be a string? Looks like:xOx\d^v
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x402 = { 02 1A 1A 1A 1A 1E 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x42 = { 04 64 5E 72 65 53 6C 0C } //This might be a string? Looks like:d^reSl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x45 = { 78 4F 78 60 01 41 56 7F } //This might be a string? Looks like:xOx`AV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x221 = "{Rtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x404 = { 05 54 62 73 46 54 6D 45 } //This might be a string? Looks like:TbsFTmE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x405 = { 77 45 74 72 01 74 6F 64 } //This might be a string? Looks like:wEtrtod
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x223 = { 7B 4F 6F 62 04 5C 57 7D } //This might be a string? Looks like:{Oob\W}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 10 files
		$x47 = "dtwtt|tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x224 = "ptttRttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x349 = { 42 74 1E 70 58 64 74 74 } //This might be a string? Looks like:BtpXdtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x50 = "ttrttttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x227 = { 5C 74 7D 7C 74 6C 64 77 } //This might be a string? Looks like:\t}|tldw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x229 = "^MYQXcF|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x409 = { 73 0C 74 70 74 74 74 76 } //This might be a string? Looks like:stptttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x410 = "tttt^Rtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x232 = { 7F 5D 51 72 59 43 57 52 } //This might be a string? Looks like:]QrYCWR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x233 = { 67 64 56 58 59 07 54 62 } //This might be a string? Looks like:gdVXYTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x353 = { 65 5D 6F 05 74 74 74 71 } //This might be a string? Looks like:e]otttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x414 = { 4F 78 4F 78 52 1E 42 7C } //This might be a string? Looks like:OxOxRB|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x415 = { 76 74 1E 63 42 73 71 1A } //This might be a string? Looks like:vtcBsq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x235 = { 1A 1A 0D 74 74 74 70 74 } //This might be a string? Looks like:\rtttpt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x236 = "ttttttwb" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x417 = { 6F 74 40 02 70 6F 43 05 } //This might be a string? Looks like:ot@poC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x63 = { 73 7D 6F 6D 67 71 57 07 } //This might be a string? Looks like:s}omgqW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x240 = "gZVXc]os" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x419 = { 79 5D 53 71 0C 1A 1A 1E } //This might be a string? Looks like:y]Sq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x358 = { 52 4F 42 73 0C 50 62 04 } //This might be a string? Looks like:ROBsPb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x64 = { 62 4D 59 60 72 0C 45 57 } //This might be a string? Looks like:bMY`rEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x244 = "swLTmoEW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x65 = { 5C 1E 4D 62 5C 06 60 7C } //This might be a string? Looks like:\Mb\`|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x361 = { 1A 0C 6F 62 6C 6D 74 51 } //This might be a string? Looks like:oblmtQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x362 = { 73 5E 6F 7D 7F 59 56 06 } //This might be a string? Looks like:s^o}YV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x420 = { 64 7F 7F 57 58 59 05 54 } //This might be a string? Looks like:dWXYT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x246 = { 70 73 4F 56 07 63 41 6C } //This might be a string? Looks like:psOVcAl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x67 = { 63 5C 1E 4C 79 63 64 4C } //This might be a string? Looks like:c\LycdL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x69 = { 78 4D 62 5C 06 64 5E 76 } //This might be a string? Looks like:xMb\d^v
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x421 = "^ttttt|C" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x423 = { 52 1E 42 7C 60 04 6F 6D } //This might be a string? Looks like:RB|`om
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x73 = "tdtttt|t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x252 = { 74 72 0D 74 57 64 77 41 } //This might be a string? Looks like:tr\rtWdwA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x426 = "xpcrMOg[" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x427 = "t}|tTdw@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 7 files
		$x428 = { 4F 1A 1A 42 70 74 74 74 } //This might be a string? Looks like:OBpttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x430 = "w`tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x431 = { 64 5E 7C 7C 59 70 7F 76 } //This might be a string? Looks like:d^||Ypv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x684 = { 57 72 63 40 6F 06 67 5A } //This might be a string? Looks like:Wrc@ogZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x84 = { 7A 46 76 78 0D 77 53 6D } //This might be a string? Looks like:zFvx\rwSm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x434 = { 64 74 74 53 71 05 74 74 } //This might be a string? Looks like:dttSqtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x327 = { 42 50 5E 76 0D 03 62 79 } //This might be a string? Looks like:BP^v\rby
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x91 = { 74 74 71 1A 74 74 74 74 } //This might be a string? Looks like:ttqtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x436 = "ldwOtrpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x265 = { 7F 57 5B 7B 05 6C 62 00 } //This might be a string? Looks like:W[{lb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x438 = { 71 0C 1A 1A 1E 71 4D 74 } //This might be a string? Looks like:qqMt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x646 = "wttttttd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x440 = { 74 74 74 74 52 0D 64 6C } //This might be a string? Looks like:ttttR\rdl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x647 = { 7F 51 50 61 7D 67 53 4F } //This might be a string? Looks like:QPa}gSO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x443 = { 74 74 74 7C 41 73 03 7C } //This might be a string? Looks like:ttt|As|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x444 = { 52 6C 62 4D 46 57 07 7B } //This might be a string? Looks like:RlbMFW{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x96 = "WRwYtrBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x334 = { 59 00 51 42 52 64 74 54 } //This might be a string? Looks like:YQBRdtT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x650 = { 72 64 74 57 42 77 06 74 } //This might be a string? Looks like:rdtWBwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x273 = { 5C 65 52 05 7E 7C 76 74 } //This might be a string? Looks like:\eR~|vt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x447 = { 05 05 64 7A 01 5C 46 74 } //This might be a string? Looks like:dz\Ft
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x651 = { 06 71 61 52 7B 7A 64 05 } //This might be a string? Looks like:qaR{zd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 11 files
		$x102 = "QrcrTbMY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 3 files
		$x275 = "RwYtvttV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x653 = { 47 74 4F 65 7F 64 6C 6D } //This might be a string? Looks like:GtOedlm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x449 = "^Q|f`Eya" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x450 = { 5C 74 01 65 00 76 7D 7C } //This might be a string? Looks like:\tev}|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x105 = { 7F 77 74 74 74 74 74 74 } //This might be a string? Looks like:wtttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x451 = { 57 07 04 42 57 72 63 05 } //This might be a string? Looks like:WBWrc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x277 = "tttttvtp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x337 = "ZVXc]ott" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x452 = "Bwtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x113 = "t|tttvyg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x458 = "]lRwttvq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x459 = { 74 74 74 74 74 72 47 1A } //This might be a string? Looks like:tttttrG
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x460 = "OcXsFTbg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x461 = "ds}omgqQ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x665 = { 7A 79 61 53 67 5E 5C 64 } //This might be a string? Looks like:zyaSg^\d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x121 = { 74 74 74 74 7C 04 70 7F } //This might be a string? Looks like:tttt|p
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x122 = { 05 64 5E 77 74 74 74 74 } //This might be a string? Looks like:d^wtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x281 = { 6D 77 59 67 5B 7F 43 57 } //This might be a string? Looks like:mwYg[CW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x465 = { 64 63 6F 05 50 6D 77 59 } //This might be a string? Looks like:dcoPmwY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x673 = { 78 51 70 7F 74 64 74 74 } //This might be a string? Looks like:xQptdtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x345 = { 53 02 1A 1A 01 41 73 76 } //This might be a string? Looks like:SAsv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x127 = "gdttatpp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x467 = "tttt|Asv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x129 = { 64 5E 76 7D 6C 7F 61 5C } //This might be a string? Looks like:d^v}la\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x470 = "d`Yz|rcL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x472 = "ttttttdw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x136 = { 4F 7C 41 70 7F 74 66 79 } //This might be a string? Looks like:O|Aptfy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x473 = { 02 74 4D 61 78 0C 41 62 } //This might be a string? Looks like:tMaxAb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x140 = "dRtOMlYs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x475 = { 45 51 73 77 4C 57 07 7B } //This might be a string? Looks like:EQswLW{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x289 = "twlttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x348 = { 74 74 74 74 71 02 56 70 } //This might be a string? Looks like:ttttqVp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x142 = { 70 71 7C 6D 74 71 01 62 } //This might be a string? Looks like:pq|mtqb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x143 = "tttwlttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x478 = { 71 0C 1A 1A 0C 58 5F 7E } //This might be a string? Looks like:qX_~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x146 = { 7D 77 4C 57 07 51 4C 6C } //This might be a string? Looks like:}wLWQLl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x149 = { 6C 07 0C 4C 56 58 63 5F } //This might be a string? Looks like:lLVXc_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 3 files
		$x481 = "d`ttxteY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x291 = { 74 70 51 59 51 73 7B 05 } //This might be a string? Looks like:tpQYQs{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x484 = "W^wOQrgt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 6 files
		$x152 = { 74 74 08 00 00 00 00 EF } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x154 = { 43 56 58 59 05 50 61 76 } //This might be a string? Looks like:CVXYPav
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x157 = "ttvygRfq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x160 = "tt~ttttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x489 = { 0D 5B 1A 5F 60 5E 74 52 } //This might be a string? Looks like:\r[_`^tR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x162 = { 42 74 74 52 0D 64 78 52 } //This might be a string? Looks like:BttR\rdxR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x298 = "|tldw@t}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x166 = { 53 58 74 0C 73 4C 71 5F } //This might be a string? Looks like:SXtsLq_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x490 = { 46 47 7A 05 41 57 54 06 } //This might be a string? Looks like:FGzAWT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x491 = "|roEWr`R" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x302 = "R|vttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 9 files
		$x167 = { 78 4F 78 4F 78 4D 62 5C } //This might be a string? Looks like:xOxOxMb\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x659 = { 4F 78 63 6C 43 46 52 1E } //This might be a string? Looks like:OxclCFR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x169 = "tBRdtOxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x494 = "tqtttttR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x170 = { 42 71 59 73 76 74 1E 63 } //This might be a string? Looks like:BqYsvtc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x309 = "{Ay[lO|_" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x496 = { 1A 1A 1E 71 4D 77 74 4F } //This might be a string? Looks like:qMwtO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 8 files
		$x172 = { 00 05 6F 6D 5D 05 74 74 } //This might be a string? Looks like:om]tt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 11 files
		$x173 = { 65 0C 04 70 65 0C 04 71 } //This might be a string? Looks like:epeq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x174 = { 72 63 60 54 62 04 59 74 } //This might be a string? Looks like:rc`TbYt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x313 = "tvdtttt^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x319 = { 74 72 05 74 6C 64 77 4F } //This might be a string? Looks like:trtldwO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x501 = { 1A 01 43 01 62 63 58 73 } //This might be a string? Looks like:CbcXs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x502 = { 0D 64 70 5D 56 77 05 71 } //This might be a string? Looks like:\rdp]Vwq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x503 = { 72 4D 43 6C 07 73 46 6F } //This might be a string? Looks like:rMClsFo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x322 = { 1A 53 06 0D 1A 1A 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x323 = { 01 74 6C 64 77 41 74 72 } //This might be a string? Looks like:tldwAtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 8 files
		$x376 = "qxtxRt@t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x0 = "vttttttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x1 = "ttdtttt|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x506 = { 05 66 01 7B 0C 03 74 73 } //This might be a string? Looks like:f{ts
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x3 = { 70 7F 77 74 57 63 76 64 } //This might be a string? Looks like:pwtWcvd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x4 = "]QrYCWRt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x509 = "tttttwdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x9 = "tttttvZt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x511 = "g_lbMFtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x512 = { 74 7C 6D 1A 51 58 54 71 } //This might be a string? Looks like:t|mQXTq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x197 = { 74 6F 42 77 45 74 72 01 } //This might be a string? Looks like:toBwEtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x198 = { 78 74 57 42 77 04 74 72 } //This might be a string? Looks like:xtWBwtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x329 = { 46 60 6C 7B 59 1A 74 77 } //This might be a string? Looks like:F`l{Ytw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x16 = { 06 7F 59 6C 6D 67 59 74 } //This might be a string? Looks like:YlmgYt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 6 files
		$x517 = "|tt|epp|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x518 = { 7C 43 72 6D 04 00 57 6D } //This might be a string? Looks like:|CrmWm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x17 = { 74 7F 58 5D 56 59 04 0C } //This might be a string? Looks like:tX]VY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x519 = { 63 5C 1E 4C 71 02 74 5C } //This might be a string? Looks like:c\Lqt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x520 = "`ttttt}g" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x523 = { 51 64 5F 5A 47 53 02 1A } //This might be a string? Looks like:Qd_ZGS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x525 = { 42 5C 7B 45 76 64 74 74 } //This might be a string? Looks like:B\{Evdtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x206 = { 74 70 63 40 6C 07 0C 5E } //This might be a string? Looks like:tpc@l^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x527 = { 60 7C 5C 05 05 78 5C 4D } //This might be a string? Looks like:`|\x\M
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x19 = "cr]Lobs^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x528 = { 45 52 7F 7C 6F 62 73 42 } //This might be a string? Looks like:ER|obsB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x529 = { 57 50 77 04 7E 6C 78 0C } //This might be a string? Looks like:WPw~lx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x530 = { 00 05 60 7D 7F 43 6C 07 } //This might be a string? Looks like:`}Cl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x210 = { 5E 1E 71 64 5A 52 7C 71 } //This might be a string? Looks like:^qdZR|q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x340 = { 72 0C 45 57 5B 67 59 56 } //This might be a string? Looks like:rEW[gYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x531 = "sPr{YV}g" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x212 = "wZtr^tPR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x533 = { 65 5D 74 1A 7A 5E 5C 05 } //This might be a string? Looks like:e]tz^\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x535 = { 54 64 77 4F 74 72 0D 74 } //This might be a string? Looks like:TdwOtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x538 = { 1A 42 70 74 74 74 76 79 } //This might be a string? Looks like:Bptttvy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x23 = "swd`sqZw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x30 = "wtttdttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x541 = { 71 60 07 7B 4F 52 00 7A } //This might be a string? Looks like:q`{ORz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x675 = { 05 7B 60 62 63 77 73 74 } //This might be a string? Looks like:{`bcwst
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x36 = "ttttqRtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x218 = "xtTdwDtv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x39 = { 4F 78 5C 05 64 5E 77 7C } //This might be a string? Looks like:Ox\d^w|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x219 = { 74 74 74 74 74 74 7E 1A } //This might be a string? Looks like:tttttt~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x683 = "cwLom{YW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x43 = "]vf|tttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x44 = "W[gYVXMC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 3 files
		$x46 = "|twFtrpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x550 = { 74 77 45 74 72 01 74 6F } //This might be a string? Looks like:twEtrto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x551 = { 05 77 61 65 7F 6F 5A 5E } //This might be a string? Looks like:waeoZ^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x347 = { 1A 1A 5C 1A 77 6F 62 6C } //This might be a string? Looks like:\wobl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x553 = { 61 59 00 40 53 5A 03 50 } //This might be a string? Looks like:aY@SZP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 4 files
		$x554 = "pRtttt|t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x641 = { 1E 73 01 42 74 74 74 7C } //This might be a string? Looks like:sBttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x555 = "bsFTmEYd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x645 = { 53 4D 62 63 01 41 0C 76 } //This might be a string? Looks like:SMbcAv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x556 = { 7C 41 60 7F 77 76 7F 74 } //This might be a string? Looks like:|A`wvt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x228 = "wOtr^tWB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x54 = { 05 74 74 7C 65 70 77 7C } //This might be a string? Looks like:tt|epw|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x559 = "qttttwRt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 11 files
		$x56 = { 74 74 76 79 67 64 5C 7F } //This might be a string? Looks like:ttvygd\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x57 = "X`tttttd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x237 = "db{_om{O" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x655 = { 5C 1E 4C 71 02 77 4C 79 } //This might be a string? Looks like:\LqwLy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x61 = "rwRlrwRl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x565 = "MYQrcqVX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x245 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x570 = { 73 42 64 62 4D 46 57 07 } //This might be a string? Looks like:sBdbMFW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x248 = "tttttsdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x668 = { 74 78 0D 63 64 5F 60 6D } //This might be a string? Looks like:tx\rcd_`m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x575 = { 07 57 74 74 74 74 74 72 } //This might be a string? Looks like:Wtttttr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x676 = { 74 5C 60 64 5E 7D 7C 59 } //This might be a string? Looks like:t\`d^}|Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x77 = "~ttttqtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x253 = { 01 03 56 07 7B 5A 6F 62 } //This might be a string? Looks like:V{Zob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x255 = { 52 74 42 74 76 01 74 78 } //This might be a string? Looks like:RtBtvtx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x370 = "wtttqtyX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 7 files
		$x371 = { 53 1A 1A 74 64 74 74 74 } //This might be a string? Looks like:Stdttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x579 = { 4F 78 4F 78 5C 04 64 5E } //This might be a string? Looks like:OxOx\d^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x78 = { 5C 1E 4C 79 61 64 5D 62 } //This might be a string? Looks like:\Lyad]b
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x80 = { 5E 74 74 74 74 74 7C 04 } //This might be a string? Looks like:^ttttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x583 = "wYtrxtWB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x584 = { 79 0D 6D 59 0C 57 42 1A } //This might be a string? Looks like:y\rmYWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x585 = "BwCt}|to" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 12 files
		$x82 = "ttttdtwt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x257 = { 77 45 74 72 01 74 6F 42 } //This might be a string? Looks like:wEtrtoB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x325 = { 63 71 57 07 00 4F 57 07 } //This might be a string? Looks like:cqWOW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x86 = { 74 5C 1A 76 73 0C 52 1E } //This might be a string? Looks like:t\vsR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x87 = "ttttttpv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x259 = "W^MYQXcF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x587 = "cCvqtqxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 4 files
		$x260 = { 1A 1A 0D 76 74 74 74 74 } //This might be a string? Looks like:\rvtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x589 = { 61 53 77 5E 5C 64 05 74 } //This might be a string? Looks like:aSw^\dt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x263 = { 00 1E 65 52 76 79 5C 60 } //This might be a string? Looks like:eRvy\`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x590 = { 57 73 7B 59 6C 06 67 45 } //This might be a string? Looks like:Ws{YlgE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x266 = "]trdtodw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x591 = { 0D 77 51 42 07 5A 64 54 } //This might be a string? Looks like:\rwQBZdT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x593 = { 1A 0D 74 74 74 74 74 5C } //This might be a string? Looks like:\rttttt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x95 = "ElbMEPX`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x594 = { 5D 57 72 4D 43 6C 05 77 } //This might be a string? Looks like:]WrMClw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x270 = "wttltttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x271 = { 6F 6D 7F 4F 54 62 0C 40 } //This might be a string? Looks like:omOTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x335 = { 1A 1A 0D 4F 42 72 54 7F } //This might be a string? Looks like:\rOBrT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x595 = { 77 6C 06 67 45 51 58 63 } //This might be a string? Looks like:wlgEQXc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x107 = "@orMFttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x598 = "xteYxryB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x599 = { 05 64 5E 73 72 54 7F 77 } //This might be a string? Looks like:d^srTw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x278 = { 59 6C 06 63 4C 54 6D 67 } //This might be a string? Looks like:YlcLTmg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x111 = "wtttttdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x600 = { 7A 1E 61 00 00 00 00 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x116 = "@ywZmtQt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x342 = { 5C 05 06 5A 5D 56 59 05 } //This might be a string? Looks like:\Z]VY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x601 = { 4F 73 62 79 02 7C 65 46 } //This might be a string? Looks like:Osby|eF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x603 = { 6C 7D 71 0C 52 0D 5F 1A } //This might be a string? Looks like:l}qR\r_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x118 = { 06 63 42 56 72 0C 4C 51 } //This might be a string? Looks like:cBVrLQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x119 = "|XrDtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x120 = { 72 74 04 60 70 76 52 42 } //This might be a string? Looks like:rt`pvRB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x280 = "dw_t}|tW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x606 = { 74 57 42 77 46 74 72 0D } //This might be a string? Looks like:tWBwFtr\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x674 = { 67 07 63 05 61 72 73 4F } //This might be a string? Looks like:gcarsO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x282 = { 7B 59 56 5B 6F 45 6C 07 } //This might be a string? Looks like:{YV[oEl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x607 = "YFWrc[lb" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x124 = { 77 5E 74 72 0D 74 51 42 } //This might be a string? Looks like:w^tr\rtQB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x610 = { 7E 67 76 64 7C 60 01 43 } //This might be a string? Looks like:~gvd|`C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 12 files
		$x128 = { 67 61 51 7D 7F 45 57 58 } //This might be a string? Looks like:gaQ}EWX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x285 = { 1A 1A 1A 1A 1A 4F 0D 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x612 = "p^tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x613 = { 74 74 74 5D 56 77 05 76 } //This might be a string? Looks like:ttt]Vwv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x133 = { 56 58 0C 4F 57 07 6F 05 } //This might be a string? Looks like:VXOWo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x134 = "ttdtttt`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x135 = "tttvyg]L" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x614 = { 43 1A 1A 1A 01 41 73 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x615 = { 6D 7B 05 56 58 59 5F 51 } //This might be a string? Looks like:m{VXY_Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x616 = { 7F 5D 45 77 79 44 07 66 } //This might be a string? Looks like:]EwyDf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x643 = { 74 5C 01 6D 52 1A 65 1A } //This might be a string? Looks like:t\mRe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x290 = "ttttvtpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x618 = { 52 0D 64 60 6D 56 65 78 } //This might be a string? Looks like:R\rd`mVex
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 13 files
		$x148 = "dpwtdpwt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x150 = { 7F 43 6C 07 63 4F 56 05 } //This might be a string? Looks like:ClcOV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x151 = "ttw|tttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x153 = { 78 54 62 7F 4C 6C 6D 7F } //This might be a string? Looks like:xTbLlm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x155 = { 6F 6D 67 78 6C 6D 7B 05 } //This might be a string? Looks like:omgxlm{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x156 = "V}wFTb{]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x294 = "lBwLtr^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x622 = { 1A 0C 63 5C 1E 4D 62 03 } //This might be a string? Looks like:c\Mb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x161 = { 73 05 6F 60 04 04 51 72 } //This might be a string? Looks like:so`Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x623 = { 79 1A 04 62 79 02 65 0D } //This might be a string? Looks like:ybye\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x295 = { 74 71 74 74 74 74 74 01 } //This might be a string? Looks like:tqttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x296 = { 56 07 59 43 57 5F 05 5C } //This might be a string? Looks like:VYCW_\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x164 = "QBRdtcco" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 2 files
		$x300 = { 0D 46 64 64 74 74 74 74 } //This might be a string? Looks like:\rFddtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x626 = { 74 74 74 74 74 74 76 01 } //This might be a string? Looks like:ttttttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x359 = { 46 5C 05 60 7C 63 5A 43 } //This might be a string? Looks like:F\`|cZC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x304 = { 7D 7F 59 56 6D 63 59 56 } //This might be a string? Looks like:}YVmcYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x308 = { 63 4C 56 07 59 43 57 5F } //This might be a string? Looks like:cLVYCW_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x629 = { 62 51 5B 6F 6D 7F 64 56 } //This might be a string? Looks like:bQ[omdV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x633 = { 56 06 67 4C 54 62 00 5B } //This might be a string? Looks like:VgLTb[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x314 = "ttttttqP" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x634 = { 64 7F 71 02 6F 7B 1E 56 } //This might be a string? Looks like:dqo{V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x635 = { 62 79 02 7C 41 73 71 7C } //This might be a string? Looks like:by|Asq|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x176 = { 52 57 06 7C 52 6F 72 59 } //This might be a string? Looks like:RW|RorY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x317 = "pttdpwtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x368 = { 1E 73 52 74 74 74 74 7C } //This might be a string? Looks like:sRtttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x372 = { 62 6C 6D 74 51 67 1E 71 } //This might be a string? Looks like:blmtQgq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x182 = "xOxLycvd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x639 = "dTRwDtrZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x324 = "twYtrVtl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x187 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x188 = "VRwYtrVt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x189 = "VRwOtr^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x2 = "twtttttd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x192 = { 6C 64 77 00 74 72 60 74 } //This might be a string? Looks like:ldwtr`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x377 = "tttttqpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x5 = "ttwoblCB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x379 = { 59 03 6C 6D 67 45 57 07 } //This might be a string? Looks like:YlmgEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x380 = "vqMtfyad" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x328 = { 63 5C 1E 4C 79 67 64 5D } //This might be a string? Looks like:c\Lygd]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x381 = { 43 46 52 1E 42 46 5C 05 } //This might be a string? Looks like:CFRBF\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x196 = { 45 51 7D 5E 1E 71 64 5A } //This might be a string? Looks like:EQ}^qdZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 2 files
		$x200 = { 07 74 7D 60 74 54 74 77 } //This might be a string? Looks like:t}`tTtw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x202 = { 52 64 6D 63 05 54 72 0C } //This might be a string? Looks like:RdmcTr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x384 = "sW[gYV^{" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x204 = "tWRw]trB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x336 = "ttvqMtBO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x205 = { 07 0C 42 50 6D 7F 45 6F } //This might be a string? Looks like:BPmEo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x387 = { 7D 6F 6D 67 63 56 07 63 } //This might be a string? Looks like:}omgcVc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x18 = { 62 7B 05 54 62 0C 40 74 } //This might be a string? Looks like:b{Tb@t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x388 = "Rptttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x390 = { 5C 42 03 79 60 64 67 6D } //This might be a string? Looks like:\By`dgm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x391 = { 65 46 76 73 7B 62 63 1A } //This might be a string? Looks like:eFvs{bc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x21 = { 73 77 4C 57 07 7B 59 56 } //This might be a string? Looks like:swLW{YV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x22 = "ttdtttts" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x393 = { 5F 60 7C 78 5C 05 47 46 } //This might be a string? Looks like:_`|x\GF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x25 = { 74 74 74 76 01 74 74 74 } //This might be a string? Looks like:tttvttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x395 = { 67 53 5C 79 00 63 06 71 } //This might be a string? Looks like:gS\ycq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x26 = { 0D 64 78 5D 56 77 04 70 } //This might be a string? Looks like:\rdx]Vwp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x396 = { 52 61 59 5F 56 07 06 52 } //This might be a string? Looks like:RaY_VR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x397 = "combsYTt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x398 = { 74 73 04 7E 6C 46 02 40 } //This might be a string? Looks like:ts~lF@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x214 = "vttVRwYt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x399 = { 78 6F 62 73 07 6F 60 7B } //This might be a string? Looks like:xobso`{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x37 = { 45 57 58 73 05 6F 63 77 } //This might be a string? Looks like:EWXsocw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x403 = { 07 7D 79 5A 7A 0C 5D 04 } //This might be a string? Looks like:}yZz]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x220 = { 42 78 71 4F 1A 0D 71 74 } //This might be a string? Looks like:BxqO\rqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x41 = "tRGL|e]w" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x346 = { 67 07 63 05 61 62 0C 5E } //This might be a string? Looks like:gcab^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x406 = { 7C 1A 06 70 56 5C 42 6F } //This might be a string? Looks like:|pV\Bo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x407 = "ttttbdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x222 = "tttw`ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x226 = "tt{dtttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x408 = "fBtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x49 = "xOxMacYP" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x230 = { 74 64 76 00 4C 6F 62 4D } //This might be a string? Looks like:tdvLobM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x411 = { 7C 77 71 03 46 70 7F 7A } //This might be a string? Looks like:|wqFpz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x412 = "ttRttttp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x231 = "tVBwOtr`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x413 = { 67 59 67 58 0C 4C 57 62 } //This might be a string? Looks like:gYgXLWb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x53 = { 01 43 0D 74 74 74 76 7F } //This might be a string? Looks like:C\rtttv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x55 = "Rw^trBtW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x416 = "vSt^]Ylm" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x60 = "cFo`]]WX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x418 = { 1A 63 6C 43 46 54 52 77 } //This might be a string? Looks like:clCFTRw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x241 = "tWBw@ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x242 = { 6C 07 0C 41 7A 58 73 4F } //This might be a string? Looks like:lAzXsO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x243 = { 77 43 74 72 01 74 74 74 } //This might be a string? Looks like:wCtrttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x667 = { 01 41 7B 0C 72 66 7F 71 } //This might be a string? Looks like:A{rfq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x71 = { 5C 06 64 5E 70 73 50 79 } //This might be a string? Looks like:\d^psPy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x250 = { 76 01 74 6F 64 77 01 74 } //This might be a string? Looks like:vtodwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x72 = "fxprqtbR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x422 = "tttttt`_" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x424 = { 74 57 42 77 05 74 72 70 } //This might be a string? Looks like:tWBwtrp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x251 = { 43 1A 1A 1A 1A 02 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x425 = { 52 57 06 77 59 57 5C 77 } //This might be a string? Looks like:RWwYW\w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x74 = { 73 06 71 4F 78 4F 78 4F } //This might be a string? Looks like:sqOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x76 = { 06 60 64 1A 06 60 78 63 } //This might be a string? Looks like:`d`xc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x375 = { 78 63 5A 41 04 76 73 56 } //This might be a string? Looks like:xcZAvsV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x429 = "vqMtfyMY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x681 = { 43 67 07 51 7D 44 05 51 } //This might be a string? Looks like:CgQ}DQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x79 = { 62 0D 7C 7C 74 78 4F 78 } //This might be a string? Looks like:b\r||txOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 4 files
		$x256 = { 74 65 1A 1A 74 74 71 1A } //This might be a string? Looks like:tettq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x81 = { 5E 51 59 51 73 7B 00 56 } //This might be a string? Looks like:^QYQs{V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x83 = "ttttttvp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x326 = { 73 1E 79 4D 59 00 51 62 } //This might be a string? Looks like:syMYQb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x432 = { 1A 0C 0C 52 57 42 65 53 } //This might be a string? Looks like:RWBeS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x258 = { 7D 73 5C 44 4F 04 64 57 } //This might be a string? Looks like:}s\DOdW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x433 = { 74 59 6D 1A 4C 7D 44 7B } //This might be a string? Looks like:tYmL}D{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x88 = "gElbMEPX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x89 = { 52 66 4C 1A 6C 54 77 05 } //This might be a string? Looks like:RfLlTw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x435 = "ttt|ttdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x437 = { 59 67 58 59 46 6F 60 00 } //This might be a string? Looks like:YgXYFo`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x264 = "{YQ}gEWX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x439 = { 42 74 1A 5F 1A 7F 7F 6D } //This might be a string? Looks like:Bt_m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x441 = "ttv{ovdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x442 = { 71 01 62 61 74 74 74 74 } //This might be a string? Looks like:qbatttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x445 = "ttttttde" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x97 = { 63 5C 1E 4D 67 60 63 54 } //This might be a string? Looks like:c\Mg`cT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x446 = { 64 7F 4D 05 60 60 76 52 } //This might be a string? Looks like:dM``vR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 4 files
		$x98 = { 04 02 71 4F 78 4F 78 4F } //This might be a string? Looks like:qOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x274 = "XsOTbxtd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x100 = "v^tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x101 = "tfdw@t}d" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x448 = { 6D 7F 45 6C 62 7F 46 6F } //This might be a string? Looks like:mElbFo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x103 = { 04 59 57 5B 67 61 51 7D } //This might be a string? Looks like:YW[gaQ}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x276 = "tpxtWBwB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x104 = { 4F 78 5C 04 64 5E 77 7C } //This might be a string? Looks like:Ox\d^w|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x453 = { 1E 1A 01 41 60 7F 74 5C } //This might be a string? Looks like:A`t\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 8 files
		$x454 = { 74 74 74 76 79 61 64 5C } //This might be a string? Looks like:tttvyad\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 6 files
		$x658 = "tt|epq|e" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 8 files
		$x455 = "ttpwtdpw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x110 = { 73 5B 6F 60 7F 43 50 70 } //This might be a string? Looks like:s[o`CPp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x339 = "wqWrsOVL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x456 = { 74 5E 51 59 51 73 7B 05 } //This might be a string? Looks like:t^QYQs{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x112 = { 1A 1A 1E 71 4D 77 71 45 } //This might be a string? Looks like:qMwqE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x341 = { 42 62 63 58 73 0C 5B 64 } //This might be a string? Looks like:BbcXs[d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x457 = { 64 47 5E 51 79 07 71 42 } //This might be a string? Looks like:dG^QyqB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x117 = { 74 74 7F 74 74 74 74 77 } //This might be a string? Looks like:ttttttw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x462 = "e]l|tttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x463 = { 77 7C 47 4C 59 73 64 03 } //This might be a string? Looks like:w|GLYsd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x464 = { 1E 4C 77 02 76 52 71 74 } //This might be a string? Looks like:LwvRqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x466 = "ttttttZ~" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 8 files
		$x468 = { 77 5E 5C 64 05 74 74 74 } //This might be a string? Looks like:w^\dttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 7 files
		$x130 = { 76 64 64 5C 05 64 5E 71 } //This might be a string? Looks like:vdd\d^q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x469 = "Qrc_Qttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x682 = "xVRMOq}d" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x131 = { 7F 59 6C 6D 67 59 67 58 } //This might be a string? Looks like:YlmgYgX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x132 = { 53 67 67 7D 5C 04 64 5E } //This might be a string? Looks like:Sgg}\d^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x471 = "Dds}omgq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x137 = { 07 63 05 61 72 73 4F 51 } //This might be a string? Looks like:carsOQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x139 = { 5C 51 62 6F 58 6F 6D 7C } //This might be a string? Looks like:\QboXom|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x474 = { 77 67 07 63 05 64 60 7B } //This might be a string? Looks like:wgcd`{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x476 = { 6D 59 06 71 4F 78 4F 78 } //This might be a string? Looks like:mYqOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x288 = "tslt`BwS" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x477 = { 4F 78 4D 63 5C 1E 4C 71 } //This might be a string? Looks like:OxMc\Lq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 12 files
		$x144 = "{CW[{CWr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x145 = "waccTyQv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 8 files
		$x479 = { 71 01 6D 67 74 74 74 74 } //This might be a string? Looks like:qmgtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x351 = "clCF`csb" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x480 = { 7C 46 7D 7F 53 1A 1A 1A } //This might be a string? Looks like:|F}S
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x482 = "RwDtrZtT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x292 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x483 = { 52 6F 5B 63 40 6C 06 67 } //This might be a string? Looks like:Ro[c@lg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x485 = "YLQ}c]Wp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x486 = "tvttQtwC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x648 = "EWXQmttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x293 = "@ttttttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x487 = { 74 74 74 74 74 5C 05 01 } //This might be a string? Looks like:ttttt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x488 = { 77 74 72 61 1A 7B 64 74 } //This might be a string? Looks like:wtra{dt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x297 = { 67 59 6C 5B 63 5B 6F 07 } //This might be a string? Looks like:gYl[c[o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 6 files
		$x299 = { 1A 0D 74 1A 1A 1A 1A 74 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x354 = { 1A 1A 1A 1A 0D 4F 42 73 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x165 = { 74 74 76 73 1A 42 1E 70 } //This might be a string? Looks like:ttvsBp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x492 = { 0D 74 66 64 77 7A 74 70 } //This might be a string? Looks like:\rtfdwztp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x168 = "YtrxtQdw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 9 files
		$x357 = "}gSBtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x493 = { 73 46 54 6D 45 59 64 06 } //This might be a string? Looks like:sFTmEYd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 2 files
		$x305 = "tvttWdwY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 3 files
		$x307 = { 53 1A 0C 53 6D 04 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x495 = "qtttttRt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x171 = { 7A 6C 62 04 59 63 42 74 } //This might be a string? Looks like:zlbYcBt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x363 = "oP_}gSBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x497 = { 6C 6D 7F 5B 51 62 04 59 } //This might be a string? Looks like:lm[QbY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x364 = { 74 51 53 58 7C 6D 1A 02 } //This might be a string? Looks like:tQSX|m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x498 = "`{LTmgEl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x315 = { 77 61 50 6D 7B 05 6F 62 } //This might be a string? Looks like:waPm{ob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x316 = "ttttptwR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x367 = { 5B 6F 45 56 58 0C 40 57 } //This might be a string? Looks like:[oEVX@W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x499 = "ZtTRwDtz" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x669 = { 72 59 5C 56 58 73 4C 50 } //This might be a string? Looks like:rY\VXsLP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 9 files
		$x175 = "ttdtwtt|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x318 = { 7D 7F 45 6C 5B 63 05 6F } //This might be a string? Looks like:}El[co
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x500 = "Zttttxtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x177 = { 7F 57 58 59 05 54 62 73 } //This might be a string? Looks like:WXYTbs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x178 = "sQEorcqT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x321 = { 77 05 74 72 5E 74 57 42 } //This might be a string? Looks like:wtr^tWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x180 = { 4D 4F 51 7D 7F 46 6F 62 } //This might be a string? Looks like:MOQ}Fob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x181 = { 1E 73 7B 53 1A 1A 1A 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x680 = "tttSBttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x184 = "mgYgXYFo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x186 = "OBpqGt_e" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x504 = { 7A 6D 05 64 51 79 6C 00 } //This might be a string? Looks like:zmdQyl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x505 = "teYxryBV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x190 = "tpRttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x507 = { 74 74 71 0D 74 74 74 74 } //This might be a string? Looks like:ttq\rtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x508 = { 1A 53 1A 1A 5B 7C 1E 73 } //This might be a string? Looks like:S[|s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x644 = "_TrcAlmx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x193 = "dwLt}xtT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x8 = { 07 54 6D 7F 43 57 58 04 } //This might be a string? Looks like:TmCWX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x10 = "RWbs@Pfw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x510 = { 51 77 70 4F 0C 59 6F 62 } //This might be a string? Looks like:QwpOYob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x11 = { 74 7C 04 78 7F 74 4F 5A } //This might be a string? Looks like:t|xtOZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x195 = "ttttwttl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x12 = "ttwdtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x513 = { 7A 52 77 67 07 63 05 61 } //This might be a string? Looks like:zRwgca
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x14 = { 05 60 06 67 4C 54 62 00 } //This might be a string? Looks like:`gLTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x15 = "om{Ofrc]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x199 = "wttptttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x514 = "Bxa|O{q`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x201 = { 6F 63 67 00 56 72 60 74 } //This might be a string? Looks like:ocgVr`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x331 = { 71 65 74 6D 04 00 57 6D } //This might be a string? Looks like:qetmWm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x515 = { 74 7D 5A 70 63 07 59 5E } //This might be a string? Looks like:t}ZpcY^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x516 = "tGds}omg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x521 = { 00 57 5C 1E 63 51 60 56 } //This might be a string? Looks like:W\cQ`V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x522 = { 62 73 58 7D 77 76 61 1A } //This might be a string? Looks like:bsX}wva
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x524 = { 1E 79 07 7A 46 7E 4D 01 } //This might be a string? Looks like:yzF~M
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x654 = { 42 5E 77 76 43 7C 72 0D } //This might be a string? Looks like:B^wvC|r\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x526 = { 7C 74 74 74 74 5C 60 6D } //This might be a string? Looks like:|tttt\`m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x207 = { 62 63 05 54 72 0C 5E 66 } //This might be a string? Looks like:bcTr^f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x208 = "wAtrptVR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x657 = { 1E 4D 62 5C 1A 72 79 61 } //This might be a string? Looks like:Mb\rya
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x338 = "tttttt|r" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x532 = { 1A 1A 1A 1A 52 06 05 7C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x211 = "rBtaRw]t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x534 = { 62 01 43 59 6D 56 7C 7C } //This might be a string? Looks like:bCYmV||
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x536 = { 60 7C 5C 60 6D 01 5C 05 } //This might be a string? Looks like:`|\`m\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x537 = "WB]ttOxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x24 = { 74 61 62 59 5F 56 58 0C } //This might be a string? Looks like:tabY_VX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x539 = { 06 76 76 74 71 78 4F 78 } //This might be a string? Looks like:vvtqxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x28 = "ttttvtR|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x540 = "tsxtQtwL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x31 = { 71 51 6D 76 64 7C 06 60 } //This might be a string? Looks like:qQmvd|`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x670 = "OtrxtWBw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x542 = { 51 73 7B 05 56 58 59 40 } //This might be a string? Looks like:Qs{VXY@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x40 = { 4F 78 5C 00 70 61 70 42 } //This might be a string? Looks like:Ox\papB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x543 = "gSg^ZBtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x544 = { 7C 73 02 7F 42 01 43 1A } //This might be a string? Looks like:|sBC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x545 = { 5E 54 6D 7F 59 6C 06 67 } //This might be a string? Looks like:^TmYlg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x546 = { 00 6D 67 74 65 5D 7B 60 } //This might be a string? Looks like:mgte]{`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x547 = { 43 51 6D 7F 5F 6F 66 77 } //This might be a string? Looks like:CQm_ofw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x548 = { 01 1A 64 72 73 5C 6C 07 } //This might be a string? Looks like:drs\l
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x549 = { 43 1A 51 77 0C 44 74 7C } //This might be a string? Looks like:CQwDt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x552 = "bsFTmE]Q" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x640 = "tr`tPtwY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x225 = { 74 60 06 59 4F 51 72 63 } //This might be a string? Looks like:t`YOQrc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x642 = { 43 6C 07 63 4F 56 42 71 } //This might be a string? Looks like:ClcOVBq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x48 = { 05 70 74 74 74 74 74 74 } //This might be a string? Looks like:ptttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x557 = { 53 6D 04 00 57 5C 1E 63 } //This might be a string? Looks like:SmW\c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x51 = { 59 57 72 63 05 6F 60 6F } //This might be a string? Looks like:YWrco`o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x52 = { 7F 7F 42 74 74 74 76 79 } //This might be a string? Looks like:Btttvy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 10 files
		$x352 = "tttt|mtQ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x558 = "tttttvya" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x234 = { 63 01 6F 62 7B 04 51 72 } //This might be a string? Looks like:cob{Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x560 = "ttttpsvd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x58 = { 43 01 52 0D 64 78 5D 53 } //This might be a string? Looks like:CR\rdx]S
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 7 files
		$x59 = { 05 6F 6D 5D 05 74 74 74 } //This might be a string? Looks like:om]ttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x238 = "wLtr^toR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x239 = { 51 7D 67 4C 54 62 7F 04 } //This might be a string? Looks like:Q}gLTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x62 = { 06 07 77 43 74 52 1E 76 } //This might be a string? Looks like:wCtRv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x561 = { 64 5C 6D 01 60 56 52 7E } //This might be a string? Looks like:d\m`VR~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x562 = { 47 07 72 5A 74 5F 6C 60 } //This might be a string? Looks like:GrZt_l`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x563 = { 59 4F 6F 60 63 01 6C 07 } //This might be a string? Looks like:YOo`cl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x564 = "B}dxTRwD" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x566 = { 05 74 72 60 74 57 52 77 } //This might be a string? Looks like:tr`tWRw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x567 = { 74 60 72 77 42 52 7F 76 } //This might be a string? Looks like:t`rwBRv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x568 = { 7F 74 52 47 4C 7C 65 5D } //This might be a string? Looks like:tRGL|e]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x66 = "ttttZ~tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x569 = { 6D 01 43 72 6D 59 06 76 } //This might be a string? Looks like:mCrmYv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x247 = "wat}dtVR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.561278124459133 Found in 9 files
		$x571 = "ttxOxOxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x664 = { 51 70 73 5F 51 72 59 07 } //This might be a string? Looks like:Qps_QrY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x68 = "tttt}Btt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x70 = { 04 57 7D 67 45 64 5B 59 } //This might be a string? Looks like:W}gEd[Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x249 = "wBtrptWR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x572 = { 74 72 0D 74 57 52 77 45 } //This might be a string? Looks like:tr\rtWRwE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x573 = "ttGds}om" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x574 = "Q}c]WpoL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x671 = "Rt}VtTdw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x369 = { 04 62 79 02 73 54 79 51 } //This might be a string? Looks like:bysTyQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x576 = "ttVtwCt}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 4 files
		$x75 = "OxOxOs{c" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x577 = { 06 67 5F 6C 62 4D 46 74 } //This might be a string? Looks like:g_lbMFt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x254 = "ttttttwE" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x578 = "o]WrY^|}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x373 = { 73 50 79 1E 71 43 72 56 } //This might be a string? Looks like:sPyqCrV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x374 = { 74 74 74 5C 1A 76 71 4D } //This might be a string? Looks like:ttt\vqM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x580 = { 07 4D 59 61 06 63 05 56 } //This might be a string? Looks like:MYacV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x581 = "te]x`ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x582 = { 5F 1A 1A 01 65 70 73 7C } //This might be a string? Looks like:_eps|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x586 = { 74 74 52 0D 64 70 5C 05 } //This might be a string? Looks like:ttR\rdp\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x85 = { 57 07 7B 5D 51 72 59 43 } //This might be a string? Looks like:W{]QrYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x90 = "CVY{EWXQ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x261 = "omgYV[xt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x588 = { 74 74 74 74 5C 05 60 78 } //This might be a string? Looks like:tttt\`x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x92 = { 74 74 76 73 0C 52 1E 70 } //This might be a string? Looks like:ttvsRp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x262 = "tqtttvtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x267 = { 66 6F 6D 73 04 6F 6D 7B } //This might be a string? Looks like:fomsom{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x330 = { 74 74 76 79 51 64 5C 73 } //This might be a string? Looks like:ttvyQd\s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x93 = { 41 70 7F 74 61 06 01 56 } //This might be a string? Looks like:AptaV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x592 = "wwt|mtQd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x94 = { 62 79 02 73 72 7F 61 53 } //This might be a string? Looks like:bysraS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x268 = "dtttw`t}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x269 = { 03 1E 43 47 1A 1E 4F 46 } //This might be a string? Looks like:CGOF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 2 files
		$x272 = { 74 74 42 74 74 64 77 7F } //This might be a string? Looks like:ttBttdw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x99 = { 5C 1E 4C 79 63 64 5D 62 } //This might be a string? Looks like:\Lycd]b
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x652 = "obgsPr{Z" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x596 = "Wrc`PmwY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x597 = "Pr{YV}gE" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x106 = { 01 07 5E 7F 74 74 74 74 } //This might be a string? Looks like:^tttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x656 = { 64 4C 71 6F 53 42 74 03 } //This might be a string? Looks like:dLqoSBt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x108 = "ttptttxt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x109 = "wpobMYQr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x114 = { 74 58 54 73 4C 6D 6D 04 } //This might be a string? Looks like:tXTsLmm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x279 = "t}xtTdwC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x115 = "Mg`cTyQd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x661 = "trxtWBw^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x343 = { 62 0D 7A 79 61 76 64 70 } //This might be a string? Looks like:b\rzyavdp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x602 = "w]tr|tod" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x662 = { 74 56 52 77 59 74 72 01 } //This might be a string? Looks like:tVRwYtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x604 = "gC|rY@Tm" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x605 = { 59 5D 57 5C 04 7A 50 62 } //This might be a string? Looks like:Y]W\zPb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x123 = { 67 61 50 6D 7B 05 6F 62 } //This might be a string? Looks like:gaPm{ob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x283 = { 7D 59 7F 6F 72 63 40 51 } //This might be a string? Looks like:}Yorc@Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x284 = "tWBw@tqZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x608 = { 03 4D 06 7C 72 7A 46 7B } //This might be a string? Looks like:M|rzF{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x609 = { 51 72 63 71 57 07 00 4F } //This might be a string? Looks like:QrcqWO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x125 = "|}{YQttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 4 files
		$x126 = "xOxOx`c{" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x611 = { 50 58 73 05 54 62 0C 40 } //This might be a string? Looks like:PXsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x678 = { 67 59 56 07 7B 4C 54 6D } //This might be a string? Looks like:gYV{LTm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x679 = "gqDT@Zw[" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x286 = "r]Lobs^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x287 = "trVtldwF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x138 = { 74 74 74 42 0D 4F 78 4F } //This might be a string? Looks like:tttB\rOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 8 files
		$x141 = { 4F 78 4F 78 4F 78 52 1E } //This might be a string? Looks like:OxOxOxR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x350 = { 60 4F 65 57 63 59 56 02 } //This might be a string? Looks like:`OeWcYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x617 = "xtmBwbtp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x147 = "ttt}Bttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x619 = "trZtTRqZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x620 = { 1A 1A 1A 4D 42 74 7F 74 } //This might be a string? Looks like:MBtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x649 = { 1A 66 67 0C 01 42 41 7B } //This might be a string? Looks like:fgBA{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x158 = "c{s`_xLy" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x159 = { 66 77 59 56 5B 7F 43 56 } //This might be a string? Looks like:fwYV[CV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x621 = "ttttt^Rt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x163 = { 05 60 7C 5C 1E 63 51 42 } //This might be a string? Looks like:`|\cQB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x355 = { 64 5E 70 7C 41 70 7F 77 } //This might be a string? Looks like:d^p|Apw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x356 = { 74 6D 04 00 57 4C 56 7B } //This might be a string? Looks like:tmWLV{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x301 = { 70 74 51 64 77 05 74 72 } //This might be a string? Looks like:ptQdwtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x624 = "XsFTbdRl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 2 files
		$x303 = "pttvtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x625 = "tttcBttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x627 = { 6D 67 59 56 5E 00 5D 57 } //This might be a string? Looks like:mgYV^]W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x360 = { 74 62 6C 43 72 6D 59 06 } //This might be a string? Looks like:tblCrmY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x628 = { 74 52 0D 64 70 78 0D 71 } //This might be a string? Looks like:tR\rdpx\rq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x306 = "ttrRpttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x310 = "qttxttBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x311 = "`ttdtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x312 = { 07 6F 6D 7F 4F 54 62 0C } //This might be a string? Looks like:omOTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x630 = "optttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x663 = { 74 76 71 1E 74 7C 65 5D } //This might be a string? Looks like:tvqt|e]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x631 = "tptttqGq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x632 = "r]Lobs^f" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x666 = { 52 74 51 64 77 05 74 72 } //This might be a string? Looks like:RtQdwtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x365 = { 64 52 77 51 42 01 43 1A } //This might be a string? Looks like:dRwQBC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x366 = { 56 51 73 1A 74 7C 74 74 } //This might be a string? Looks like:VQst|tt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x672 = "QbMYfrs@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x636 = "Zttttptt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x637 = { 74 76 01 74 64 74 74 74 } //This might be a string? Looks like:tvtdttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x638 = { 1A 43 0D 74 74 64 7C 71 } //This might be a string? Looks like:C\rttd|q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x320 = "w`t}|tld" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x677 = { 63 5C 1E 4C 71 02 71 5D } //This might be a string? Looks like:c\Lqq]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x179 = { 54 60 7F 00 51 72 60 74 } //This might be a string? Looks like:T`Qr`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x183 = { 43 6D 1A 1A 01 65 70 71 } //This might be a string? Looks like:Cmepq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x185 = "txRt@trd" ascii

		condition:
(149 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83,$x84,$x85,$x86,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x106,$x107,$x108,$x109,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x133,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186) ) or (114 of ($x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x198,$x199,$x200,$x201,$x202,$x203,$x204,$x205,$x206,$x207,$x208,$x209,$x210,$x211,$x212,$x213,$x214,$x215,$x216,$x217,$x218,$x219,$x220,$x221,$x222,$x223,$x224,$x225,$x226,$x227,$x228,$x229,$x230,$x231,$x232,$x233,$x234,$x235,$x236,$x237,$x238,$x239,$x240,$x241,$x242,$x243,$x244,$x245,$x246,$x247,$x248,$x249,$x250,$x251,$x252,$x253,$x254,$x255,$x256,$x257,$x258,$x259,$x260,$x261,$x262,$x263,$x264,$x265,$x266,$x267,$x268,$x269,$x270,$x271,$x272,$x273,$x274,$x275,$x276,$x277,$x278,$x279,$x280,$x281,$x282,$x283,$x284,$x285,$x286,$x287,$x288,$x289,$x290,$x291,$x292,$x293,$x294,$x295,$x296,$x297,$x298,$x299,$x300,$x301,$x302,$x303,$x304,$x305,$x306,$x307,$x308,$x309,$x310,$x311,$x312,$x313,$x314,$x315,$x316,$x317,$x318,$x319,$x320,$x321,$x322,$x323,$x324) ) or (39 of ($x325,$x326,$x327,$x328,$x329,$x330,$x331,$x332,$x333,$x334,$x335,$x336,$x337,$x338,$x339,$x340,$x341,$x342,$x343,$x344,$x345,$x346,$x347,$x348,$x349,$x350,$x351,$x352,$x353,$x354,$x355,$x356,$x357,$x358,$x359,$x360,$x361,$x362,$x363,$x364,$x365,$x366,$x367,$x368,$x369,$x370,$x371,$x372,$x373,$x374,$x375,$x376) ) or (211 of ($x377,$x378,$x379,$x380,$x381,$x382,$x383,$x384,$x385,$x386,$x387,$x388,$x389,$x390,$x391,$x392,$x393,$x394,$x395,$x396,$x397,$x398,$x399,$x400,$x401,$x402,$x403,$x404,$x405,$x406,$x407,$x408,$x409,$x410,$x411,$x412,$x413,$x414,$x415,$x416,$x417,$x418,$x419,$x420,$x421,$x422,$x423,$x424,$x425,$x426,$x427,$x428,$x429,$x430,$x431,$x432,$x433,$x434,$x435,$x436,$x437,$x438,$x439,$x440,$x441,$x442,$x443,$x444,$x445,$x446,$x447,$x448,$x449,$x450,$x451,$x452,$x453,$x454,$x455,$x456,$x457,$x458,$x459,$x460,$x461,$x462,$x463,$x464,$x465,$x466,$x467,$x468,$x469,$x470,$x471,$x472,$x473,$x474,$x475,$x476,$x477,$x478,$x479,$x480,$x481,$x482,$x483,$x484,$x485,$x486,$x487,$x488,$x489,$x490,$x491,$x492,$x493,$x494,$x495,$x496,$x497,$x498,$x499,$x500,$x501,$x502,$x503,$x504,$x505,$x506,$x507,$x508,$x509,$x510,$x511,$x512,$x513,$x514,$x515,$x516,$x517,$x518,$x519,$x520,$x521,$x522,$x523,$x524,$x525,$x526,$x527,$x528,$x529,$x530,$x531,$x532,$x533,$x534,$x535,$x536,$x537,$x538,$x539,$x540,$x541,$x542,$x543,$x544,$x545,$x546,$x547,$x548,$x549,$x550,$x551,$x552,$x553,$x554,$x555,$x556,$x557,$x558,$x559,$x560,$x561,$x562,$x563,$x564,$x565,$x566,$x567,$x568,$x569,$x570,$x571,$x572,$x573,$x574,$x575,$x576,$x577,$x578,$x579,$x580,$x581,$x582,$x583,$x584,$x585,$x586,$x587,$x588,$x589,$x590,$x591,$x592,$x593,$x594,$x595,$x596,$x597,$x598,$x599,$x600,$x601,$x602,$x603,$x604,$x605,$x606,$x607,$x608,$x609,$x610,$x611,$x612,$x613,$x614,$x615,$x616,$x617,$x618,$x619,$x620,$x621,$x622,$x623,$x624,$x625,$x626,$x627,$x628,$x629,$x630,$x631,$x632,$x633,$x634,$x635,$x636,$x637,$x638,$x639) ) or (34 of ($x640,$x641,$x642,$x643,$x644,$x645,$x646,$x647,$x648,$x649,$x650,$x651,$x652,$x653,$x654,$x655,$x656,$x657,$x658,$x659,$x660,$x661,$x662,$x663,$x664,$x665,$x666,$x667,$x668,$x669,$x670,$x671,$x672,$x673,$x674,$x675,$x676,$x677,$x678,$x679,$x680,$x681,$x682,$x683,$x684) )}