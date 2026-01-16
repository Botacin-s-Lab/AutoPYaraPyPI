rule 040.dll.patched_SpectralCoCluster_AugmentedKMeansVT_k15
{
	//Input TP Rate:
	//2/15
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x4 = "gElXYFTm" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x209 = { 61 62 63 4F 56 07 73 5B } //This might be a string? Looks like:abcOVs[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x211 = "Foc{EPX`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x7 = { 58 0C 05 6F 62 7B 05 74 } //This might be a string? Looks like:Xob{t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 14 files
		$x9 = "|vtR|vtR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x214 = { 56 07 59 43 57 52 74 74 } //This might be a string? Looks like:VYCWRtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x10 = { 57 52 77 58 74 72 0D 74 } //This might be a string? Looks like:WRwXtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x217 = "poEWrMfo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x218 = { 1E 4D 62 5C 06 60 7C 63 } //This might be a string? Looks like:Mb\`|c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 5 files
		$x220 = "dRtvtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x221 = { 5C 57 72 63 6D 54 62 00 } //This might be a string? Looks like:\WrcmTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 7 files
		$x222 = "t`swd`sw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x12 = { 60 74 77 4C 74 72 0D 74 } //This might be a string? Looks like:`twLtr\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 9 files
		$x228 = { 53 42 77 74 74 74 74 5C } //This might be a string? Looks like:SBwtttt\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x14 = { 0C 5C 54 58 63 5F 51 74 } //This might be a string? Looks like:\TXc_Qt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x229 = "|ro]TbMY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 5 files
		$x15 = "tQtwbtr`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x16 = { 4F 6F 62 04 5C 57 7D 5E } //This might be a string? Looks like:Oob\W}^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x231 = "tptttxt@" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x18 = "{Rtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x233 = { 51 6D 67 59 56 05 70 74 } //This might be a string? Looks like:QmgYVpt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x234 = { 54 62 00 5E 57 06 51 4F } //This might be a string? Looks like:Tb^WQO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x21 = { 7B 4F 6F 62 04 5C 57 7D } //This might be a string? Looks like:{Oob\W}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x22 = { 7F 59 56 6D 63 59 56 06 } //This might be a string? Looks like:YVmcYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x23 = "ptttRttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 10 files
		$x236 = "dtwtt|tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x26 = "tttdtttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x237 = { 67 72 63 4F 51 7D 7F 43 } //This might be a string? Looks like:grcOQ}C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x27 = "tpttttvt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x238 = "ttrttttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x28 = "^MYQXcF|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x241 = { 77 63 5C 1E 4C 71 02 74 } //This might be a string? Looks like:wc\Lqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x32 = { 67 64 56 58 59 07 54 62 } //This might be a string? Looks like:gdVXYTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x33 = { 4C 6F 62 00 05 63 72 5D } //This might be a string? Looks like:Lobcr]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x243 = { 62 00 5E 57 06 56 74 74 } //This might be a string? Looks like:b^WVtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x35 = { 1A 1A 0D 74 74 74 70 74 } //This might be a string? Looks like:\rtttpt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x36 = "ttttttwb" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x244 = "t]Vte]lp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x37 = "wYtrVtld" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x246 = { 1A 74 70 74 74 74 76 71 } //This might be a string? Looks like:tptttvq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x248 = { 70 59 40 6F 58 0D 52 50 } //This might be a string? Looks like:pY@oX\rRP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x39 = "gZVXc]os" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x43 = "swLTmoEW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x252 = { 5C 1E 4D 62 5C 06 60 7C } //This might be a string? Looks like:\Mb\`|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x45 = { 70 73 4F 56 07 63 41 6C } //This might be a string? Looks like:psOVcAl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x254 = { 60 4D 43 6C 07 73 46 6F } //This might be a string? Looks like:`MClsFo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x48 = "btr`tVRw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x258 = "f`tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x50 = { 74 72 0D 74 57 64 77 41 } //This might be a string? Looks like:tr\rtWdwA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x259 = { 04 77 6C 65 7C 1A 1E 46 } //This might be a string? Looks like:wle|F
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x260 = "}ltttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x51 = "ttttt|td" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x261 = { 6F 72 59 4C 6F 62 7B 05 } //This might be a string? Looks like:orYLob{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x262 = { 1E 70 5C 64 74 74 74 7C } //This might be a string? Looks like:p\dttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x52 = "Rtttqttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x264 = "QsoYV[{E" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x54 = { 6C 06 7F 43 56 07 0C 58 } //This might be a string? Looks like:lCVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x265 = "tttBtdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x266 = { 6F 6D 7F 5D 51 72 59 43 } //This might be a string? Looks like:om]QrYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x58 = "sgZVXc]o" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x59 = { 74 72 42 74 6C 64 77 00 } //This might be a string? Looks like:trBtldw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x269 = { 74 74 71 1A 74 74 74 74 } //This might be a string? Looks like:ttqtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x61 = { 72 01 74 6C 64 77 46 74 } //This might be a string? Looks like:rtldwFt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x271 = "tttttbtw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x273 = "wttttttd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x62 = "r`tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x275 = "QrYCW^pt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x65 = { 5C 65 52 05 7E 7C 76 74 } //This might be a string? Looks like:\eR~|vt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 3 files
		$x66 = "RwYtvttV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x280 = { 77 61 63 5A 41 04 76 73 } //This might be a string? Looks like:wacZAvs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x68 = { 7B 04 56 5B 7F 59 57 5B } //This might be a string? Looks like:{V[YW[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 6 files
		$x282 = "Rtt]Vte]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 10 files
		$x70 = "tr^tWtwY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x71 = "tttttvtp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x284 = { 71 4C 65 0C 53 6D 59 43 } //This might be a string? Looks like:qLeSmYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x286 = { 52 50 62 0C 04 56 5C 77 } //This might be a string? Looks like:RPbV\w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x290 = { 46 6F 60 59 40 6F 58 0C } //This might be a string? Looks like:Fo`Y@oX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x292 = { 40 78 76 7C 52 6F 62 00 } //This might be a string? Looks like:@xv|Rob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x73 = { 06 67 4C 54 62 00 5B 56 } //This might be a string? Looks like:gLTb[V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x294 = { 5C 1E 4C 71 02 74 4C 79 } //This might be a string? Looks like:\LqtLy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x74 = { 6D 77 59 67 5B 7F 43 57 } //This might be a string? Looks like:mwYg[CW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 7 files
		$x76 = { 74 79 52 74 42 74 76 01 } //This might be a string? Looks like:tyRtBtv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x297 = { 66 62 00 58 57 05 70 74 } //This might be a string? Looks like:fbXWpt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 10 files
		$x298 = { 05 6D 0D 74 64 74 74 74 } //This might be a string? Looks like:m\rtdttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x78 = "tttwtt|t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x301 = { 7D 6F 6D 67 7B 57 07 67 } //This might be a string? Looks like:}omg{Wg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x80 = "twlttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x81 = "tttwlttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x306 = { 6C 62 04 59 64 64 74 74 } //This might be a string? Looks like:lbYddtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x83 = { 74 70 51 59 51 73 7B 05 } //This might be a string? Looks like:tpQYQs{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x309 = "gYgXYFo`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x310 = { 42 7A 46 71 78 0D 77 74 } //This might be a string? Looks like:BzFqx\rwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x311 = "tt~ttttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x312 = "ttt}|ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x87 = { 00 45 51 72 59 5D 57 72 } //This might be a string? Looks like:EQrY]Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x88 = "dtttpxtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x91 = "|tldw@t}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x313 = { 60 78 1A 06 60 7C 1A 4D } //This might be a string? Looks like:`x`|M
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x93 = "ttttttvC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x94 = "R|vttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x314 = { 74 74 7C 43 7D 6D 04 00 } //This might be a string? Looks like:tt|C}m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x315 = "soYV[{EW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x317 = { 7B 46 57 06 7B 59 66 72 } //This might be a string? Looks like:{FW{Yfr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x318 = "gLom{Ott" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x319 = "}`tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x97 = "{Ay[lO|_" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x322 = "ds}omg{W" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 11 files
		$x323 = { 65 0C 04 70 65 0C 04 71 } //This might be a string? Looks like:epeq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 5 files
		$x325 = { 52 74 74 1A 1A 1A 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x326 = "rcrTbMYt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x330 = "XYFocwCT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 13 files
		$x101 = { 70 04 43 6F 7D 63 46 6F } //This might be a string? Looks like:pCo}cFo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x333 = "ttdtwtts" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x334 = { 77 71 57 07 04 42 6C 6D } //This might be a string? Looks like:wqWBlm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 4 files
		$x336 = "ttBtqttx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x339 = { 71 65 0C 04 76 65 0D 63 } //This might be a string? Looks like:qeve\rc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x105 = { 1A 53 06 0D 1A 1A 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x107 = { 01 74 6C 64 77 41 74 72 } //This might be a string? Looks like:tldwAtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x341 = { 5F 60 6D 5A 60 7C 04 73 } //This might be a string? Looks like:_`mZ`|s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x342 = "vttttttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x345 = { 42 74 74 1A 06 60 7C 03 } //This might be a string? Looks like:Btt`|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x346 = { 62 00 58 57 05 70 74 74 } //This might be a string? Looks like:bXWptt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x349 = "|}oYV[{E" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x112 = { 74 6F 42 77 45 74 72 01 } //This might be a string? Looks like:toBwEtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 10 files
		$x357 = { 74 74 74 74 5C 05 6D 5E } //This might be a string? Looks like:tttt\m^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4056390622295665 Found in 13 files
		$x118 = { 1A 1A 1A 1A 42 74 74 74 } //This might be a string? Looks like:Bttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x119 = { 74 70 63 40 6C 07 0C 5E } //This might be a string? Looks like:tpc@l^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x361 = { 70 4D 45 6C 5B 7F 5D 56 } //This might be a string? Looks like:pMEl[]V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x121 = "cr]Lobs^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x362 = { 44 74 40 5C 7D 07 43 1A } //This might be a string? Looks like:Dt@\}C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x363 = "l|tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x123 = { 5E 1E 71 64 5A 52 7C 71 } //This might be a string? Looks like:^qdZR|q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x364 = { 6F 62 04 5C 57 7D 5E 52 } //This might be a string? Looks like:ob\W}^R
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x125 = "t|tdtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x365 = { 74 7C 43 7D 6D 04 00 57 } //This might be a string? Looks like:t|C}mW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x366 = "ttBtdttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x367 = { 5C 6C 62 4D 77 57 72 4D } //This might be a string? Looks like:\lbMwWrM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x368 = "WpoLob`t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x369 = { 41 60 7F 77 76 79 67 76 } //This might be a string? Looks like:A`wvygv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x370 = { 59 40 6F 58 0C 77 74 74 } //This might be a string? Looks like:Y@oXwtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x127 = { 74 74 74 74 74 74 7E 1A } //This might be a string? Looks like:tttttt~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x379 = "tttttpQY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x381 = "wtt|ttBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x382 = { 67 07 63 05 64 06 63 4C } //This might be a string? Looks like:gcdcL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x383 = { 5F 60 6D 05 60 65 0C 04 } //This might be a string? Looks like:_`m`e
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 9 files
		$x129 = { 01 74 6F 52 77 43 74 74 } //This might be a string? Looks like:toRwCtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x384 = { 60 04 54 79 51 67 77 6D } //This might be a string? Looks like:`TyQgwm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x132 = "wOtr^tWB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x133 = { 56 06 7B 59 57 62 7F 46 } //This might be a string? Looks like:V{YWbF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x386 = "Qdtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x387 = "`tWtwFtv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x134 = "ltodwLt}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x135 = "sltodwLt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x388 = { 78 0D 77 53 6D 59 43 7F } //This might be a string? Looks like:x\rwSmYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x136 = "XsAomgYV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 11 files
		$x391 = { 74 74 76 79 67 64 5C 7F } //This might be a string? Looks like:ttvygd\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x393 = { 04 59 56 06 7B 5D 6F 07 } //This might be a string? Looks like:YV{]o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x396 = "t|tt|Arv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x138 = "db{_om{O" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x397 = { 43 57 5B 67 4C 57 07 42 } //This might be a string? Looks like:CW[gLWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x398 = { 64 5E 7D 65 0C 05 7F 77 } //This might be a string? Looks like:d^}ew
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x399 = { 73 1A 74 70 74 74 74 77 } //This might be a string? Looks like:stptttw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x400 = { 74 74 74 71 65 74 6D 04 } //This might be a string? Looks like:tttqetm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x140 = "ttttorg^" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x402 = { 74 74 7C 6D 74 71 01 61 } //This might be a string? Looks like:tt|mtqa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x141 = { 60 07 63 4C 51 58 59 5F } //This might be a string? Looks like:`cLQXY_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x143 = "tttttsdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x403 = "Bt`ttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x404 = { 74 74 74 74 53 1A 1A 42 } //This might be a string? Looks like:ttttSB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x408 = { 07 04 42 6C 6D 7F 59 67 } //This might be a string? Looks like:BlmYg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x409 = "tgrcFomg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x411 = "ts}omgqW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x146 = { 01 03 56 07 7B 5A 6F 62 } //This might be a string? Looks like:V{Zob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x147 = { 52 74 42 74 76 01 74 78 } //This might be a string? Looks like:RtBtvtx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x414 = "BRRtclCF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x415 = { 78 5C 00 5E 57 72 42 74 } //This might be a string? Looks like:x\^WrBt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x148 = { 77 45 74 72 01 74 6F 42 } //This might be a string? Looks like:wEtrtoB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x417 = { 74 74 74 71 74 79 5B 7F } //This might be a string? Looks like:tttqty[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x418 = "Xg]Qrptt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x150 = "W^MYQXcF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x422 = "t|tttdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 4 files
		$x152 = { 1A 1A 0D 76 74 74 74 74 } //This might be a string? Looks like:\rvtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x423 = { 7B 6D 54 62 00 5E 57 06 } //This might be a string? Looks like:{mTb^W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x426 = "t|twtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x427 = { 74 74 5C 1A 77 62 03 7C } //This might be a string? Looks like:tt\wb|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x156 = "]trdtodw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x432 = "ElbMEPX`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x159 = { 6F 6D 7F 4F 54 62 0C 40 } //This might be a string? Looks like:omOTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x161 = "SBtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 8 files
		$x434 = { 62 1A 06 60 64 1A 06 60 } //This might be a string? Looks like:b`d`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x436 = { 5C 05 6D 56 5C 04 6D 52 } //This might be a string? Looks like:\mV\mR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x438 = "@orMFttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x162 = { 59 6C 06 63 4C 54 6D 67 } //This might be a string? Looks like:YlcLTmg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x442 = { 00 5E 57 06 51 60 6F 6D } //This might be a string? Looks like:^WQ`om
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x443 = { 06 63 42 56 72 0C 4C 51 } //This might be a string? Looks like:cBVrLQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x165 = { 66 62 00 45 51 72 59 5D } //This might be a string? Looks like:fbEQrY]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x446 = { 56 58 0C 4C 74 74 74 74 } //This might be a string? Looks like:VXLtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x447 = { 64 52 77 44 74 65 0D 63 } //This might be a string? Looks like:dRwDte\rc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 3 files
		$x448 = { 6C 1E 61 00 00 00 00 02 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x449 = "|tttttts" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 15 files
		$x166 = { 68 4A 01 10 E8 12 03 00 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x450 = { 45 57 58 67 43 51 06 7B } //This might be a string? Looks like:EWXgCQ{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x451 = { 67 07 63 05 61 72 73 4F } //This might be a string? Looks like:gcarsO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x168 = { 7B 59 56 5B 6F 45 6C 07 } //This might be a string? Looks like:{YV[oEl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x169 = "ttttttp]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x453 = { 70 54 6D 7F 59 6C 06 67 } //This might be a string? Looks like:pTmYlg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x172 = { 1A 1A 1A 1A 1A 4F 0D 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x456 = "poLob`tt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 4 files
		$x457 = { 74 42 74 74 63 1A 0D 63 } //This might be a string? Looks like:tBttc\rc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 12 files
		$x175 = "pttttvtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x459 = { 74 74 66 05 63 66 61 5E } //This might be a string? Looks like:ttfcfa^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x461 = { 62 4D 59 64 6D 67 05 56 } //This might be a string? Looks like:bMYdmgV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x179 = "ttttvtpt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x464 = { 74 74 74 1A 06 60 7C 03 } //This might be a string? Looks like:ttt`|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x465 = { 77 64 1A 0C 50 73 42 7D } //This might be a string? Looks like:wdPsB}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x466 = { 07 63 05 63 72 59 5F 54 } //This might be a string? Looks like:ccrY_T
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x180 = "lBwLtr^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 7 files
		$x468 = "tpttdtvt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x182 = { 74 71 74 74 74 74 74 01 } //This might be a string? Looks like:tqttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x183 = { 56 07 59 43 57 5F 05 5C } //This might be a string? Looks like:VYCW_\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x471 = { 70 63 4C 56 58 0C 4C 74 } //This might be a string? Looks like:pcLVXLt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 2 files
		$x184 = { 0D 46 64 64 74 74 74 74 } //This might be a string? Looks like:\rFddtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 8 files
		$x185 = "t}dtodwL" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 12 files
		$x187 = "tttptttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 4 files
		$x473 = "ttwtt^pt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x475 = { 63 61 51 7D 7F 45 57 58 } //This might be a string? Looks like:caQ}EWX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x189 = "ttR|vttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x190 = { 7D 7F 59 56 6D 63 59 56 } //This might be a string? Looks like:}YVmcYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x476 = { 56 58 63 5F 51 72 0C 4C } //This might be a string? Looks like:VXc_QrL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x191 = { 63 4C 56 07 59 43 57 5F } //This might be a string? Looks like:cLVYCW_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 11 files
		$x196 = { 5F 6F 6D 77 05 54 62 0C } //This might be a string? Looks like:_omwTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 6 files
		$x197 = { 1A 42 74 74 1A 1A 0D 74 } //This might be a string? Looks like:Btt\rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x198 = "ttttttqP" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x485 = { 7D 7F 45 57 58 51 77 74 } //This might be a string? Looks like:}EWXQwt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x486 = { 1E 73 5E 64 74 74 74 7C } //This might be a string? Looks like:s^dttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x203 = "dtwttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x204 = "pltTdwFt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x206 = "twYtrVtl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x489 = "^arY@o`p" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x0 = { 4D 59 64 6D 67 05 56 58 } //This might be a string? Looks like:MYdmgVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 4 files
		$x1 = "VRwYtrVt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x2 = "VRwOtr^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 7 files
		$x207 = { 74 74 1A 1A 1A 1A 1A 01 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x208 = { 71 57 07 04 42 6C 6D 7F } //This might be a string? Looks like:qWBlm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x3 = { 6C 64 77 00 74 72 60 74 } //This might be a string? Looks like:ldwtr`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x5 = { 45 51 7D 5E 1E 71 64 5A } //This might be a string? Looks like:EQ}^qdZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x6 = { 52 64 6D 63 05 54 72 0C } //This might be a string? Looks like:RdmcTr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x210 = { 53 6D 59 04 57 52 0D 64 } //This might be a string? Looks like:SmYWR\rd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x8 = "tWRw]trB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x212 = { 74 74 77 73 56 5B 7F 43 } //This might be a string? Looks like:ttwsV[C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x213 = { 74 78 0D 77 53 6D 59 43 } //This might be a string? Looks like:tx\rwSmYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 8 files
		$x215 = { 74 74 65 0D 74 74 74 71 } //This might be a string? Looks like:tte\rtttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x216 = "gXYFo`pt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x219 = "ttttttpR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x223 = { 7F 45 6C 5B 63 05 6F 6D } //This might be a string? Looks like:El[com
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x224 = { 78 0D 77 74 03 42 7C 4F } //This might be a string? Looks like:x\rwtB|O
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x225 = { 07 59 40 6F 72 0C 06 60 } //This might be a string? Looks like:Y@or`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 4 files
		$x11 = "vttVRwYt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x226 = "rTbMYaXs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x227 = { 73 7D 6F 6D 67 7B 57 07 } //This might be a string? Looks like:s}omg{W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 9 files
		$x13 = "yXgFWttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x230 = { 67 58 59 46 6F 60 63 01 } //This might be a string? Looks like:gXYFo`c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x17 = { 42 78 71 4F 1A 0D 71 74 } //This might be a string? Looks like:BxqO\rqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x19 = "ttttttwa" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x232 = { 59 46 6F 60 73 05 51 7D } //This might be a string? Looks like:YFo`sQ}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x20 = "tttw`ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x235 = { 67 72 63 07 54 62 7B 59 } //This might be a string? Looks like:grcTb{Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x24 = "tt{dtttq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x25 = "Tdtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x239 = { 6F 60 73 05 51 7D 7F 45 } //This might be a string? Looks like:o`sQ}E
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x240 = { 78 1A 06 60 7C 1A 4D 63 } //This might be a string? Looks like:x`|Mc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x29 = { 74 64 76 00 4C 6F 62 4D } //This might be a string? Looks like:tdvLobM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 9 files
		$x30 = { 01 7B 76 52 74 74 74 74 } //This might be a string? Looks like:{vRtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x31 = "tVBwOtr`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x242 = { 1E 4C 71 02 70 66 79 67 } //This might be a string? Looks like:Lqpfyg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x34 = "Yt}|tWRw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 12 files
		$x38 = "tttttwdg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x245 = "cFo`]]WX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x247 = { 74 03 42 7C 4F 42 73 00 } //This might be a string? Looks like:tB|OBs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 5 files
		$x249 = { 1A 74 65 1A 1A 1A 42 74 } //This might be a string? Looks like:teBt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x40 = "tWBw@ttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 7 files
		$x250 = "ttttpQYQ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x251 = "tvRttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x41 = { 6C 07 0C 41 7A 58 73 4F } //This might be a string? Looks like:lAzXsO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x42 = { 77 43 74 72 01 74 74 74 } //This might be a string? Looks like:wCtrttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 14 files
		$x44 = "`]]WXgFo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x253 = "rTbMYdmg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x46 = "rdtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x47 = { 40 51 58 59 4C 57 07 00 } //This might be a string? Looks like:@QXYLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x255 = { 1A 5D 56 77 05 76 72 5A } //This might be a string? Looks like:]VwvrZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x256 = { 5C 05 64 5E 77 7C 46 7B } //This might be a string? Looks like:\d^w|F{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x257 = { 5C 0D 6F 50 42 52 64 74 } //This might be a string? Looks like:\\roPBRdt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x49 = { 43 1A 1A 1A 1A 02 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x263 = { 51 67 71 1A 51 64 4F 5A } //This might be a string? Looks like:QgqQdOZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.811278124459133 Found in 4 files
		$x53 = { 74 65 1A 1A 74 74 71 1A } //This might be a string? Looks like:tettq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x55 = { 7F 59 56 07 0C 04 56 58 } //This might be a string? Looks like:YVVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x56 = { 52 77 5D 74 72 05 74 6F } //This might be a string? Looks like:Rw]trto
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x267 = { 59 6C 73 5D 6F 05 0C 7D } //This might be a string? Looks like:Yls]o}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 1 files
		$x57 = { 7D 73 5C 44 4F 04 64 57 } //This might be a string? Looks like:}s\DOdW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x268 = { 71 01 62 6C 74 74 74 74 } //This might be a string? Looks like:qbltttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x60 = "ttttttwB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x270 = "VXc]Qr`t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x272 = "ttwAt}xt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x63 = "Rttttttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x274 = { 63 58 63 4C 56 07 59 43 } //This might be a string? Looks like:cXcLVYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x64 = "pRtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x276 = { 5F 60 6D 05 60 7C 04 73 } //This might be a string? Looks like:_`m`|s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x277 = { 59 56 5B 7B 45 57 07 01 } //This might be a string? Looks like:YV[{EW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x278 = { 72 0C 5D 6F 70 4D 45 6C } //This might be a string? Looks like:r]opMEl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x67 = "tpxtWBwB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x279 = { 04 59 57 5B 67 61 51 7D } //This might be a string? Looks like:YW[gaQ}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x69 = "d|tttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x281 = { 77 62 5C 06 64 5E 76 7C } //This might be a string? Looks like:wb\d^v|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x283 = { 63 72 59 41 6F 62 0C 04 } //This might be a string? Looks like:crYAob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x285 = "tdtttttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x287 = { 73 5B 6F 60 7F 43 50 70 } //This might be a string? Looks like:s[o`CPp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 7 files
		$x288 = "ttvqSSBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x72 = "qRtttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x289 = { 5D 56 07 41 7B 6F 62 04 } //This might be a string? Looks like:]VA{ob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x291 = { 41 70 7F 74 66 73 42 7D } //This might be a string? Looks like:AptfsB}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x293 = { 6C 07 63 4F 56 04 67 43 } //This might be a string? Looks like:lcOVgC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x295 = { 5C 7C 74 74 74 74 74 74 } //This might be a string? Looks like:\|tttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x75 = "ttttttvx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x296 = "tttRtxtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 6 files
		$x77 = { 01 74 51 74 77 59 74 7D } //This might be a string? Looks like:tQtwYt}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x299 = { 7F 59 6C 6D 67 59 67 58 } //This might be a string? Looks like:YlmgYgX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x300 = { 45 57 72 63 61 51 7D 7F } //This might be a string? Looks like:EWrcaQ}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x302 = { 07 63 05 61 72 73 4F 51 } //This might be a string? Looks like:carsOQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x303 = { 7F 43 6C 07 63 4F 56 04 } //This might be a string? Looks like:ClcOV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x304 = { 74 7C 43 42 5D 53 6F 05 } //This might be a string? Looks like:t|CB]So
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x79 = "tslt`BwS" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x305 = { 05 74 74 74 74 60 65 0D } //This might be a string? Looks like:tttt`e\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 13 files
		$x82 = { 72 4D 45 6C 07 73 05 54 } //This might be a string? Looks like:rMElsT
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x307 = "]opoEWr`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x308 = "[}gSBwtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x84 = { 07 63 41 6C 58 4D 00 7C } //This might be a string? Looks like:cAlXM|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x85 = "@ttttttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x86 = "tttttwBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 6 files
		$x89 = { 1A 0D 74 1A 1A 1A 1A 74 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x90 = { 67 59 6C 5B 63 5B 6F 07 } //This might be a string? Looks like:gYl[c[o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x92 = { 57 06 77 00 56 58 59 5B } //This might be a string? Looks like:WwVXY[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x316 = { 4D 00 66 62 67 59 57 5B } //This might be a string? Looks like:MfbgYW[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 7 files
		$x320 = { 6D 67 61 50 6D 7B 05 6F } //This might be a string? Looks like:mgaPm{o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 5 files
		$x321 = "`p`ttpBw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 2 files
		$x95 = "tvttWdwY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 3 files
		$x96 = { 53 1A 0C 53 6D 04 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x324 = { 6F 72 63 4F 6C 06 7F 45 } //This might be a string? Looks like:orcOlE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x98 = { 77 61 50 6D 7B 05 6F 62 } //This might be a string? Looks like:waPm{ob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 3 files
		$x99 = "ttttptwR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x327 = { 72 59 5C 56 58 73 4C 50 } //This might be a string? Looks like:rY\VXsLP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x328 = { 59 6C 06 67 43 56 5B 59 } //This might be a string? Looks like:YlgCV[Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x100 = { 7D 7F 45 6C 5B 63 05 6F } //This might be a string? Looks like:}El[co
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 9 files
		$x329 = "ttdtwtt|" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x331 = { 6D 0D 74 52 74 74 74 7C } //This might be a string? Looks like:m\rtRttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x102 = "txttttqt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x332 = "LVXc@Qsw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x335 = { 74 5C 0D 6F 50 42 52 64 } //This might be a string? Looks like:t\\roPBRd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x103 = "ttw`tttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x337 = { 6F 6D 67 71 57 07 04 41 } //This might be a string? Looks like:omgqWA
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x104 = { 77 05 74 72 5E 74 57 42 } //This might be a string? Looks like:wtr^tWB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x338 = "tttSBttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 14 files
		$x106 = "ttttttvR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 9 files
		$x340 = "mgYgXYFo" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x108 = { 07 73 05 54 62 0C 40 79 } //This might be a string? Looks like:sTb@y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x343 = { 73 63 4F 6F 6D 7F 70 6F } //This might be a string? Looks like:scOompo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x109 = "tpRttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x344 = { 43 6C 58 73 46 63 62 00 } //This might be a string? Looks like:ClXsFcb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x110 = "dwLt}xtT" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x347 = { 07 54 6D 7F 43 57 58 04 } //This might be a string? Looks like:TmCWX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x111 = "ttttwttl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x348 = "BClm{Oob" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x350 = { 62 64 63 77 7F 78 4F 7C } //This might be a string? Looks like:bdcwxO|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x351 = "dtttttwt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x352 = "FocgEWb`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x353 = { 72 0C 06 57 58 4D 43 6C } //This might be a string? Looks like:rWXMCl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 5 files
		$x354 = { 74 52 06 06 0D 74 7D 64 } //This might be a string? Looks like:tR\rt}d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x113 = { 4C 57 06 7B 43 6F 5B 64 } //This might be a string? Looks like:LW{Co[d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 7 files
		$x355 = { 0C 04 70 65 0C 04 71 7A } //This might be a string? Looks like:peqz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x114 = "wttptttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x115 = { 05 60 06 67 4C 54 62 00 } //This might be a string? Looks like:`gLTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x356 = { 46 57 07 00 59 65 66 7F } //This might be a string? Looks like:FWYef
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x116 = { 6F 63 67 00 56 72 60 74 } //This might be a string? Looks like:ocgVr`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x358 = "ttttttws" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x117 = "tttt}dtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x359 = { 1A 4F 65 74 60 73 77 64 } //This might be a string? Looks like:Oet`swd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x360 = { 63 5F 51 72 0C 4C 50 60 } //This might be a string? Looks like:c_QrLP`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 2 files
		$x120 = { 62 63 05 54 72 0C 5E 66 } //This might be a string? Looks like:bcTr^f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x122 = "wAtrptVR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x124 = "rBtaRw]t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x126 = { 51 73 7B 05 56 58 59 40 } //This might be a string? Looks like:Qs{VXY@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 7 files
		$x371 = { 0C 50 6D 56 7C 7C 74 7C } //This might be a string? Looks like:PmV||t|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 11 files
		$x372 = { 73 56 5B 7F 43 56 52 74 } //This might be a string? Looks like:sV[CVRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 7 files
		$x373 = "ttttttvq" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 8 files
		$x374 = { 05 6D 01 74 64 74 74 74 } //This might be a string? Looks like:mtdttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 3 files
		$x375 = "tdttttrt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 4 files
		$x376 = "ttwBtdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x377 = "BwpobMYQ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x378 = { 57 07 6F 05 6D 73 51 45 } //This might be a string? Looks like:WomsQE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x380 = { 07 42 67 77 05 74 01 65 } //This might be a string? Looks like:Bgwte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x128 = { 74 54 64 77 43 74 72 01 } //This might be a string? Looks like:tTdwCtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 12 files
		$x130 = "xttttvtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x131 = { 74 60 06 59 4F 51 72 63 } //This might be a string? Looks like:t`YOQrc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x385 = { 43 6C 07 63 4F 56 42 71 } //This might be a string? Looks like:ClcOVBq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 5 files
		$x389 = "tt]Vte]{" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x390 = { 71 47 77 0D 51 73 1A 74 } //This might be a string? Looks like:qGw\rQst
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x392 = "p{CW[gLW" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x137 = { 63 01 6F 62 7B 04 51 72 } //This might be a string? Looks like:cob{Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x394 = { 04 73 03 73 76 7B 67 53 } //This might be a string? Looks like:ssv{gS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x395 = { 43 6C 62 67 78 54 62 7F } //This might be a string? Looks like:ClbgxTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x139 = { 51 7D 67 4C 54 62 7F 04 } //This might be a string? Looks like:Q}gLTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x401 = { 5C 54 58 63 5F 51 74 74 } //This might be a string? Looks like:\TXc_Qtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x142 = "wat}dtVR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x144 = "wBtrptWR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x405 = { 04 57 7D 67 45 64 5B 59 } //This might be a string? Looks like:W}gEd[Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x406 = "tttttwtr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x407 = { 40 65 1A 1A 1A 06 1A 45 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x410 = { 78 1A 06 60 7C 1A 4D 60 } //This might be a string? Looks like:x`|M`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x145 = "ttttttwE" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 4 files
		$x412 = { 0D 74 74 74 74 74 1A 42 } //This might be a string? Looks like:\rtttttB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x413 = { 74 71 01 62 67 74 74 74 } //This might be a string? Looks like:tqbgttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5 Found in 5 files
		$x416 = { 74 74 71 1A 74 74 71 1A } //This might be a string? Looks like:ttqttq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 10 files
		$x149 = { 74 65 1A 1A 1A 1A 1A 1A } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x419 = "t|tstttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x420 = { 57 07 7B 5D 51 72 59 43 } //This might be a string? Looks like:W{]QrYC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x421 = "{gQMd_`m" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x151 = { 72 63 4F 6C 06 7F 45 56 } //This might be a string? Looks like:rcOlEV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x153 = "omgYV[xt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 7 files
		$x424 = { 54 6D 7F 59 6C 06 67 43 } //This might be a string? Looks like:TmYlgC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x425 = { 74 64 76 00 5E 6C 6D 67 } //This might be a string? Looks like:tdv^lmg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x154 = "tqtttvtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x155 = "tttBtttw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x428 = "mgrTbMYc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x429 = { 0C 42 6F 6D 7F 5D 51 72 } //This might be a string? Looks like:Bom]Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x157 = { 74 72 01 74 6F 52 77 43 } //This might be a string? Looks like:trtoRwC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x430 = { 74 79 5B 7F 4F 56 58 78 } //This might be a string? Looks like:ty[OVXx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 6 files
		$x158 = "dtttw`t}" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x431 = { 04 00 57 4C 56 7C 78 74 } //This might be a string? Looks like:WLV|xt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 2 files
		$x160 = { 74 74 42 74 74 64 77 7F } //This might be a string? Looks like:ttBttdw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 6 files
		$x433 = "ttttttwr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 10 files
		$x435 = { 62 00 05 6F 6D 7C 74 74 } //This might be a string? Looks like:bom|tt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x437 = { 72 63 64 56 58 0C 5F 6F } //This might be a string? Looks like:rcdVX_o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x439 = "ttptttxt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x440 = "wpobMYQr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x441 = "ttdttttr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x163 = "t}xtTdwC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x444 = "]]WXgFo`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 8 files
		$x164 = "ttpxtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 7 files
		$x445 = "Otttt|As" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x167 = "ttttttqx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x170 = { 7D 59 7F 6F 72 63 40 51 } //This might be a string? Looks like:}Yorc@Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x452 = { 67 61 50 6D 7B 05 6F 62 } //This might be a string? Looks like:gaPm{ob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x171 = "twtttttB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 9 files
		$x454 = { 67 59 56 07 7B 4C 54 6D } //This might be a string? Looks like:gYV{LTm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x173 = "r]Lobs^t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.4056390622295662 Found in 11 files
		$x455 = "}gSBwttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x174 = "trVtldwF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x458 = { 59 5C 54 62 4D 45 51 7D } //This might be a string? Looks like:Y\TbMEQ}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x460 = { 0D 74 64 74 74 74 65 0D } //This might be a string? Looks like:\rtdttte\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 12 files
		$x176 = "]]WXgFod" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 11 files
		$x177 = { 67 7B 57 07 67 04 57 72 } //This might be a string? Looks like:g{WgWr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 11 files
		$x178 = "ttxttttv" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 3 files
		$x462 = { 71 1A 51 53 5D 61 1A 06 } //This might be a string? Looks like:qQS]a
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 6 files
		$x463 = "cMQbcOQr" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x467 = { 56 06 67 4C 57 72 63 40 } //This might be a string? Looks like:VgLWrc@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 9 files
		$x181 = { 54 62 7B 4C 57 06 7B 43 } //This might be a string? Looks like:Tb{LW{C
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.5 Found in 3 files
		$x469 = { 77 52 74 74 5D 56 77 05 } //This might be a string? Looks like:wRtt]Vw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 6 files
		$x470 = "om{OlbQY" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 2 files
		$x186 = { 70 74 51 64 77 05 74 72 } //This might be a string? Looks like:ptQdwtr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 5 files
		$x472 = { 74 73 0C 50 42 52 64 74 } //This might be a string? Looks like:tsPBRdt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 2 files
		$x188 = "pttvtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 5 files
		$x474 = { 04 43 56 58 60 52 54 62 } //This might be a string? Looks like:CVX`RTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.2987949406953985 Found in 10 files
		$x192 = { 1A 1A 1A 1A 1A 0D 74 74 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5487949406953985 Found in 6 files
		$x193 = "qttxttBt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 4 files
		$x194 = "`ttdtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x195 = { 07 6F 6D 7F 4F 54 62 0C } //This might be a string? Looks like:omOTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 4 files
		$x477 = "rYCW^ptt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x478 = { 0C 50 62 0D 5B 76 71 74 } //This might be a string? Looks like:Pb\r[vqt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x479 = "faxLyXgF" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 4 files
		$x480 = "Ycr]Lobs" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.1556390622295662 Found in 10 files
		$x199 = "wdgdttat" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 9 files
		$x200 = { 1A 1A 1A 1A 1A 1A 42 74 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 10 files
		$x481 = { 41 6C 6D 67 45 57 07 01 } //This might be a string? Looks like:AlmgEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9056390622295665 Found in 8 files
		$x482 = { 74 1A 06 60 60 1A 06 60 } //This might be a string? Looks like:t```
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x483 = { 5E 00 73 61 71 78 4C 74 } //This might be a string? Looks like:^saqxLt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 6 files
		$x201 = "w`t}|tld" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.75 Found in 3 files
		$x484 = { 74 1E 70 42 42 74 74 74 } //This might be a string? Looks like:tpBBttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 11 files
		$x202 = "RwEtrBto" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.061278124459133 Found in 5 files
		$x487 = "ttvttRtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.75 Found in 8 files
		$x205 = "}|tldw@t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 3 files
		$x488 = "Y@QrcLWX" ascii

		condition:
(207 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83,$x84,$x85,$x86,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x106,$x107,$x108,$x109,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x133,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x198,$x199,$x200,$x201,$x202,$x203,$x204,$x205,$x206) ) or (283 of ($x207,$x208,$x209,$x210,$x211,$x212,$x213,$x214,$x215,$x216,$x217,$x218,$x219,$x220,$x221,$x222,$x223,$x224,$x225,$x226,$x227,$x228,$x229,$x230,$x231,$x232,$x233,$x234,$x235,$x236,$x237,$x238,$x239,$x240,$x241,$x242,$x243,$x244,$x245,$x246,$x247,$x248,$x249,$x250,$x251,$x252,$x253,$x254,$x255,$x256,$x257,$x258,$x259,$x260,$x261,$x262,$x263,$x264,$x265,$x266,$x267,$x268,$x269,$x270,$x271,$x272,$x273,$x274,$x275,$x276,$x277,$x278,$x279,$x280,$x281,$x282,$x283,$x284,$x285,$x286,$x287,$x288,$x289,$x290,$x291,$x292,$x293,$x294,$x295,$x296,$x297,$x298,$x299,$x300,$x301,$x302,$x303,$x304,$x305,$x306,$x307,$x308,$x309,$x310,$x311,$x312,$x313,$x314,$x315,$x316,$x317,$x318,$x319,$x320,$x321,$x322,$x323,$x324,$x325,$x326,$x327,$x328,$x329,$x330,$x331,$x332,$x333,$x334,$x335,$x336,$x337,$x338,$x339,$x340,$x341,$x342,$x343,$x344,$x345,$x346,$x347,$x348,$x349,$x350,$x351,$x352,$x353,$x354,$x355,$x356,$x357,$x358,$x359,$x360,$x361,$x362,$x363,$x364,$x365,$x366,$x367,$x368,$x369,$x370,$x371,$x372,$x373,$x374,$x375,$x376,$x377,$x378,$x379,$x380,$x381,$x382,$x383,$x384,$x385,$x386,$x387,$x388,$x389,$x390,$x391,$x392,$x393,$x394,$x395,$x396,$x397,$x398,$x399,$x400,$x401,$x402,$x403,$x404,$x405,$x406,$x407,$x408,$x409,$x410,$x411,$x412,$x413,$x414,$x415,$x416,$x417,$x418,$x419,$x420,$x421,$x422,$x423,$x424,$x425,$x426,$x427,$x428,$x429,$x430,$x431,$x432,$x433,$x434,$x435,$x436,$x437,$x438,$x439,$x440,$x441,$x442,$x443,$x444,$x445,$x446,$x447,$x448,$x449,$x450,$x451,$x452,$x453,$x454,$x455,$x456,$x457,$x458,$x459,$x460,$x461,$x462,$x463,$x464,$x465,$x466,$x467,$x468,$x469,$x470,$x471,$x472,$x473,$x474,$x475,$x476,$x477,$x478,$x479,$x480,$x481,$x482,$x483,$x484,$x485,$x486,$x487,$x488,$x489) )}