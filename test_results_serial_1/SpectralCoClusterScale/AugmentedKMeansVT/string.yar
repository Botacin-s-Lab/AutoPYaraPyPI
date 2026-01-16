rule 040.dll.patched_SpectralCoClusterScale_AugmentedKMeansVT_k15
{
	//Input TP Rate:
	//6/15
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x84 = { 52 0C 1A 67 4D 77 58 71 06 0C 7D 7C 72 6C 65 53 } //This might be a string? Looks like:RgMwXq}|rleS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x85 = { 66 62 65 53 4D 52 1A 52 76 56 5F 58 7B 67 74 5E } //This might be a string? Looks like:fbeSMRRvV_X{gt^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.014097655573916 Found in 4 files
		$x297 = { 74 74 74 74 74 74 74 74 74 74 74 74 1A 43 1A 1A } //This might be a string? Looks like:ttttttttttttC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x86 = "St^]YlmwqVXc]Qr`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x87 = { 76 79 05 6C 65 5C 53 01 59 63 0C 71 43 7E 51 77 } //This might be a string? Looks like:vyle\SYcqC~Qw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x88 = { 1A 52 02 4D 5B 78 65 5C 42 50 73 42 7D 64 76 1A } //This might be a string? Looks like:RM[xe\BPsB}dv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x89 = { 70 64 7D 7B 05 6F 70 77 74 63 5F 0D 5E 6C 62 4D } //This might be a string? Looks like:pd}{opwtc_\r^lbM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x341 = { 5C 1A 76 71 1E 65 0C 04 43 6C 43 7D 6D 04 00 51 } //This might be a string? Looks like:\vqeClC}mQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x6 = { 6F 60 7B 4C 54 6D 67 45 6C 07 73 46 60 07 63 5F } //This might be a string? Looks like:o`{LTmgElsF`c_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x90 = { 78 5C 04 64 5E 77 73 54 79 0D 6C 43 76 63 0D 51 } //This might be a string? Looks like:x\d^wsTy\rlCvc\rQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x91 = { 1A 04 62 79 02 7C 41 73 76 71 65 7F 7A 42 61 7B } //This might be a string? Looks like:by|AsvqezBa{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 5 files
		$x8 = { 7D 6F 6D 67 64 56 58 0C 5F 64 62 67 5E 56 58 63 } //This might be a string? Looks like:}omgdVX_dbg^VXc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 3 files
		$x92 = { 70 74 51 74 77 45 74 72 0D 74 57 52 77 4F 74 74 } //This might be a string? Looks like:ptQtwEtr\rtWRwOtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x93 = { 6D 06 52 03 42 40 71 53 51 4F 1A 51 74 62 79 61 } //This might be a string? Looks like:mRB@qSQOQtbya
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x94 = { 03 0D 70 4F 42 73 0C 50 62 04 06 71 54 52 4D 5A } //This might be a string? Looks like:\rpOBsPbqTRMZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.202819531114783 Found in 2 files
		$x15 = { 78 4F 78 4F 78 4F 78 4D 62 63 01 41 0D 7F 74 4C } //This might be a string? Looks like:xOxOxOxMbcA\rtL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 10 files
		$x309 = { 01 41 7B 0D 72 66 7F 71 64 74 74 74 74 77 6F 6D } //This might be a string? Looks like:A{\rrfqdttttwom
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 6 files
		$x23 = { 5C 05 64 5E 70 65 53 58 74 0C 73 4C 71 5F 41 60 } //This might be a string? Looks like:\d^peSXtsLq_A`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.646782221599798 Found in 5 files
		$x26 = "xtxRt@trdtWtwFtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 3 files
		$x95 = { 71 65 73 60 7C 59 59 0D 65 0C 04 1A 78 51 73 1A } //This might be a string? Looks like:qes`|YY\rexQs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 4 files
		$x96 = { 76 67 07 63 05 60 06 59 4F 51 72 63 41 63 72 59 } //This might be a string? Looks like:vgc`YOQrcAcrY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x97 = { 74 74 5C 6D 06 0D 03 4F 62 79 67 50 4C 79 76 7C } //This might be a string? Looks like:tt\m\rObygPLyv|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x98 = { 74 77 63 63 59 51 61 5C 1E 5A 4F 42 71 65 57 78 } //This might be a string? Looks like:twccYQa\ZOBqeWx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x29 = { 7F 7F 57 5B 67 59 56 58 4D 43 6C 07 41 59 6F 70 } //This might be a string? Looks like:W[gYVXMClAYop
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x335 = { 45 6C 06 7F 43 56 07 0C 58 51 76 77 62 54 6D 7B } //This might be a string? Looks like:ElCVXQvwbTm{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x99 = { 77 56 1E 62 7B 67 76 64 64 60 7C 04 78 7F 74 61 } //This might be a string? Looks like:wVb{gvdd`|xta
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 2 files
		$x35 = { 62 04 64 57 06 51 59 56 59 7B 05 6C 6D 67 04 56 } //This might be a string? Looks like:bdWQYVY{lmgV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x39 = "csg`csg`csg`csg`" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x323 = { 0C 5C 54 58 63 5F 51 7D 78 52 79 61 01 7E 74 76 } //This might be a string? Looks like:\TXc_Q}xRya~tv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7169171866886992 Found in 6 files
		$x100 = { 70 74 74 74 74 74 74 74 74 74 1A 43 1A 1A 1A 42 } //This might be a string? Looks like:ptttttttttCB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x101 = { 67 5B 7F 59 6F 64 77 72 57 7D 7B 61 6F 6D 67 62 } //This might be a string? Looks like:g[YodwrW}{aomgb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x43 = { 6F 6D 67 60 54 62 7B 47 64 07 0C 04 57 5B 64 74 } //This might be a string? Looks like:omg`Tb{GdW[dt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x102 = { 1E 07 56 7A 64 65 41 59 7D 5E 7E 1A 7F 05 73 61 } //This might be a string? Looks like:VzdeAY}^~sa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x44 = { 74 64 60 67 62 64 63 77 7F 78 4F 7C 40 67 70 4D } //This might be a string? Looks like:td`gbdcwxO|@gpM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5306390622295665 Found in 4 files
		$x46 = "sxexOxOxOxOxOxOx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x103 = { 02 7C 41 73 76 72 54 79 76 70 77 74 6F 5A 6D 7F } //This might be a string? Looks like:|AsvrTyvpwtoZm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 3 files
		$x296 = { 58 63 46 7C 72 4D 59 51 58 63 46 65 66 7F 5D 56 } //This might be a string? Looks like:XcF|rMYQXcFef]V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.25 Found in 5 files
		$x298 = "tdtwttptvpt|dt]t" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x104 = { 03 46 70 7F 7A 43 4D 5C 06 60 7C 52 0D 5B 1A 5F } //This might be a string? Looks like:FpzCM\`|R\r[_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x105 = { 05 62 5A 04 1E 66 7C 6D 57 51 71 65 1A 7B 01 07 } //This might be a string? Looks like:bZf|mWQqe{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x303 = { 52 4F 50 03 66 5F 41 72 7B 1E 5C 73 67 45 5B 5D } //This might be a string? Looks like:ROPf_Ar{\sgE[]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x290 = { 07 0C 4C 67 6D 5D 59 61 62 73 45 57 52 77 41 56 } //This might be a string? Looks like:Lgm]YabsEWRwAV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x106 = { 78 6F 56 59 5C 71 50 77 42 74 51 73 7C 00 7A 6D } //This might be a string? Looks like:xoVY\qPwBtQs|zm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 2 files
		$x58 = { 51 59 51 73 7B 00 56 06 67 59 57 60 59 40 6F 58 } //This might be a string? Looks like:QYQs{VgYW`Y@oX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x59 = { 77 73 76 1E 58 52 06 65 45 7A 41 67 42 70 04 6C } //This might be a string? Looks like:wsvXReEzAgBpl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x62 = { 60 42 5A 43 76 42 01 41 59 03 78 51 73 1A 65 02 } //This might be a string? Looks like:`BZCvBAYxQse
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x107 = { 05 7B 7D 66 05 0C 61 63 04 41 53 6C 07 51 47 57 } //This might be a string? Looks like:{}facASlQGW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x310 = { 07 63 05 60 06 67 4C 54 62 00 5B 63 7D 59 42 6F } //This might be a string? Looks like:c`gLTb[c}YBo
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x108 = { 65 70 77 7C 59 73 76 7A 41 62 52 0D 5F 1A 78 0C } //This might be a string? Looks like:epw|YsvzAbR\r_x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 2 files
		$x109 = { 59 41 56 70 77 46 57 07 7B 5D 57 72 63 74 56 06 } //This might be a string? Looks like:YAVpwFW{]WrctV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.2743974703476995 Found in 6 files
		$x110 = { 06 60 52 1A 06 60 56 1A 06 60 6C 1A 06 60 60 1A } //This might be a string? Looks like:`R`V`l``
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x111 = { 46 6F 62 67 73 50 72 7B 59 56 7D 67 45 57 07 00 } //This might be a string? Looks like:FobgsPr{YV}gEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 4 files
		$x112 = { 64 74 64 74 52 42 5F 1A 4D 5E 74 73 76 5A 7B 52 } //This might be a string? Looks like:dtdtRB_M^tsvZ{R
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x70 = { 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 } //This might be a string? Looks like:zqRzqRzqRzqR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 5 files
		$x113 = { 62 0C 40 64 7D 7B 05 6F 70 77 74 74 74 74 74 74 } //This might be a string? Looks like:b@d}{opwtttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 9 files
		$x114 = { 61 70 04 7A 61 04 77 67 60 59 7B 60 63 63 6F 6D } //This might be a string? Looks like:apzawg`Y{`ccom
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 6 files
		$x72 = { 57 5B 6F 45 56 58 0C 40 57 62 63 40 51 73 6F 5D } //This might be a string? Looks like:W[oEVX@Wbc@Qso]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x115 = { 6F 76 77 5D 57 72 4D 43 6C 07 73 05 54 62 0C 40 } //This might be a string? Looks like:ovw]WrMClsTb@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 6 files
		$x74 = "mFexOxOxOxOxOxOx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x75 = { 05 61 62 0C 5E 51 62 4D 59 66 72 73 40 6F 72 4D } //This might be a string? Looks like:ab^QbMYfrs@orM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x116 = { 78 60 01 41 56 7F 74 5D 63 5C 07 42 5E 70 73 6F } //This might be a string? Looks like:x`AVt]c\B^pso
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 5 files
		$x325 = { 43 6F 7D 63 46 6F 60 6F 45 57 72 63 7A 6C 62 04 } //This might be a string? Looks like:Co}cFo`oEWrczlb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.423794940695399 Found in 4 files
		$x78 = { 50 62 0D 7C 7C 74 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:Pb\r||txOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7169171866886992 Found in 6 files
		$x117 = { 1A 1A 0D 74 74 65 1A 1A 1A 1A 1A 1A 1A 42 74 74 } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x332 = { 7E 79 67 64 5D 50 6D 0D 5B 71 5E 7C 45 72 74 01 } //This might be a string? Looks like:~ygd]Pm\r[q^|Ert
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x118 = { 1A 0C 76 73 42 7D 64 6C 54 52 77 62 03 78 6D 1E } //This might be a string? Looks like:vsB}dlTRwbxm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x119 = { 78 0C 41 71 60 03 52 7C 51 70 72 79 53 64 5F 1A } //This might be a string? Looks like:xAq`R|QprySd_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4913146570363986 Found in 7 files
		$x120 = { 70 74 74 74 74 74 74 74 74 74 1A 1A 1A 1A 1A 42 } //This might be a string? Looks like:ptttttttttB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.8522170014624826 Found in 3 files
		$x121 = { 7B 61 60 04 7B 61 4D 42 74 62 74 74 74 74 03 7B } //This might be a string? Looks like:{a`{aMBtbtttt{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x122 = { 0D 7D 71 00 5E 57 6F 51 58 03 67 60 79 1A 56 73 } //This might be a string? Looks like:\r}q^WoQXg`yVs
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.180036532577266 Found in 5 files
		$x123 = { 74 65 02 1A 1A 1A 0D 74 74 74 74 74 4C 65 1A 1A } //This might be a string? Looks like:te\rtttttLe
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x124 = { 74 76 01 1A 64 63 6F 5C 6C 62 67 53 6F 6D 5D 5F } //This might be a string? Looks like:tvdco\lbgSom]_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x288 = { 53 44 03 6C 7B 4F 5E 5F 57 70 72 04 0C 5B 58 40 } //This might be a string? Looks like:SDl{O^_Wpr[X@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 4 files
		$x125 = { 1A 7F 42 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:B\rOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.186278124459133 Found in 3 files
		$x339 = { 1A 1A 52 74 5A 74 74 74 74 74 74 74 74 74 74 74 } //This might be a string? Looks like:RtZttttttttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x3 = { 7D 5C 04 64 5E 72 65 53 6C 0C 0C 44 71 07 74 76 } //This might be a string? Looks like:}\d^reSlDqtv
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x5 = { 67 06 0D 64 6D 6C 5E 44 54 01 60 4D 73 78 61 5A } //This might be a string? Looks like:g\rdml^DT`MsxaZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x126 = { 71 1E 72 59 05 56 6C 65 01 57 5B 64 5A 52 1A 5D } //This might be a string? Looks like:qrYVleW[dZR]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 6 files
		$x127 = { 74 76 79 67 64 5D 50 6D 0D 5B 71 5E 7C 5A 72 5C } //This might be a string? Looks like:tvygd]Pm\r[q^|Zr\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 5 files
		$x128 = { 41 70 7F 74 5C 79 63 76 64 64 5C 64 7E 01 74 42 } //This might be a string? Looks like:Apt\ycvdd\d~tB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 5 files
		$x9 = "txRt@tpdtatwxttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 7 files
		$x12 = "OxOxOxOxOxOxOxcl" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 6 files
		$x129 = { 51 64 4D 44 74 53 0C 04 72 65 1A 62 5D 56 77 05 } //This might be a string? Looks like:QdMDtSreb]Vw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2743974703476995 Found in 6 files
		$x130 = { 7B 74 74 74 74 74 73 59 53 6D 04 00 57 5C 1E 63 } //This might be a string? Looks like:{tttttsYSmW\c
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x131 = { 73 7D 7C 76 5C 4D 43 72 77 71 46 74 62 04 1E 79 } //This might be a string? Looks like:s}|v\MCrwqFtby
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.5052408149441479 Found in 7 files
		$x132 = { 1A 1A 1A 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:xOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 4 files
		$x308 = { 74 74 74 74 1E 74 74 74 74 74 01 53 40 52 01 74 } //This might be a string? Looks like:tttttttttS@Rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.1216407621868583 Found in 6 files
		$x133 = { 74 74 74 74 74 74 74 77 74 74 74 74 1A 1A 1A 1A } //This might be a string? Looks like:tttttttwtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x24 = "sMVmsMVmsMVmsMVm" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x25 = { 6D 0C 42 79 67 70 6C 73 61 1E 5E 41 1A 40 7D 72 } //This might be a string? Looks like:mBygplsa^A@}r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 10 files
		$x134 = { 46 57 62 00 43 56 7D 73 4C 56 06 67 04 51 5B 51 } //This might be a string? Looks like:FWbCV}sLVgQ[Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 6 files
		$x314 = { 59 51 73 7B 00 56 06 67 59 57 63 67 45 57 62 63 } //This might be a string? Looks like:YQs{VgYWcgEWbc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x135 = { 79 51 67 52 4F 07 01 7B 0C 71 74 73 6D 5C 6C 63 } //This might be a string? Looks like:yQgRO{qtsm\lc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x136 = { 0D 03 66 79 67 64 5F 47 60 4F 43 65 51 61 6D 06 } //This might be a string? Looks like:\rfygd_G`OCeQam
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x316 = { 76 67 07 63 05 60 06 67 4C 54 62 00 5B 63 7D 59 } //This might be a string? Looks like:vgc`gLTb[c}Y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.305036532577266 Found in 9 files
		$x28 = "xOxOxOxOxOxLygvd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 2 files
		$x283 = { 70 74 57 74 77 71 74 72 0D 74 56 74 77 00 74 7D } //This might be a string? Looks like:ptWtwqtr\rtVtwt}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 6 files
		$x318 = { 08 00 00 00 00 EF BB BF 3C 3F 78 6D 6C 20 76 65 } //This might be a string? Looks like:<?xml ve
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x137 = { 78 76 79 67 64 5C 7C 61 5E 7B 04 74 42 59 01 77 } //This might be a string? Looks like:xvygd\|a^{tBYw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 5 files
		$x33 = { 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4D 67 5C } //This might be a string? Looks like:xOxOxOxOxOxOxMg\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 6 files
		$x138 = { 5E 59 40 51 72 63 4C 57 72 0C 5F 54 07 63 5E 66 } //This might be a string? Looks like:^Y@QrcLWr_Tc^f
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 3 files
		$x38 = { 5C 05 6D 0D 5C 1E 63 51 42 52 64 74 4F 78 4F 78 } //This might be a string? Looks like:\m\r\cQBRdtOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x139 = { 7C 7B 52 56 65 05 4F 42 73 41 53 6D 46 5B 71 5C } //This might be a string? Looks like:|{RVeOBsASmF[q\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0243974703476995 Found in 4 files
		$x41 = { 60 6D 05 6F 7E 78 74 74 74 74 74 5C 62 6D 42 5C } //This might be a string? Looks like:`mo~xttttt\bmB\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 5 files
		$x45 = { 74 74 74 70 73 76 64 05 67 73 67 5E 51 7C 66 60 } //This might be a string? Looks like:tttpsvdgsg^Q|f`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x140 = { 0C 6F 7A 63 1A 0D 51 77 7E 79 67 42 64 02 42 06 } //This might be a string? Looks like:ozc\rQw~ygBdB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x141 = { 6D 77 43 56 58 73 4C 54 62 4D 00 7C 7D 63 40 6C } //This might be a string? Looks like:mwCVXsLTbM|}c@l
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x142 = { 7B 05 6F 70 77 74 63 5F 0D 5E 6C 62 4D 46 57 07 } //This might be a string? Looks like:{opwtc_\r^lbMFW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x143 = { 5F 6C 62 4D 46 74 74 77 53 6D 06 7B 05 6F 72 7B } //This might be a string? Looks like:_lbMFttwSm{or{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x144 = { 7D 6F 6D 67 61 51 72 73 4C 51 7D 63 42 66 62 00 } //This might be a string? Looks like:}omgaQrsLQ}cBfb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 2 files
		$x145 = "W`gqd^s@osgEWbcC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4913146570363986 Found in 5 files
		$x146 = { 1A 1A 1A 1A 1A 74 74 74 74 74 70 74 74 74 74 77 } //This might be a string? Looks like:tttttpttttw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9237949406953985 Found in 6 files
		$x147 = { 5F 56 07 06 52 74 64 74 74 74 74 74 74 74 74 74 } //This might be a string? Looks like:_VRtdttttttttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 6 files
		$x48 = { 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 5C 04 64 5E } //This might be a string? Looks like:OxOxOxOxOxOx\d^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x148 = { 4F 52 00 7A 5F 46 0D 65 61 01 1A 64 72 73 5C 6C } //This might be a string? Looks like:ORz_F\readrs\l
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.423794940695399 Found in 4 files
		$x149 = { 78 4F 78 4F 78 4F 78 4F 78 4F 73 62 79 02 73 6C } //This might be a string? Looks like:xOxOxOxOxOsbysl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 4 files
		$x150 = { 74 71 74 1A 1A 1A 1A 74 74 74 74 74 65 02 1A 1A } //This might be a string? Looks like:tqtttttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x151 = { 1A 0C 71 47 77 4F 65 74 64 78 7A 79 6F 50 5F 7D } //This might be a string? Looks like:qGwOetdxzyoP_}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 4 files
		$x51 = "xOxOxOxOxOxOxMgc" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x338 = { 5E 4D 71 61 62 73 42 60 06 67 4C 54 62 00 5B 64 } //This might be a string? Looks like:^MqabsB`gLTb[d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x152 = { 07 73 5E 57 42 7A 46 76 78 0D 77 50 6D 56 7B 44 } //This might be a string? Looks like:s^WBzFvx\rwPmV{D
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x153 = { 74 41 64 7F 7F 57 58 59 05 54 62 73 46 54 6D 45 } //This might be a string? Looks like:tAdWXYTbsFTmE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 5 files
		$x154 = { 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4D 62 5C 1A } //This might be a string? Looks like:OxOxOxOxOxOxMb\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x155 = { 74 71 00 6D 77 5C 60 06 5E 03 42 7A 7F 51 50 64 } //This might be a string? Looks like:tqmw\`^BzQPd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 5 files
		$x156 = { 57 72 59 5E 64 07 0C 5E 6F 63 77 5D 6F 07 60 74 } //This might be a string? Looks like:WrY^d^ocw]o`t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x348 = { 5A 43 51 6D 6C 41 7B 70 73 62 79 03 01 7D 00 74 } //This might be a string? Looks like:ZCQmlA{psby}t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x157 = { 5D 51 1A 7D 64 7D 5C 05 06 01 52 07 73 42 1A 63 } //This might be a string? Looks like:]Q}d}\RsBc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9772170014624826 Found in 8 files
		$x158 = "ttpwtdpwtdpwtdpw" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 4 files
		$x159 = { 74 76 73 42 7D 64 71 60 65 1A 62 5C 01 53 74 74 } //This might be a string? Looks like:tvsB}dq`eb\Stt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x160 = { 7F 7D 6F 6D 67 61 51 72 73 4C 51 7D 63 42 66 62 } //This might be a string? Looks like:}omgaQrsLQ}cBfb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 4 files
		$x63 = { 60 51 59 51 70 7B 04 56 5B 7F 59 57 5B 67 60 54 } //This might be a string? Looks like:`QYQp{V[YW[g`T
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 8 files
		$x161 = { 72 00 43 51 76 77 59 57 58 0C 04 6F 07 52 52 56 } //This might be a string? Looks like:rCQvwYWXoRRV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 4 files
		$x162 = { 74 74 07 42 7F 7F 56 04 6F 5D 57 72 59 5E 64 07 } //This might be a string? Looks like:ttBVo]WrY^d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 2 files
		$x65 = { 74 74 77 79 67 63 7F 7A 67 60 42 4F 78 5C 00 5E } //This might be a string? Looks like:ttwygczg`BOx\^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x163 = { 7A 52 77 67 07 63 05 61 72 0C 5F 6C 62 4D 59 66 } //This might be a string? Looks like:zRwgcar_lbMYf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x164 = { 00 52 0D 02 1A 59 00 53 51 64 5D 50 6D 04 06 45 } //This might be a string? Looks like:R\rYSQd]PmE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 3 files
		$x285 = { 6F 6D 7B 05 6F 62 67 64 56 58 59 07 54 62 4D 59 } //This might be a string? Looks like:om{obgdVXYTbMY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 4 files
		$x333 = { 5D 74 70 67 60 63 73 77 64 60 73 77 64 60 04 78 } //This might be a string? Looks like:]tpg`cswd`swd`x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x66 = { 7C 65 74 74 58 54 73 4C 6D 6D 04 7E 0D 79 67 1E } //This might be a string? Looks like:|ettXTsLmm~\ryg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x68 = { 65 5B 03 1E 1A 4F 0C 1A 43 0D 74 74 64 7C 71 77 } //This might be a string? Looks like:e[OC\rttd|qw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x165 = { 51 74 79 1A 05 7C 65 7D 77 71 43 1E 56 43 73 53 } //This might be a string? Looks like:Qty|e}wqCVCsS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.077819531114783 Found in 2 files
		$x69 = "BRRtOxOxOxLycvdx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x166 = { 52 57 42 65 53 64 7C 0D 5C 79 4D 76 60 74 0D 65 } //This might be a string? Looks like:RWBeSd|\r\yMv`t\re
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x167 = { 0C 06 60 70 78 0D 71 47 6F 61 59 0C 76 7D 60 57 } //This might be a string? Looks like:`px\rqGoaYv}`W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 2 files
		$x322 = { 67 43 57 4C 77 41 6C 62 00 00 7C 72 0C 42 6F 62 } //This might be a string? Looks like:gCWLwAlb|rBob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.305036532577266 Found in 4 files
		$x73 = "xOxOxOxOxOxLycvd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x168 = { 77 61 54 5E 4C 7B 5D 51 4F 0D 1A 1A 0C 44 74 73 } //This might be a string? Looks like:waT^L{]QO\rDts
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x169 = { 74 5A 79 07 7B 46 56 5C 5E 52 6F 5B 63 40 6C 06 } //This might be a string? Looks like:tZy{FV\^Ro[c@l
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x170 = { 44 71 42 4D 66 7F 6D 64 52 02 07 7D 79 5A 7A 0C } //This might be a string? Looks like:DqBMfmdR}yZz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 9 files
		$x79 = "|ptxOxOxOxOxOxOx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 5 files
		$x80 = { 51 64 58 79 67 76 64 70 0C 1E 7D 76 70 74 77 61 } //This might be a string? Looks like:QdXygvdp}vptwa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 4 files
		$x171 = { 71 5C 1A 0C 63 5C 1E 4D 44 74 65 0C 04 76 7A 5C } //This might be a string? Looks like:q\c\MDtevz\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1493974703476995 Found in 3 files
		$x82 = "{s`_xLy^gxattttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x172 = { 04 54 79 78 71 43 06 51 76 5D 6D 5C 61 5F 5A 58 } //This might be a string? Looks like:TyxqCQv]m\a_ZX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x173 = { 56 52 62 79 67 42 61 47 74 01 04 7D 77 7C 41 7B } //This might be a string? Looks like:VRbygBaGt}w|A{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x174 = { 58 79 61 64 5C 77 7A 62 7B 4F 57 50 77 04 7E 6C } //This might be a string? Looks like:Xyad\wzb{OWPw~l
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x175 = { 71 5F 05 5D 77 6F 78 6F 51 74 56 0C 7C 52 62 61 } //This might be a string? Looks like:q_]woxoQtV|Rba
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 2 files
		$x286 = { 72 79 61 52 5C 7C 7D 7B 05 6C 62 00 5E 6C 62 4D } //This might be a string? Looks like:ryaR\|}{lb^lbM
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x176 = { 74 0D 7C 71 4C 5C 43 03 7A 1A 5A 65 52 01 57 02 } //This might be a string? Looks like:t\r|qL\CzZeRW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 2 files
		$x299 = { 73 7D 6F 6D 67 76 54 62 00 5D 56 5B 59 60 50 6D } //This might be a string? Looks like:s}omgvTb]V[Y`Pm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2743974703476995 Found in 3 files
		$x177 = { 06 05 6F 7C 5E 7B 74 74 74 74 74 73 59 53 6D 04 } //This might be a string? Looks like:o|^{tttttsYSm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x7 = { 63 05 67 62 00 07 54 6D 7F 43 57 58 04 59 57 5B } //This might be a string? Looks like:cgbTmCWXYW[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7489992230622806 Found in 3 files
		$x11 = "tttxexOxOxOxOxOx" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.271782221599798 Found in 9 files
		$x13 = "xOxOxOxOxOxOxOxR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.548794940695399 Found in 6 files
		$x18 = { 4F 78 4F 78 4F 78 4F 78 4F 78 5C 05 64 5E 77 73 } //This might be a string? Looks like:OxOxOxOxOx\d^ws
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x19 = { 71 64 05 7B 71 64 05 7B 71 64 05 7B 71 64 05 7B } //This might be a string? Looks like:qd{qd{qd{qd{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293645 Found in 9 files
		$x20 = { 74 42 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:tB\rOxOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 10 files
		$x22 = { 58 59 05 54 62 7B 5D 57 73 7B 59 6C 06 67 45 57 } //This might be a string? Looks like:XYTb{]Ws{YlgEW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x178 = { 64 52 6C 62 4D 46 57 07 7B 5D 51 72 59 43 57 52 } //This might be a string? Looks like:dRlbMFW{]QrYCWR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 6 files
		$x179 = { 6F 60 7B 5A 6C 6D 7F 60 57 05 04 04 57 7D 67 45 } //This might be a string? Looks like:o`{Zlm`WW}gE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x180 = { 63 06 01 5C 0C 44 79 05 7C 43 71 52 1A 5E 7F 51 } //This might be a string? Looks like:c\Dy|CqR^Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 9 files
		$x181 = { 7F 04 6C 06 67 43 56 5C 77 5F 57 72 0C 4F 51 6D } //This might be a string? Looks like:lgCV\w_WrOQm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x315 = { 5D 6F 5B 67 59 56 5C 77 59 57 58 64 52 57 07 6C } //This might be a string? Looks like:]o[gYV\wYWXdRWl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.125 Found in 3 files
		$x27 = { 6D 74 72 5E 74 57 52 77 5E 74 72 0D 74 51 42 77 } //This might be a string? Looks like:mtr^tWRw^tr\rtQBw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x317 = { 64 74 76 79 67 7C 02 5E 5C 60 66 65 00 7C 41 70 } //This might be a string? Looks like:dtvyg|^\`fe|Ap
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x31 = { 73 6F 45 56 5B 67 04 6C 62 4D 72 56 58 63 59 74 } //This might be a string? Looks like:soEV[glbMrVXcYt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 6 files
		$x182 = { 02 6F 7F 1A 42 1E 07 05 5F 43 7E 5C 60 06 52 53 } //This might be a string? Looks like:oB_C~\`RS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 6 files
		$x183 = { 71 60 65 1A 62 52 06 43 0D 74 7D 64 7E 5C 05 78 } //This might be a string? Looks like:q`ebRC\rt}d~\x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x287 = { 6C 6D 7B 4F 6F 62 04 5C 57 7D 59 7F 6F 72 63 40 } //This might be a string? Looks like:lm{Oob\W}Yorc@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x319 = { 06 67 4C 54 62 00 5B 63 7D 59 42 6F 60 70 74 74 } //This might be a string? Looks like:gLTb[c}YBo`ptt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x184 = { 1A 01 41 60 7F 74 5C 7B 64 52 4C 79 66 40 42 4F } //This might be a string? Looks like:A`t\{dRLyf@BO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x34 = { 60 6F 6D 7F 41 54 62 00 5D 51 72 63 64 56 58 0C } //This might be a string? Looks like:`omATb]QrcdVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x185 = { 74 5F 65 07 7A 1A 7B 05 64 53 0C 04 1E 73 6F 6D } //This might be a string? Looks like:t_ez{dSsom
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.548794940695399 Found in 7 files
		$x36 = { 78 4F 78 4F 78 4F 78 4F 78 4F 7C 41 70 7F 74 67 } //This might be a string? Looks like:xOxOxOxOxO|Aptg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x186 = { 02 7C 65 46 77 73 7B 67 5C 05 60 78 52 0D 74 78 } //This might be a string? Looks like:|eFws{g\`xR\rtx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x187 = { 1A 05 7C 65 7D 77 71 43 1E 56 43 73 53 6D 46 7A } //This might be a string? Looks like:|e}wqCVCsSmFz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 7 files
		$x324 = { 4D 43 6C 62 67 78 54 62 7F 4C 6C 6D 7F 00 64 64 } //This might be a string? Looks like:MClbgxTbLlmdd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x188 = { 61 72 0C 5F 6C 62 4D 59 66 62 00 58 57 04 56 74 } //This might be a string? Looks like:ar_lbMYfbXWVt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x189 = { 52 7B 66 6C 62 59 4F 6F 60 63 01 6C 07 63 42 51 } //This might be a string? Looks like:R{flbYOo`clcBQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 8 files
		$x42 = { 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 5C 05 64 5E } //This might be a string? Looks like:OxOxOxOxOxOx\d^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9772170014624826 Found in 7 files
		$x326 = "ttdpwtdpwtdpwtdp" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.9056390622295662 Found in 4 files
		$x329 = "ttOtq|tyRwptpBta" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x190 = { 5A 50 5F 71 1A 56 46 60 5C 73 44 52 7F 62 59 63 } //This might be a string? Looks like:ZP_qVF`\sDRbYc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x349 = "RyXzFQLw_GqQB|vM" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 3 files
		$x191 = { 65 41 5E 60 7C 5C 05 06 42 5C 01 5B 7C 74 74 74 } //This might be a string? Looks like:eA^`|\B\[|ttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x284 = { 05 59 40 51 58 0C 47 6F 6D 7C 5C 7C 7D 63 45 64 } //This might be a string? Looks like:Y@QXGom|\|}cEd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x192 = { 77 05 4F 66 43 42 5C 0D 57 47 40 61 65 74 6D 04 } //This might be a string? Looks like:wOfCB\\rWG@aetm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x193 = { 73 06 0D 51 74 50 79 67 53 5C 71 6C 7D 71 0C 78 } //This might be a string? Looks like:s\rQtPygS\ql}qx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x194 = { 1E 1A 01 41 60 7F 74 5C 7B 64 52 4C 79 66 40 42 } //This might be a string? Looks like:A`t\{dRLyf@B
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x195 = { 6C 0C 1A 72 71 1E 74 7F 4C 7A 6C 04 70 76 64 52 } //This might be a string? Looks like:lrqtLzlpvdR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x196 = { 1A 62 63 58 73 42 7D 64 66 5C 5E 60 7C 54 52 7E } //This might be a string? Looks like:bcXsB}df\^`|TR~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x197 = { 79 02 7C 65 46 70 73 65 1A 51 67 76 7B 61 53 71 } //This might be a string? Looks like:y|eFpseQgv{aSq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x198 = "^Y@TmgElbMEPXcqV" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 5 files
		$x53 = "BxqtBxqtBxqtBxqt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x54 = { 04 76 6C 41 70 7F 74 61 06 01 56 7C 64 74 73 65 } //This might be a string? Looks like:vlAptaV|dtse
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4237949406953985 Found in 7 files
		$x199 = { 74 74 74 74 74 74 74 64 74 74 74 65 1A 1A 1A 1A } //This might be a string? Looks like:tttttttdttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.186278124459133 Found in 6 files
		$x301 = "ttttttttttwdgdtt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x343 = { 74 04 7B 59 51 73 7B 05 6F 70 5D 5D 57 58 67 46 } //This might be a string? Looks like:t{YQs{op]]WXgF
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 5 files
		$x304 = { 51 59 51 73 7B 00 56 06 67 59 57 63 67 45 57 62 } //This might be a string? Looks like:QYQs{VgYWcgEWb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0306390622295662 Found in 4 files
		$x305 = "rvtl|wRRpvtd|wtR" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 5 files
		$x56 = "xOxOxOxOxOxOxOsb" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 5 files
		$x57 = "OxOxOxOxOxOxMgcZ" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x200 = { 74 5F 65 74 5C 05 06 0D 6D 04 01 4F 4F 63 43 5A } //This might be a string? Looks like:t_et\\rmOOcCZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x345 = { 5C 04 64 5E 77 7C 41 78 7F 74 5F 06 42 52 78 74 } //This might be a string? Looks like:\d^w|Axt_BRxt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 4 files
		$x60 = { 73 67 59 56 58 04 45 57 58 73 05 6F 63 77 4C 57 } //This might be a string? Looks like:sgYVXEWXsocwLW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.2743974703476995 Found in 5 files
		$x201 = { 52 74 74 5F 6C 42 77 67 74 70 74 74 7C 59 7B 0C } //This might be a string? Looks like:Rtt_lBwgtptt|Y{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 5 files
		$x202 = "{gQbcLPcwYVXoCVX" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x294 = { 67 62 6F 6D 7F 4F 54 62 0C 40 65 66 7C 4D 79 5F } //This might be a string? Looks like:gbomOTb@ef|My_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x203 = { 0C 63 5C 1E 4D 44 74 72 5A 77 1A 06 60 7C 03 7E } //This might be a string? Looks like:c\MDtrZw`|~
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 6 files
		$x204 = { 5E 51 59 51 73 67 45 6C 07 41 71 57 06 63 40 51 } //This might be a string? Looks like:^QYQsgElAqWc@Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x311 = { 73 4C 63 72 0C 7B 51 62 4D 05 54 60 7F 00 51 72 } //This might be a string? Looks like:sLcr{QbMT`Qr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 5 files
		$x205 = "cBQrYCW^wOQrgtdt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4966407621868583 Found in 5 files
		$x312 = "ttttRwoxottttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 6 files
		$x64 = "V|ptxOxOxOxOxOxO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x206 = { 57 58 59 05 54 62 73 46 54 6D 45 59 64 06 7F 45 } //This might be a string? Looks like:WXYTbsFTmEYdE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x207 = { 74 5C 79 56 74 4C 71 1A 43 0C 05 7A 5A 7B 0D 7F } //This might be a string? Looks like:t\yVtLqCzZ{\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x334 = { 45 04 79 43 71 57 6F 44 73 06 46 67 5B 51 5F 77 } //This might be a string? Looks like:EyCqWoDsFg[Q_w
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x67 = { 6F 62 00 05 60 7D 7F 43 6C 07 63 4F 56 05 59 5E } //This might be a string? Looks like:ob`}ClcOVY^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 2 files
		$x208 = { 5C 79 0D 74 1E 07 77 01 04 7B 0D 73 73 64 03 72 } //This might be a string? Looks like:\y\rtw{\rssdr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x209 = { 5C 05 05 7C 60 4F 65 57 7A 0D 41 62 63 06 4D 57 } //This might be a string? Looks like:\|`OeWz\rAbcMW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x210 = { 05 54 62 0C 40 64 62 00 5E 60 06 77 45 57 5E 7B } //This might be a string? Looks like:Tb@db^`wEW^{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x211 = { 65 7E 7A 60 06 56 53 67 58 79 61 51 4D 47 4C 64 } //This might be a string? Looks like:e~z`VSgXyaQMGLd
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 6 files
		$x212 = { 6D 5D 5F 6F 6D 77 05 54 62 0C 40 64 7D 7B 05 6F } //This might be a string? Looks like:m]_omwTb@d}{o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 2 files
		$x340 = { 52 5C 60 6C 78 52 0D 5F 1A 03 06 58 79 61 64 4C } //This might be a string? Looks like:R\`lxR\r_XyadL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x342 = { 63 01 43 00 52 1A 5A 70 56 5F 7D 06 07 6C 65 5D } //This might be a string? Looks like:cCRZpV_}le]
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x213 = { 4C 79 67 64 5D 61 63 5A 41 04 72 71 65 57 52 06 } //This might be a string? Looks like:Lygd]acZArqeWR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 7 files
		$x76 = { 62 73 07 6F 60 7B 4C 54 6D 67 45 6C 07 73 46 60 } //This might be a string? Looks like:bso`{LTmgElsF`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x214 = { 42 64 02 1A 5B 79 4D 6D 04 02 71 5C 1A 0C 62 40 } //This might be a string? Looks like:Bd[yMmq\b@
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 4 files
		$x215 = { 5B 71 5C 1A 0C 63 5C 1E 42 4F 42 73 71 1A 51 67 } //This might be a string? Looks like:[q\c\BOBsqQg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.521782221599798 Found in 4 files
		$x292 = { 52 74 74 74 74 74 01 53 40 52 01 74 41 74 5B 7B } //This might be a string? Looks like:RtttttS@RtAt[{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x327 = { 4F 7C 41 60 7F 74 4C 79 61 76 64 70 5D 51 7F 05 } //This might be a string? Looks like:O|A`tLyavdp]Q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 2 files
		$x347 = "CWrcq`tttYds}omg" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6216407621868583 Found in 4 files
		$x328 = { 74 74 74 74 74 74 74 74 64 74 74 74 42 76 00 4C } //This might be a string? Looks like:ttttttttdtttBvL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x216 = { 76 01 1A 64 63 6F 46 57 07 51 45 6C 04 0C 59 56 } //This might be a string? Looks like:vdcoFWQElYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x217 = { 02 42 7F 78 6F 62 73 07 6F 60 7B 4C 54 6D 67 45 } //This might be a string? Looks like:Bxobso`{LTmgE
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.1556390622295662 Found in 6 files
		$x331 = { 4F 78 4F 78 4F 73 62 79 02 73 51 62 5C 06 60 78 } //This might be a string? Looks like:OxOxOsbysQb\`x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 7 files
		$x218 = { 64 60 63 7F 61 63 73 63 62 63 04 5D 6F 62 52 74 } //This might be a string? Looks like:d`cacscbc]obRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x219 = { 72 6D 59 06 76 77 74 76 79 1A 04 62 79 02 73 57 } //This might be a string? Looks like:rmYvwtvybysW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x220 = { 74 62 63 58 79 1E 7C 59 0C 06 71 43 02 71 01 61 } //This might be a string? Looks like:tbcXy|YqCqa
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x221 = { 00 5E 54 62 7B 5D 51 72 63 4F 7C 72 70 52 6C 5B } //This might be a string? Looks like:^Tb{]QrcO|rpRl[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 4 files
		$x222 = { 74 74 52 0D 64 78 5D 56 77 05 71 4F 65 74 60 73 } //This might be a string? Looks like:ttR\rdx]VwqOet`s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4237949406953985 Found in 7 files
		$x223 = { 74 77 74 74 74 74 74 74 74 74 74 65 1A 1A 1A 1A } //This might be a string? Looks like:twttttttttte
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x224 = "Qso]W}cYtqxpcrMO" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 4 files
		$x0 = { 59 51 70 63 40 51 58 59 4C 57 07 00 41 6F 62 00 } //This might be a string? Looks like:YQpc@QXYLWAob
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 8 files
		$x1 = { 62 4D 59 51 72 63 71 56 58 59 05 54 62 7B 5D 57 } //This might be a string? Looks like:bMYQrcqVXYTb{]W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x225 = { 42 5C 0C 59 05 78 5A 7B 1A 76 74 77 04 79 7C 41 } //This might be a string? Looks like:B\YxZ{vtwy|A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x2 = { 67 71 57 07 04 42 51 6D 67 59 56 5E 00 5D 57 62 } //This might be a string? Looks like:gqWBQmgYV^]Wb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x226 = { 43 54 5C 1A 5D 04 74 5F 65 57 52 02 06 5A 1A 53 } //This might be a string? Looks like:CT\]t_eWRZS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x227 = { 70 63 07 59 5E 6F 60 7B 5A 6C 6D 7F 60 57 05 04 } //This might be a string? Looks like:pcY^o`{Zlm`W
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x228 = { 73 04 57 7D 64 52 6C 07 0C 40 56 06 67 4C 51 62 } //This might be a string? Looks like:sW}dRl@VgLQb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.577819531114783 Found in 4 files
		$x229 = { 74 67 62 54 6D 7F 05 51 62 73 46 64 62 4D 46 57 } //This might be a string? Looks like:tgbTmQbsFdbMFW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6084585933443494 Found in 7 files
		$x230 = "ZaBtdtvw@tttdtwd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x231 = { 59 0C 00 7D 63 7C 7A 1A 51 04 77 5F 65 07 67 5A } //This might be a string? Looks like:Y}c|zQw_egZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x232 = { 51 76 71 65 1A 7A 0C 0D 65 59 56 74 02 4D 06 60 } //This might be a string? Looks like:Qvqez\reYVtM`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7987949406953985 Found in 4 files
		$x233 = { 74 74 74 74 0D 74 74 74 74 74 01 53 40 52 01 74 } //This might be a string? Looks like:tttt\rtttttS@Rt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.375 Found in 4 files
		$x4 = "todt@trdtWtwFttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x234 = { 7C 04 70 7F 74 42 47 6F 76 64 78 60 04 6F 6D 5C } //This might be a string? Looks like:|ptBGovdx`om\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 5 files
		$x235 = { 74 74 74 73 59 53 6D 04 00 57 5C 1E 63 51 60 56 } //This might be a string? Looks like:tttsYSmW\cQ`V
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 4 files
		$x10 = "c{s`_xLy^gxatttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x236 = { 62 4D 59 7C 7D 67 43 57 4C 77 46 6C 6D 7F 5B 6F } //This might be a string? Looks like:bMY|}gCWLwFlm[o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x291 = { 4F 5D 72 41 56 51 4D 77 7D 50 1A 66 7F 45 1E 5F } //This might be a string? Looks like:O]rAVQMw}PfE_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 4 files
		$x14 = "txOxOxOxOxOxO|Ap" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.061278124459133 Found in 5 files
		$x16 = { 0C 50 42 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:PB\rOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 5 files
		$x17 = { 1A 71 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:qOxOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.327819531114783 Found in 6 files
		$x237 = "RgcWX]]WXgFobgsP" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6774212838293645 Found in 6 files
		$x306 = { 1A 1A 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:\rOxOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x307 = { 54 79 61 64 42 65 43 59 70 77 52 1A 5A 05 51 67 } //This might be a string? Looks like:TyadBeCYpwRZQg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x21 = { 43 5F 67 4F 41 0D 7F 77 4D 05 70 58 6C 00 79 5B } //This might be a string? Looks like:C_gOA\rwMpXly[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x238 = { 74 62 61 72 6D 64 63 65 66 70 73 5E 4D 59 05 71 } //This might be a string? Looks like:tbarmdcefps^MYq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x239 = { 01 74 67 07 63 05 63 6D 7B 59 56 5E 0C 5C 54 58 } //This might be a string? Looks like:tgccm{YV^\TX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x240 = { 43 6C 07 63 4F 56 42 74 74 44 64 73 7D 6F 6D 67 } //This might be a string? Looks like:ClcOVBttDds}omg
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x241 = { 74 5A 65 5C 74 01 65 00 76 7D 7C 44 0D 03 6D 1A } //This might be a string? Looks like:tZe\tev}|D\rm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x242 = { 64 78 52 0D 6C 77 71 03 78 70 7F 7D 65 4D 5F 60 } //This might be a string? Looks like:dxR\rlwqxp}eM_`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 7 files
		$x243 = { 57 58 56 52 6F 72 63 4F 51 7D 7F 04 6C 06 67 43 } //This might be a string? Looks like:WXVRorcOQ}lgC
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 10 files
		$x30 = { 45 6C 07 73 46 60 07 63 5F 51 72 59 43 57 52 74 } //This might be a string? Looks like:ElsF`c_QrYCWRt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 3 files
		$x32 = { 43 6C 07 41 59 6F 70 63 01 6C 07 5D 5D 57 58 51 } //This might be a string? Looks like:ClAYopcl]]WXQ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x244 = { 57 58 73 46 54 62 51 40 6F 62 64 74 6D 04 0C 4C } //This might be a string? Looks like:WXsFTbQ@obdtmL
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x336 = "ofw]V}wFTb{]QrYC" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.543564443199596 Found in 7 files
		$x320 = { 02 71 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:qOxOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 5 files
		$x37 = { 62 0D 65 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 } //This might be a string? Looks like:b\rexOxOxOxOxOxOx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x245 = { 56 07 52 41 54 72 0C 40 6F 7D 63 4C 6C 6D 78 74 } //This might be a string? Looks like:VRATr@o}cLlmxt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x40 = { 63 59 67 62 00 07 54 6D 7F 43 57 58 04 59 57 5B } //This might be a string? Looks like:cYgbTmCWXYW[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x246 = { 70 73 42 56 52 77 7B 6C 6D 7C 74 67 58 63 5C 74 } //This might be a string? Looks like:psBVRw{lm|tgXc\t
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 7 files
		$x247 = { 42 74 51 74 50 79 61 53 5C 71 6C 6D 71 0C 4C 56 } //This might be a string? Looks like:BtQtPyaS\qlmqLV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x248 = { 5C 7B 5D 60 5F 59 1A 1A 0D 47 07 72 5A 74 5F 6C } //This might be a string? Looks like:\{]`_Y\rGrZt_l
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x249 = { 5C 79 4D 0D 7D 01 77 6C 43 06 52 1E 6C 53 42 50 } //This might be a string? Looks like:\yM\r}wlCRlSBP
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 4 files
		$x250 = { 76 60 74 0D 65 1A 1A 7A 0D 5D 4C 76 5A 43 77 62 } //This might be a string? Looks like:v`t\rez\r]LvZCwb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x344 = { 67 53 6C 62 4D 46 57 07 7B 74 56 06 67 5E 64 70 } //This might be a string? Looks like:gSlbMFW{tVg^dp
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 6 files
		$x251 = { 42 7E 79 67 64 5D 50 6D 0D 5B 71 5E 7C 04 05 78 } //This might be a string? Looks like:B~ygd]Pm\r[q^|x
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 5 files
		$x252 = { 70 6F 62 7B 43 6F 72 63 64 57 07 59 40 51 72 63 } //This might be a string? Looks like:pob{CorcdWY@Qrc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x47 = { 44 72 66 7C 57 06 71 64 70 77 76 42 60 74 78 7D } //This might be a string? Looks like:Drf|WqdpwvB`tx}
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x253 = { 7C 7D 6F 59 6C 06 67 43 56 5C 77 5E 6F 6D 7B 05 } //This might be a string? Looks like:|}oYlgCV\w^om{
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x254 = { 52 79 72 7A 40 77 04 76 01 65 45 74 6D 6D 67 78 } //This might be a string? Looks like:Ryrz@wveEtmmgx
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x255 = { 43 0C 57 42 01 04 76 1A 59 00 53 62 0D 7A 7B 64 } //This might be a string? Looks like:CWBvYSb\rz{d
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.7743974703476995 Found in 5 files
		$x49 = { 78 4F 78 4F 78 4F 78 4F 78 4D 63 5C 1E 4C 71 02 } //This might be a string? Looks like:xOxOxOxOxMc\Lq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7640976555739163 Found in 5 files
		$x256 = { 71 78 0D 71 71 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:qx\rqqOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.305036532577266 Found in 3 files
		$x50 = { 78 4F 78 4F 78 4F 78 4F 78 4F 78 5C 05 64 5E 71 } //This might be a string? Looks like:xOxOxOxOxOx\d^q
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x257 = { 59 4F 67 72 63 5C 51 62 51 5B 6F 6D 7F 64 56 58 } //This might be a string? Looks like:YOgrc\QbQ[omdVX
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x258 = { 74 03 74 7B 61 6F 6D 67 7C 6C 62 00 5E 57 72 63 } //This might be a string? Looks like:tt{aomg|lb^Wrc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x289 = { 65 72 73 4F 56 07 63 41 6C 58 4D 00 7C 7D 5D 41 } //This might be a string? Looks like:ersOVcAlXM|}]A
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293647 Found in 6 files
		$x52 = { 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4D 62 5C } //This might be a string? Looks like:xOxOxOxOxOxOxMb\
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 5 files
		$x259 = { 0D 51 53 6D 59 06 71 5C 1A 0C 63 5C 1E 4D 62 63 } //This might be a string? Looks like:\rQSmYq\c\Mbc
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4966407621868583 Found in 5 files
		$x300 = "Rwoxottttttttttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x260 = { 4D 77 76 71 53 5D 52 64 5C 6D 01 60 56 52 7E 79 } //This might be a string? Looks like:MwvqS]Rd\m`VR~y
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x261 = { 78 4F 78 4C 7B 64 43 0C 57 42 01 07 5E 7F 74 74 } //This might be a string? Looks like:xOxL{dCWB^tt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 5 files
		$x262 = { 6F 73 0C 5D 57 72 4D 43 6C 05 77 4F 51 72 67 74 } //This might be a string? Looks like:os]WrMClwOQrgt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.396782221599798 Found in 7 files
		$x302 = { 0C 05 70 70 77 52 74 74 74 79 52 77 74 74 74 74 } //This might be a string? Looks like:ppwRtttyRwtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4913146570363986 Found in 7 files
		$x55 = { 0D 74 74 74 74 74 1A 1A 1A 1A 1A 42 74 74 74 74 } //This might be a string? Looks like:\rtttttBtttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.4237949406953985 Found in 5 files
		$x263 = { 74 74 74 74 74 74 74 74 71 1E 1A 1A 1A 1A 74 74 } //This might be a string? Looks like:ttttttttqtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.0 Found in 8 files
		$x264 = { 67 53 4F 1E 1A 1A 1A 1A 03 74 5E 74 74 74 76 79 } //This might be a string? Looks like:gSOt^tttvy
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.5 Found in 4 files
		$x346 = { 60 70 60 07 63 05 63 62 00 5A 6C 62 00 5E 57 72 } //This might be a string? Looks like:`p`ccbZlb^Wr
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 3 files
		$x61 = { 45 51 70 6F 43 56 59 7B 45 57 58 51 46 6F 60 0C } //This might be a string? Looks like:EQpoCVY{EWXQFo`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 4 files
		$x265 = { 74 01 42 7F 78 64 05 04 5D 56 73 7B 05 56 58 59 } //This might be a string? Looks like:tBxd]Vs{VXY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x266 = { 74 65 64 77 67 07 63 05 61 62 0C 5E 51 62 4D 59 } //This might be a string? Looks like:tedwgcab^QbMY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 6 files
		$x267 = { 78 5F 60 5E 74 5C 52 7C 7E 42 7D 64 7F 52 0D 7C } //This might be a string? Looks like:x_`^t\R|~B}dR\r|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.625 Found in 6 files
		$x268 = { 63 06 7F 45 51 72 63 71 57 07 00 4F 57 07 4D 59 } //This might be a string? Looks like:cEQrcqWOWMY
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.75 Found in 3 files
		$x313 = { 76 74 73 50 79 1E 71 43 72 56 42 1E 79 77 01 6D } //This might be a string? Looks like:vtsPyqCrVBywm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x269 = { 7D 60 64 7A 70 6D 05 51 74 50 79 67 53 76 71 6C } //This might be a string? Looks like:}`dzpmQtPygSvql
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.702819531114783 Found in 4 files
		$x270 = { 1A 6F 5A 4C 63 1E 65 06 1A 1A 07 54 78 5F 50 4F } //This might be a string? Looks like:oZLceTx_PO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 8 files
		$x271 = { 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B } //This might be a string? Looks like:C\rqwBFepMVW}Lx[
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 2 files
		$x272 = { 64 5E 76 77 41 60 7F 74 4F 06 07 43 53 6C 52 0C } //This might be a string? Looks like:d^vwA`tOCSlR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9237949406953985 Found in 3 files
		$x273 = "ttwattttqdtttsVt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 1 files
		$x337 = { 06 71 63 1E 41 76 5B 7E 07 6C 72 52 01 54 74 1A } //This might be a string? Looks like:qcAv[~lrRTt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 4 files
		$x71 = { 60 73 67 6C 6D 72 77 5E 54 72 4D 42 51 7D 5D 0D } //This might be a string? Looks like:`sglmrw^TrMBQ}]\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x274 = { 01 5D 53 6F 04 77 6C 65 7C 1A 0D 5B 71 52 07 6D } //This might be a string? Looks like:]Sowle|\r[qRm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 7 files
		$x321 = { 04 77 1A 5A 41 78 7F 74 64 47 42 56 7A 7B 64 53 } //This might be a string? Looks like:wZAxtdGBVz{dS
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 3 files
		$x275 = { 5B 64 63 52 70 42 72 7D 66 76 7E 5F 74 6D 0D 1A } //This might be a string? Looks like:[dcRpBr}fv~_tm\r
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 9 files
		$x276 = { 7A 06 40 02 1A 71 4D 0D 43 65 05 0C 53 57 06 1E } //This might be a string? Looks like:z@qM\rCeSW
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 6 files
		$x277 = { 57 7D 77 05 50 7D 4C 74 5D 7C 5C 78 5E 7F 66 6C } //This might be a string? Looks like:W}wP}Lt]|\x^fl
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.7169171866886992 Found in 9 files
		$x278 = { 74 74 74 74 71 1E 1A 1A 1A 1A 74 74 74 74 74 7C } //This might be a string? Looks like:ttttqttttt|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.8024212838293645 Found in 11 files
		$x77 = { 51 42 0D 4F 78 4F 78 4F 78 4F 78 4F 78 4F 78 4F } //This might be a string? Looks like:QB\rOxOxOxOxOxOxO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 4 files
		$x279 = { 54 79 51 64 5D 6D 71 02 6C 72 5F 60 5C 1A 67 5A } //This might be a string? Looks like:TyQd]mqlr_`\gZ
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x280 = { 71 02 6F 67 00 5C 43 4C 51 77 60 4F 05 5A 6D 07 } //This might be a string? Looks like:qog\CLQw`OZm
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.375 Found in 3 files
		$x293 = { 76 74 52 7C 76 74 52 65 7D 7F 59 56 6D 63 59 56 } //This might be a string? Looks like:vtR|vtRe}YVmcYV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.0 Found in 5 files
		$x281 = { 42 1E 07 56 7A 78 65 41 59 7D 5F 7E 1A 7F 05 73 } //This might be a string? Looks like:BVzxeAY}_~s
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 2 files
		$x295 = { 07 04 42 6C 6D 7F 59 67 6D 5D 5F 54 72 73 40 6F } //This might be a string? Looks like:BlmYgm]_Trs@o
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 5 files
		$x81 = "tcc{s`_xLy^gxatt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.875 Found in 3 files
		$x330 = { 6D 56 7B 63 5C 07 42 5E 76 73 7F 67 1A 06 64 5E } //This might be a string? Looks like:mV{c\B^vsgd^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 3.452819531114783 Found in 5 files
		$x282 = { 78 64 05 04 5D 56 73 7B 05 56 58 59 40 6F 04 56 } //This might be a string? Looks like:xd]Vs{VXY@oV
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.6774212838293645 Found in 7 files
		$x83 = "]ttOxOxOxOxOxOxO" ascii

		condition:
(80 of ($x0,$x1,$x2,$x3,$x4,$x5,$x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27,$x28,$x29,$x30,$x31,$x32,$x33,$x34,$x35,$x36,$x37,$x38,$x39,$x40,$x41,$x42,$x43,$x44,$x45,$x46,$x47,$x48,$x49,$x50,$x51,$x52,$x53,$x54,$x55,$x56,$x57,$x58,$x59,$x60,$x61,$x62,$x63,$x64,$x65,$x66,$x67,$x68,$x69,$x70,$x71,$x72,$x73,$x74,$x75,$x76,$x77,$x78,$x79,$x80,$x81,$x82,$x83) ) or (159 of ($x84,$x85,$x86,$x87,$x88,$x89,$x90,$x91,$x92,$x93,$x94,$x95,$x96,$x97,$x98,$x99,$x100,$x101,$x102,$x103,$x104,$x105,$x106,$x107,$x108,$x109,$x110,$x111,$x112,$x113,$x114,$x115,$x116,$x117,$x118,$x119,$x120,$x121,$x122,$x123,$x124,$x125,$x126,$x127,$x128,$x129,$x130,$x131,$x132,$x133,$x134,$x135,$x136,$x137,$x138,$x139,$x140,$x141,$x142,$x143,$x144,$x145,$x146,$x147,$x148,$x149,$x150,$x151,$x152,$x153,$x154,$x155,$x156,$x157,$x158,$x159,$x160,$x161,$x162,$x163,$x164,$x165,$x166,$x167,$x168,$x169,$x170,$x171,$x172,$x173,$x174,$x175,$x176,$x177,$x178,$x179,$x180,$x181,$x182,$x183,$x184,$x185,$x186,$x187,$x188,$x189,$x190,$x191,$x192,$x193,$x194,$x195,$x196,$x197,$x198,$x199,$x200,$x201,$x202,$x203,$x204,$x205,$x206,$x207,$x208,$x209,$x210,$x211,$x212,$x213,$x214,$x215,$x216,$x217,$x218,$x219,$x220,$x221,$x222,$x223,$x224,$x225,$x226,$x227,$x228,$x229,$x230,$x231,$x232,$x233,$x234,$x235,$x236,$x237,$x238,$x239,$x240,$x241,$x242,$x243,$x244,$x245,$x246,$x247,$x248,$x249,$x250,$x251,$x252,$x253,$x254,$x255,$x256,$x257,$x258,$x259,$x260,$x261,$x262,$x263,$x264,$x265,$x266,$x267,$x268,$x269,$x270,$x271,$x272,$x273,$x274,$x275,$x276,$x277,$x278,$x279,$x280,$x281,$x282) ) or (12 of ($x283,$x284,$x285,$x286,$x287,$x288,$x289,$x290,$x291,$x292,$x293,$x294,$x295,$x296) ) or (25 of ($x297,$x298,$x299,$x300,$x301,$x302,$x303,$x304,$x305,$x306,$x307,$x308,$x309,$x310,$x311,$x312,$x313,$x314,$x315,$x316,$x317,$x318,$x319,$x320,$x321,$x322,$x323,$x324,$x325,$x326,$x327,$x328,$x329,$x330,$x331,$x332) ) or (12 of ($x333,$x334,$x335,$x336,$x337,$x338,$x339,$x340,$x341,$x342,$x343,$x344,$x345,$x346,$x347,$x348,$x349) )}