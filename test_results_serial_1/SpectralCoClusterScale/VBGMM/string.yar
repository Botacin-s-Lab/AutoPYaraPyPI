rule 040.dll.patched_SpectralCoClusterScale_VBGMM
{
	//Input TP Rate:
	//11/15
	strings:
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.595103078152579 Found in 6 files
		$x6 = { 62 51 40 6F 62 64 74 6D 04 0C 4C 6F 6D 7B 05 56 58 59 5F 51 74 74 74 6D 04 0C 42 51 7D 7C 07 7B 74 77 53 6D 07 7B 46 56 58 7B 5D 57 72 42 74 74 74 77 53 6D 07 6F 5D 56 06 67 5F 6C 62 4D 46 74 } //This might be a string? Looks like:bQ@obdtmLom{VXY_QtttmBQ}|{twSm{FVX{]WrBtttwSmo]Vg_lbMFt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.976409765557392 Found in 6 files
		$x9 = { 6D 0D 5B 71 5F 60 5E 74 5C 52 54 7C 77 01 45 72 74 6C 5D 7D 74 6C 45 72 74 5A 5D 7D 74 5A 41 73 76 73 00 53 4C 56 7A 64 5F 6D 64 4D 1A 7C 04 0D 7A 53 4F 06 4D 42 78 74 74 74 77 04 7F 78 7D 45 } //This might be a string? Looks like:m\r[q_`^t\RT|wErtl]}tlErtZ]}tZAsvsSLVzd_mdM|\rzSOMBxtttwx}E
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x2 = { 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 52 01 7A 71 } //This might be a string? Looks like:RzqRzqRzqRzqRzqRzqRzqRzqRzqRzqRzqRzqRzqRzqRzqRzq
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.623232282211646 Found in 5 files
		$x14 = { 56 58 0C 5B 56 58 73 41 7C 72 7B 5D 57 58 00 43 51 76 77 5C 6F 66 77 4C 51 62 01 52 54 62 01 52 67 70 0C 61 7C 72 04 43 6F 72 60 40 71 64 05 7E 7F 74 74 74 74 74 74 74 74 74 74 74 74 74 74 74 } //This might be a string? Looks like:VX[VXsA|r{]WXCQvw\ofwLQbRTbRgpa|rCor`@qd~ttttttttttttttt
		//Benign FP est: -8.008408829270734E-4 Malicious FP est: -0.0 Entropy: 5.202819531114784 Found in 6 files
		$x15 = { 5C 60 6D 64 53 5C 05 01 6D 50 00 05 7E 7C 04 73 02 01 5A 7C 7A 46 41 05 7D 42 1E 07 50 65 0D 65 41 46 5B 47 76 01 41 7B 06 78 6C 70 71 4C 74 65 41 52 5D 7D 7A 1A 59 1E 0D 60 77 74 7A 73 5F 1A } //This might be a string? Looks like:\`mdS\mP~|sZ|zFA}BPe\reAF[GvA{xlpqLteAR]}zY\r`wtzs_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.575605320957341 Found in 6 files
		$x16 = { 61 60 1A 0C 04 70 74 1E 63 42 65 0C 04 71 7C 05 70 4D 64 70 74 74 74 77 64 1A 06 60 6C 1A 0C 54 79 1E 71 43 02 71 01 66 47 74 74 74 74 53 5F 4C 77 1A 1A 71 1A 1A 06 0C 06 7B 7C 04 70 65 42 52 } //This might be a string? Looks like:a`ptcBeq|pMdptttwd`lTyqCqfGttttS_Lwq{|peBR
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.085479296672175 Found in 5 files
		$x17 = { 52 1E 42 64 5C 6D 06 0D 5C 05 60 7C 58 6C 43 01 78 1A 5A 47 1E 5A 65 5B 71 4F 65 03 7E 1A 44 73 1A 06 60 0D 5C 05 05 64 5C 0C 72 71 01 5B 1E 7F 63 53 64 02 4C 5B 64 66 7E 0D 45 67 60 7A 5D 4F } //This might be a string? Looks like:RBd\m\r\`|XlCxZGZe[qOe~Ds`\r\d\rq[cSdL[df~\rEg`z]O
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.006819956104106 Found in 7 files
		$x18 = { 74 74 74 72 73 5C 6C 07 67 59 6F 58 51 5A 54 62 45 47 57 72 04 40 57 06 77 4D 56 5B 7B 05 51 6D 6F 06 50 7D 59 03 74 74 74 74 74 74 74 74 64 60 7F 71 67 70 63 72 67 05 5D 7F 66 5E 41 78 61 60 } //This might be a string? Looks like:tttrs\lgYoXQZTbEGWr@WwMV[{QmoP}Yttttttttd`qgpcrg]f^Axa`
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 4 files
		$x1 = { 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 0D 65 71 42 } //This might be a string? Looks like:\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB\reqB
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.303618358901742 Found in 5 files
		$x20 = { 73 53 1A 04 5A 40 7D 46 74 74 74 74 7C 6D 74 51 74 7B 64 1A 0C 54 79 5D 02 52 74 74 74 76 73 42 7D 64 71 60 65 1A 62 5C 01 50 05 74 74 74 74 5D 56 77 05 74 04 71 1A 04 5A 40 7D 42 74 74 74 74 } //This might be a string? Looks like:sSZ@}Ftttt|mtQt{dTy]RtttvsB}dq`eb\Ptttt]VwtqZ@}Btttt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 1.9671116408333627 Found in 10 files
		$x22 = "tvtt|ttRtvtt|ttRtvtt|ttRtvtt|ttRtpRtpttdtwttpttdtwttpttdtwttpttd" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.089444344318725 Found in 9 files
		$x23 = "ttRtvtt|ttRtpRtpttdtwttpttdtwttpttdtwttpttdtwttpttdtwtt]tvpt|dt]" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.104934179450871 Found in 5 files
		$x24 = { 43 72 03 4F 4C 79 51 67 74 02 0D 06 60 70 5C 77 5F 47 07 5A 43 64 7A 77 45 05 77 70 7F 65 51 53 52 02 1E 06 61 40 5C 52 03 7C 76 5E 7F 72 7A 46 41 05 74 05 0C 04 0D 4F 43 02 51 67 76 7C 72 7A } //This might be a string? Looks like:CrOLyQgt\r`p\w_GZCdzwEwpeQSRa@\R|v^rzFAt\rOCQgv|rz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.382659765557392 Found in 6 files
		$x27 = { 78 6D 72 4D 0D 5F 7F 4C 46 43 78 4F 56 02 65 05 7B 7D 66 05 0C 61 63 04 41 53 6C 07 51 47 57 06 7B 06 50 06 1E 71 5D 01 40 65 5E 00 50 57 5B 03 7A 5B 44 03 1E 4F 41 02 40 1A 42 0D 53 79 4F 0C } //This might be a string? Looks like:xmrM\r_LFCxOVe{}facASlQGW{Pq]@e^PW[z[DOA@B\rSyO
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.921973149067329 Found in 5 files
		$x7 = { 51 73 7D 60 70 5C 77 02 47 4C 5A 41 63 70 71 43 61 51 64 66 7C 7D 40 43 67 52 06 05 60 1A 01 43 72 51 64 1E 7E 76 5A 52 7C 64 70 7C 03 4C 06 64 50 61 06 6D 4F 03 4D 58 7E 76 5A 52 7C 64 70 7C } //This might be a string? Looks like:Qs}`p\wGLZAcpqCaQdf|}@CgR`CrQd~vZR|dp|LdPamOMX~vZR|dp|
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6407231490673295 Found in 6 files
		$x8 = { 64 6D 63 5B 74 70 45 04 57 74 77 7E 51 62 01 74 61 62 73 00 74 70 73 42 56 52 77 7B 6C 6D 7C 74 67 58 63 5C 74 70 45 5D 57 52 77 61 6C 6D 67 04 56 58 67 5D 50 64 74 74 74 74 77 72 56 58 59 5E } //This might be a string? Looks like:dmc[tpEWtw~QbtabstpsBVRw{lm|tgXc\tpE]WRwalmgVXg]PdttttwrVXY^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.0 Found in 3 files
		$x0 = "V}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wBV}wB" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.810328664259099 Found in 6 files
		$x10 = { 6D 59 1A 7F 42 01 04 7F 74 7C 5A 72 5C 74 50 7E 67 52 72 7C 67 42 72 7E 67 52 7E 7C 67 42 7E 79 67 64 5D 50 6D 0D 5B 71 5E 7C 04 05 78 53 4C 7B 53 71 5B 0D 0C 0D 56 71 74 74 74 74 51 66 61 77 } //This might be a string? Looks like:mYBt|Zr\tP~gRr|gBr~gR~|gB~ygd]Pm\r[q^|xSL{Sq[\r\rVqttttQfaw
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.316024413893479 Found in 8 files
		$x11 = { 72 4C 46 02 66 04 41 47 50 01 40 57 44 02 43 79 07 1E 43 0D 71 77 42 46 65 70 4D 56 57 7D 4C 78 5B 7E 4C 0D 4F 7B 4F 46 1A 64 05 51 79 61 04 7B 6D 62 04 0C 5F 6F 07 41 43 56 06 51 02 53 01 7A } //This might be a string? Looks like:rLFfAGP@WDCyC\rqwBFepMVW}Lx[~L\rO{OFdQya{mb_oACVQSz
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.884623781480404 Found in 7 files
		$x12 = { 76 66 45 74 74 71 1A 74 7D 64 61 44 64 74 74 74 65 0C 05 74 40 43 7B 5F 60 7D 1A 5C 05 42 5E 77 76 43 77 42 01 04 77 1A 5A 41 78 7F 74 64 47 42 56 7A 7B 64 53 07 79 61 76 64 70 7E 0D 7D 71 5F } //This might be a string? Looks like:vfEttqt}daDdtttet@C{_`}\B^wvCwBwZAxtdGBVz{dSyavdp~\r}q_
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.327819531114784 Found in 6 files
		$x13 = { 6D 74 51 74 7B 64 1A 0C 54 79 5D 02 52 74 74 74 76 73 42 7D 64 71 60 65 1A 62 5C 01 50 05 74 74 74 74 5D 56 77 05 74 04 71 1A 04 5A 40 7D 42 74 74 74 74 7C 6D 74 51 74 7B 64 1A 0C 54 7B 6D 04 } //This might be a string? Looks like:mtQt{dTy]RtttvsB}dq`eb\Ptttt]VwtqZ@}Btttt|mtQt{dT{m
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.253524413893479 Found in 15 files
		$x3 = { 00 64 A1 18 00 00 00 33 FF 8B 50 04 8B F7 BB 58 4A 01 10 EB 04 3B C2 74 0E 33 C0 8B CA F0 0F B1 0B 85 C0 75 F0 EB 03 33 F6 46 39 3D 5C 4A 01 10 6A 02 5F 74 09 6A 1F E8 07 03 00 00 EB 35 68 8C } 
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.6853286642591 Found in 3 files
		$x4 = { 67 59 6F 70 0C 61 7C 70 59 5E 65 66 7F 02 6F 61 7C 42 78 61 70 05 7B 61 56 41 78 61 60 05 7B 5C 05 05 78 07 78 04 79 62 70 04 6F 58 60 41 78 71 74 01 6F 72 63 59 6F 61 7B 5E 78 07 6C 42 53 66 } //This might be a string? Looks like:gYopa|pY^efoa|Bxap{aVAxa`{\xxybpoX`AxqtorcYoa{^xlBSf
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 4.725798827786958 Found in 4 files
		$x5 = { 74 74 52 74 74 74 74 74 01 53 40 52 01 74 41 74 5B 7B 7C 57 52 77 61 78 05 5D 63 72 5D 45 56 4C 77 42 56 58 0C 5B 56 58 73 41 7C 72 7B 5D 57 58 00 43 51 76 77 5C 6F 66 77 4C 51 62 01 52 54 62 } //This might be a string? Looks like:ttRtttttS@RtAt[{|WRwax]cr]EVLwBVX[VXsA|r{]WXCQvw\ofwLQbRTb
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.206954882778696 Found in 7 files
		$x19 = { 74 6C 62 7F 5F 6F 72 63 58 6F 07 5D 45 54 58 41 46 57 62 00 43 56 7D 73 4C 56 06 67 04 51 5B 51 01 50 6D 5A 74 74 74 74 74 74 74 77 77 64 5E 7B 70 67 60 6F 7D 66 70 59 7E 66 05 4D 7B 61 5E 0C } //This might be a string? Looks like:tlb_orcXo]ETXAFWbCV}sLVgQ[QPmZtttttttwwd^{pg`o}fpY~fM{a^
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.001745674421893 Found in 6 files
		$x21 = "^tttvPttttqdttt~pttttvttttEtttttFtttv[ttttqdtttyVttttgttttORtttt" ascii
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 2.6193841405826883 Found in 5 files
		$x25 = { 77 41 74 64 74 74 1A 1A 1A 1A 1A 4D 01 74 74 74 74 03 74 74 74 74 62 64 74 74 74 7D 56 74 74 74 76 62 74 74 74 74 41 74 74 74 74 7B 78 74 74 74 71 4C 74 74 74 74 70 74 70 74 74 76 0D 77 74 74 } //This might be a string? Looks like:wAtdttMttttttttbdttt}VtttvbttttAtttt{xtttqLttttptpttv\rwtt
		//Benign FP est: -0.0 Malicious FP est: -0.0 Entropy: 5.277114648336088 Found in 6 files
		$x26 = { 77 05 50 7D 4C 74 5D 7C 5C 78 5E 7F 66 6C 5B 7E 76 5E 44 7E 4C 42 41 79 5C 0D 42 78 61 7C 4F 7B 71 60 07 7B 4F 52 00 7A 5F 46 0D 65 61 01 1A 64 70 73 76 64 05 67 73 67 5E 51 7C 66 60 45 79 61 } //This might be a string? Looks like:wP}Lt]|\x^fl[~v^D~LBAy\\rBxa|O{q`{ORz_F\readpsvdgsg^Q|f`Eya

		condition:
(5 of ($x0,$x1,$x2,$x3,$x4,$x5) ) or (11 of ($x6,$x7,$x8,$x9,$x10,$x11,$x12,$x13,$x14,$x3,$x15,$x16,$x17,$x18,$x19,$x20,$x21,$x22,$x23,$x24,$x25,$x26,$x27) )}