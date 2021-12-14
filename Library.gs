nCryptLibrary = {}

nCryptLibrary.version = "2c1"

band=function(x,y)
    return bitwise("&",x,y) 
end function
bshl=function(x,y)
    return bitwise("<<",x,y)
end function
bushr=function(x,y)
    return bitwise(">>>",x,y)
end function

Ox3f = 63
Oxff = 255

hToD2 = function(num)
    hex = {"0":0, "1":1, "2":2, "3":3, "4":4, "5":5, "6":6, "7":7, "8":8, "9":9, "a":10, "b":11, "c":12, "d":13, "e":14, "f":15}
    result = 0
    pow = 0

    stack = []
    for ch in num
        stack.push(hex[ch])
    end for

    stack.reverse()

    nums = []
    for i in stack
        nums.push(i * (16 ^ pow))
        pow = pow + 1
    end for

    for n in nums
        result = result + n
    end for

    return result
end function

b64encode=function(inp)
    alph = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    i=0
    b64e=""
    p=""
    c=inp.len%3
    if c>0 then
        for _ in range(1,c-1)
            inp.push(0)
        end for
    end if
    while i<inp.len-1
        n=bshl(inp[i],16)+bshl(inp[i+1],8)+inp[i+2]
        n=[band(bushr(n,18),Ox3f),band(bushr(n,12),Ox3f),band(bushr(n,6),Ox3f),band(n,Ox3f)]
        b64e=b64e+alph[n[0]]+alph[n[1]]+alph[n[2]]+alph[n[3]]
        i=i+3
    end while
    return (b64e[:b64e.len-p.len]+p).replace("\n","n")
end function

b64decode=function(inp)
    alph = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    b64d=[]
    p=""
    for i in range(inp.len-2,inp.len-1)
        if inp[i]=="=" then p=p+"A"
    end for
    inp=inp[:inp.len-p.len]+p
    i=0
    while i<inp.len
        n=bshl(alph.indexOf(inp[i]),18)+bshl(alph.indexOf(inp[i+1]),12)+bshl(alph.indexOf(inp[i+2]),6)+alph.indexOf(inp[i+3])
        b64d=b64d+[band(bushr(n,16),Oxff),band(bushr(n,8),Oxff),band(n,Oxff)]
        i=i+4
    end while    
    return b64d[:b64d.len-p.len]
end function

bencode=function(inp)
    alph = "!#%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'"
    i=0
    b64e=""
    p=""
    c=inp.len%3
    if c>0 then
        for _ in range(1,c-1)
            inp.push(0)
        end for
    end if
    while i<inp.len-1
        n=bshl(inp[i],16)+bshl(inp[i+1],8)+inp[i+2]
        n=[band(bushr(n,18),Ox3f),band(bushr(n,12),Ox3f),band(bushr(n,6),Ox3f),band(n,Ox3f)]
        b64e=b64e+alph[n[0]]+alph[n[1]]+alph[n[2]]+alph[n[3]]
        i=i+3
    end while
    return (b64e[:b64e.len-p.len]+p).replace("\n","n")
end function

R1_MD5 = function(input)
	Blocks = [[]]
	i=0
	while i < input.len
		Blocks[-1] = Blocks[-1] + [0]
		e=6
		while e > 0 and input.hasIndex(i)
			e=e-1
			Blocks[-1][-1] = Blocks[-1][-1] + code(input[i])*256^e
			i=i+1
		end while
		if Blocks[-1].len == 10 then Blocks = Blocks + [[]]
	end while
	while Blocks[-1].len != 9
		Blocks[-1] = Blocks[-1] + [0]
	end while
	Blocks[-1] = Blocks[-1] + [input.len]
	H = [116590752822204, 206053984011466, 66447228468884, 181762835242781, 89121955491302, 170447531158334, 34651153103681, 224006659490053]
	H = H + [108414255117948, 159811460804720]
	C = (sqrt(5)-1)/2
	XOR = function(a, b)
		return bitwise("^", floor(a/16777216), floor(b/16777216))*16777216+bitwise("^", a%16777216, b%16777216)
	end function
	
	ROTR = function(num, rots)
		rots = 2^rots
		return (num % rots) * (281474976710656/rots) + floor(num/rots)
	end function
	
	MIX = function(k)
		return floor(281474976710656*((k*C)%1))
	end function
	
	
	// Message schedule
	for Block in Blocks
		W = range(109)
		for i in H.indexes
			W[i] = XOR(Block[i], H[i])
		end for
		
		for i in range(10, 109)
			W[i] = ( XOR(W[i-10], ROTR(W[i-8], 23)) + MIX(W[i-1]) ) % 281474976710656
		end for
		
		for i in H.indexes
			H[i] = W[109-i]
		end for
	end for
	
	// Compress H
	binHash = []
	for i in range(0,4)
		binHash = binHash + [XOR(H[i], H[9-i])]
	end for
	hexTable = "0123456789abcdef"
	hash = ""
	for num in binHash
		for i in range(11)
			hash = hash + hexTable[floor(num/16^i)%16]
		end for
	end for
	return hash[:32]
end function

nCryptLibrary.SHA256 = function(input)
	
	Blocks = [[0]]
	i=0
	e=0
	while i < input.len
		e=4
		while e > 0 and input.hasIndex(i)
			e=e-1
			Blocks[-1][-1] = Blocks[-1][-1] + code(input[i])*256^e
			i=i+1
		end while
		if e == 0 then
			if Blocks[-1].len == 16 then Blocks = Blocks + [[0]] else Blocks[-1] = Blocks[-1] + [0]
		end if
	end while
	
	if e > 0 then
		Blocks[-1][-1] = Blocks[-1][-1] + (2147483648/256^(4-e))
	else
		Blocks[-1][-1] = 2147483648
	end if
	
	if Blocks[-1].len == 16 then Blocks = Blocks + [[0]]
	while Blocks[-1].len != 15
		Blocks[-1] = Blocks[-1] + [0]
	end while
	
	Blocks[-1] = Blocks[-1] + [input.len*8]
	
	add = function(a, b)
		return (a + b) % 4294967296
	end function
	
	XOR = function(a, b)
		return bitwise("^", floor(a/65536), floor(b/65536))*65536+bitwise("^", a%65536, b%65536)
	end function
	
	AND = function(a, b)
		return bitwise("&", floor(a/65536), floor(b/65536))*65536+bitwise("&", a%65536, b%65536)
	end function
	
	OR = function(a, b)
		return bitwise("|", floor(a/65536), floor(b/65536))*65536+bitwise("|", a%65536, b%65536)
	end function
	
	NOT = function(n)
		return 4294967295-n
	end function
	
	Ch = function(x, y, z)
		return OR(AND(x, y), AND(NOT(x), z))
	end function
	
	Maj = function(x, y, z)
		return OR(OR(AND(x, y), AND(x, z)), AND(y, z))
	end function
	
	shr = function(n, shifts)
		return floor(n/2^shifts)
	end function
	
	rotr = function(n, rots)
		rots = 2^rots
		return (n % rots) * (4294967296/rots) + floor(n/rots)
	end function
	
	sigma0 = function(n)
		return XOR(XOR(rotr(n, 7), rotr(n, 18)), shr(n, 3))
	end function
	
	sigma1 = function(n)
		return XOR(XOR(rotr(n, 17), rotr(n, 19)), shr(n, 10))
	end function
	
	SIGMA0 = function(n)
		return XOR(XOR(rotr(n, 2), rotr(n, 13)), rotr(n, 22))
	end function
	
	SIGMA1 = function(n)
		return XOR(XOR(rotr(n, 6), rotr(n, 11)), rotr(n, 25))
	end function
	
	K = []
	K = K + [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221]
	K = K + [3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580]
	K = K + [3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986]
	K = K + [2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895]
	K = K + [666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037]
	K = K + [2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344]
	K = K + [430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779]
	K = K + [1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298]
	
	H = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]
	
	for Block in Blocks
		W = Block[0:]
		
		for i in range(16, 63)
			W = W + [add(add(add(sigma1(W[i-2]), W[i-7]), sigma0(W[i-15])), W[i-16])]
		end for
		
		a = H[0]
		b = H[1]
		c = H[2]
		d = H[3]
		e = H[4]
		f = H[5]
		g = H[6]
		h = H[7]
		
		for i in range(0, 63)
			T1 = add(add(add(add(SIGMA1(e), Ch(e, f, g)), h), K[i]), W[i])
			T2 = add(SIGMA0(a), Maj(a, b, c))
			h = g
			g = f
			f = e
			e = add(d, T1)
			d = c
			c = b
			b = a
			a = add(T1, T2)
		end for
		H[0] = add(a, H[0])
		H[1] = add(b, H[1])
		H[2] = add(c, H[2])
		H[3] = add(d, H[3])
		H[4] = add(e, H[4])
		H[5] = add(f, H[5])
		H[6] = add(g, H[6])
		H[7] = add(h, H[7])
	end for
	
	hexTable = "0123456789abcdef"
	hash = ""
	for i in H.indexes
		for j in range(7)
			hash = hash + hexTable[floor(H[i]/16^j) % 16]
		end for
	end for
	return hash
end function


nCryptLibrary.secret = ""
nCryptLibrary.iterations = 0

nCryptLibrary.getSecret = function()
    if self.secret.trim == "" then self.secret = self.GenerateRandomString(32)

    return self.secret
end function

nCryptLibrary.HashMethod = function(inp)
    return self.SHA256(inp)
end function

nCryptLibrary.GenerateRandomString = function(length)
    output = ""
    alph = "!#%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'"
    for i in range(1, length)
        c = round((rnd * alph.len))-1
        output = output + alph[c]
    end for

    return output
end function

nCryptLibrary.HexEncode = function(inputString)
    lst=[]
    for i in range(1,inputString.len,2)        
        lst.push(hToD2(inputString[i-1]+inputString[i]))
    end for
    enc = bencode(lst)
    return enc
end function

nCryptLibrary.Encode = function(inputString)
    lst=[]
    for c in inputString    
        lst.push(c.code)
    end for
    enc = bencode(lst)
    return enc
end function

nCryptLibrary.HMac = function(inputString)
    newString = self.getSecret()+"$"+inputString
    hashedString = self.HashMethod(newString)
    return self.HexEncode(hashedString)
end function

nCryptLibrary.GenerateSalt = function()
    randomStr = R1_MD5(self.GenerateRandomString(24))
    return self.HexEncode(randomStr)
end function

nCryptLibrary.CreateHash = function(inputString, iterations = null, salt = null)
    if iterations == null then iterations = self.iterations
    if salt == null then salt = self.GenerateSalt()

    saltedString = self.Encode(salt+inputString)
    hashedString = self.HMac(saltedString)

    saltHash = salt+hashedString

    lst=[]
    for c in saltHash    
        lst.push(c.code)
    end for

    saltHashEncode = b64encode(lst)

    output = ("$"+self.version+"$"+str(self.iterations)+"$"+saltHashEncode).replace("\n","n")

    return output
end function

nCryptLibrary.Hash = function(inputString, iterations = null, salt = null)
    if salt == null then salt = self.GenerateSalt()

    for i in range(1, 2^(self.iterations/2))
        inputString = self.CreateHash(inputString, i, salt)
    end for

    return inputString
end function

nCryptLibrary.Compare = function(inputString, inputHash)
    strings = inputHash.split("\$")
    strings.pull

    version = strings[0]
    if version != self.version then return exit("<color=red>Error: The hash is using version "+version+" and you are running nCrypt version "+self.version+"</color>")

    iterations = strings[1].to_int

    mainString = strings[2]

    dec = b64decode(mainString)
    mainString=""
    for i in dec
        mainString = mainString + char(i)
    end for

    salt = mainString[:24]

    for i in range(1, 2^(iterations/2))
        inputString = self.CreateHash(inputString, i, salt)
    end for

    return inputString == inputHash
end function

return nCryptLibrary
