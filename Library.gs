nCryptLibrary = {}

nCryptLibrary.version = "2a"

band=function(x,y)
    return bitwise("&",x,y) 
end function
bshl=function(x,y)
    return bitwise("<<",x,y)
end function
bushr=function(x,y)
    return bitwise(">>>",x,y)
end function

alph = "!#%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'"
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

nCryptLibrary.R1 = function(input) // Returns 240-bit hash
	
	// Blockify input
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
	
	// Padding
	while Blocks[-1].len != 9
		Blocks[-1] = Blocks[-1] + [0]
	end while
	// Add msg length at end
	Blocks[-1] = Blocks[-1] + [input.len]
	
	
	// 48-bit fractional parts of the square roots of the first 10 prime numbers
	H = [116590752822204, 206053984011466, 66447228468884, 181762835242781, 89121955491302, 170447531158334, 34651153103681, 224006659490053]
	H = H + [108414255117948, 159811460804720]
	// A constant for mixing
	C = (sqrt(5)-1)/2
	
	// Define functions
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
	
	// Convert hash to hex
	hexTable = "0123456789abcdef"
	hash = ""
	for num in binHash
		for i in range(11)
			hash = hash + hexTable[floor(num/16^i)%16]
		end for
	end for
	return hash
end function

nCryptLibrary.secret = ""

nCryptLibrary.getSecret = function()
    if self.secret.trim == "" then self.secret = nCryptLibrary.GenerateRandomString(32)

    return self.secret
end function

nCryptLibrary.HashMethod = function(inp)
    return self.R1(inp)
end function

nCryptLibrary.GenerateRandomString = function(length)
    output = ""

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
    enc = b64encode(lst)
    return enc
end function

nCryptLibrary.Encode = function(inputString)
    lst=[]
    for c in inputString    
        lst.push(c.code)
    end for
    enc = b64encode(lst)
    return enc
end function

nCryptLibrary.HMac = function(inputString)
    newString = self.getSecret()+"$"+inputString
    hashedString = self.HashMethod(newString)
    return self.HexEncode(hashedString)
end function

nCryptLibrary.GenerateSalt = function()
    randomStr = md5(self.GenerateRandomString(24))
    return self.HexEncode(randomStr)
end function

nCryptLibrary.CreateHash = function(inputString)
    salt = self.GenerateSalt()

    saltedString = self.Encode(salt+inputString)
    hashedString = self.HMac(saltedString)

    output = ("$"+self.version+"$"+salt+hashedString).replace("\n","n")

    return output
end function

nCryptLibrary.CheckHash = function(inputString, inputHash)
    strings = inputHash.split("\$")
    strings.pull

    version = strings[0]
    mainString = strings[1]

    salt = mainString[:24]

    saltedString = self.Encode(salt+inputString)
    hashedString = self.HMac(saltedString)

    output = ("$"+self.version+"$"+salt+hashedString).replace("\n","n")

    return output == inputHash
end function

return nCryptLibrary
