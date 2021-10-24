// Base 64 by Layth#2146
band=function(x,y)
    return bitwise("&",x,y) 
end function
bshl=function(x,y)
    return bitwise("<<",x,y)
end function
bushr=function(x,y)
    return bitwise(">>>",x,y)
end function

alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
Ox3f = 63
Oxff = 255

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
    return b64e[:b64e.len-p.len]+p
end function

// -- Main Library -- \\

nCrypt = {}

nCrypt.HashMethod = function(inp)
    return md5(inp)
end function

nCrypt.GenerateRandomString = function(length)
    output = ""

    for i in range(1, length)
        c = round((rnd * alph.len))-1
        output = output + alph[c]
    end for

    return output
end function

nCrypt.Encode = function(inputString)
    lst=[]
    for c in inputString
        lst.push(c.code)
    end for
    enc = b64encode(lst)
    return enc
end function

nCrypt.HMac = function(inputString, secret)
    newString = secret+"$"+inputString
    hashedString = self.HashMethod(newString)
    return self.Encode(hashedString)
end function

nCrypt.CreateHash = function(inputString, secret)
    salt = self.GenerateRandomString(15)

    saltedString = self.Encode(salt+inputString)
    hashedString = self.HMac(saltedString, secret)

    return "$"+salt+"$"+hashedString
end function

nCrypt.CheckHash = function(inputString, inputHash, secret)
    strings = inputHash.split("\$")
    strings.pull

    salt = strings[0]

    saltedString = self.Encode(salt+inputString)
    hashedString = self.HMac(saltedString, secret)

    output = "$"+salt+"$"+hashedString

    return output == inputHash
end function

return nCrypt
