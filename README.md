# nCrypt
Version: 2c1

nCrypt is a Greyhack hashing helper module for people who don't know much about password security or people who don't want to write one lol

![Image of nCrypt](https://i.ibb.co/zJsz3Sv/image.png)

## How to use:
```lua
import_code("LIBRARY_PATH.src")

nCrypt = new nCryptLibrary

nCrypt.iterations = 5 //-- how many iterations you want more iterations = takes longer to crack
nCrypt.secret = "" //-- leave blank if you want it random (you can't check a hash if it has a different secret)
//-- print(nCrypt.getSecret())  //-- prints the secret or a random secret for you to set

//-- (optional, the default is SHA2-256 https://github.com/Finko42/GreyHack/blob/main/Hash%20Functions/sha256.src)
nCrypt.HashMethod = function(inp)
    return self.SHA256(inp) // if you want md5 replace "self.SHA256(" with "md5("
end function

//-- Create a hash
input = user_input("Enter string: ")
hashedString = nCrypt.Hash(input)

//-- Print the hash for testing
print("\nHash: <color=red>"+hashedString+"</color>\n")

//-- Check the hash
input = user_input("Enter string: ")
flag = nCrypt.Compare(input, hashedString)
if flag then
  print("String is the same.")
else
  print("String is not the same.")
end if

//-- NOTE: You can look at the code if you want to make it more secure.
```

## For Servers
1. Edit the line that says ' pass = "RootPassword" ' and replace RootPassword with your root password
2. Compile the code as /server/conf/decode.bin
3. Remove the 'Decode' function and save the code as /server/conf/encode.src
4. Test if everything works

```lua
//-- PASTE THE CODE FROM 'Library.gs' ABOVE THE CODE BELOW

nCrypt = new nCryptLibrary

nCrypt.iterations = 5
nCrypt.secret = "RANDOM STRING" //-- set this to a random string (MUST BE THE SAME ON encode.src AND decode.bin)

Encode = function(password)
    password = password.replace("\n","")
    password = password.replace(char(10),"")
    password = password.trim

    password = nCrypt.Hash(password)

    password = password.replace("\n","")
    password = password.replace(char(10),"")
    password = password.trim

    return password
end function

Decode = function(input) //-- remove this section for encode.src or they will know ur pass
    pass = "RootPassword" //-- set this to your root password
    if nCrypt.Compare(pass,input) then return pass
    return "no"
end function
```

# Credits:
```
SHA2-256: https://github.com/Finko42
R1: https://github.com/Finko42
Base64 Encode: Layth#2146 (198861674424303616)
Hex to Decimal: Erekel#0001 (155429886251630592)
```
