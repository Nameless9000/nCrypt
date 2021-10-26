# nCrypt
nCrypt is a Greyhack hashing helper module for people who don't know much about password security or people who don't want to write one lol

![Image of nCrypt](https://media.discordapp.net/attachments/415878440001208320/902348381354086400/unknown.png)

## How to use:
```lua
import_code("LIBRARY_PATH.src")

nCrypt = new nCryptLibrary

nCrypt.secret = "" //-- leave blank if you want it random (you can't check a hash if it has a different secret)
//-- print(nCrypt.getSecret())  //-- prints the secret or a random secret for you to set

//-- (optional, the default is R1 https://github.com/Finko42/GreyHack/blob/main/Hash%20Functions/R1.src)
nCrypt.HashMethod = function(inp)
    return self.R1(inp) //-- if you want md5 replace "self.R1(" with "md5("
end function

//-- Create a hash
input = user_input("Enter string: ")
hashedString = nCrypt.CreateHash(input)

//-- Print the hash for testing
print("\nHash: <color=red>"+hashedString+"</color>\n")

//-- Check the hash
input = user_input("Enter string: ")
flag = nCrypt.CheckHash(input, hashedString)
if flag then
  print("String is the same.")
else
  print("String is not the same.")
end if

//-- NOTE: You can look at the code if you want to make it more secure.
```

# Credits:
Note: Most the stuff is modified but I decided to add credits anyway

```
R1: https://github.com/Finko42
Base64 Encode: Layth#2146 (198861674424303616)
Hex to Decimal: Erekel#0001 (155429886251630592)
```
