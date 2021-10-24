# nCrypt
nCrypt is a Greyhack hashing helper module for people who don't know much about password security or people who don't want to write one lol

## How to use:
```lua
import_code("LIBRARY_PATH.src")

nCrypt = new nCryptLibrary

secret = "H@McQfTjWnZr4u7x!A%D*G-JaNdRgUkX" //-- Keep this secure and do not share (https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx)

//-- (optional, the default is md5)
nCrypt.HashMethod = function(inp)
    return md5(inp)
end function

//-- Create a hash
input = user_input("Enter password:", 1)
hashedPassword = nCrypt.CreateHash(input, secret)

//-- Check the hash
input = user_input("Enter password:", 1)
flag = nCrypt.CheckHash(input, hashedPassword, secret)
if flag then
  print("Password is correct!")
else
  print("Password is incorrect!")
end if

//-- NOTE: You can look at the code if you want to make it more secure.
```
