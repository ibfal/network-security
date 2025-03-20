#!/usr/bin/env python

## Name: Bella Falbo
## Resources:
#I used the Geeksforgeeks pages for info on the functions listed in the hints 
#(so encode (i also looked at decode(), bytes(), .hex(), also the XOR info again 
#to make sure i had it right, and chr()). 
##https://www.geeksforgeeks.org/python-strings-encode-method/?ref=gcse
#https://www.geeksforgeeks.org/python-bytes-method/?ref=header_search
#https://www.geeksforgeeks.org/python-hex-function/?ref=header_search
#https://www.geeksforgeeks.org/get-the-logical-xor-of-two-variables-in-python/
#https://www.geeksforgeeks.org/chr-in-python/?ref=header_search
#https://www.geeksforgeeks.org/zip-in-python/?ref=header_search
#I am curious if decode() does the reverse of encode()
# and if we need to use that since were technically "undoing" what we did in the encryption.
#https://www.geeksforgeeks.org/python-strings-decode-method/?ref=header_search


import os

class OTP:
    def encrypt(self, key: bytes, msg: str):
        ascii = msg.encode('ascii') #this converts to sequence of ASCII bytes
        xorset = [a^k for a,k, in zip(ascii,key)] #we zip each element of the msg into a pair with the 
        #corresponding element of the key, then XOR it in the list comp. it is stored as the xor set.
        convert= bytes(xorset) #converts to bytes
        hexstr= convert.hex() #converts to hex
        return hexstr 

    def decrypt(self, key: bytes, ciphertext: hex):
        backtobyte = bytes.fromhex(ciphertext) #converts from hex to bytes 
        unxorset = [a^k for a,k, in zip(key, backtobyte)] #zip key element with msg, XOR again in list comp.
        str = [chr(i) for i in unxorset] #i put this back into a string bc it was showing arrays of characters. 
        return(''.join(str)) # or return(str)


    def key_generator(self, length: int):
        genkey = os.urandom(length) #generates a random key of specific length.
        return genkey


def main():
    otp = OTP()

    # generate random key
    print("keys:")
    print("-" * 5)
    keys = [otp.key_generator(len(msg)) for msg in messages]
    [print(key) for key in keys]
    print('-' * 80)

    # encrypt:
    print("ciphertexts:")
    print("-" * 11)
    ciphertexts = [otp.encrypt(key, msg) for key, msg in zip(keys, messages)]
    [print(ctext) for ctext in ciphertexts]
    print('-' * 80)

    # decrypt
    print("plaintexts:")
    print("-" * 10)
    plaintexts = [otp.decrypt(key, c) for key, c in zip(keys, ciphertexts)]
    [print(ptext) for ptext in plaintexts]
    print('-' * 80)


if __name__ == "__main__":
    messages = ["I taste a liquor never brewed",
                "From Tankards scooped in Pearl",
                "Not all the Frankfort Berries",
                "Yield such an Alcohol!",
                "Inebriate of air am I",
                "And Debauchee of Dew",
                "Reeling thro endless summer days",
                "From inns of molten Blue",
                "When 'Landlords' turn the drunken Bee",
                "Out of the Foxglove's door",
                "When Butterflies renounce their 'drams'",
                "I shall but drink the more!",
                "Till Seraphs swing their snowy Hats",
                "And Saints to windows run",
                "To see the little Tippler",
                "Leaning against the Sun!"]

    main()
