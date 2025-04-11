# mist-ap41-challenge-resolver

This is a C implementation of the SHA256 HMAC based challange of the mist AP 41 , for more information and how to access the serial terminal check https://github.com/neggles/mist-ap41.

# compilation

dependences = libssl, libcrypto

make (debug)

# usage 

Usage: ./sha256_challenge [arguments]

Arguments:

  -F <eeprom_file> 24c64 eeprom dump from a mist AP-41
  
  -C <challenge_from_mist> base64 challenge, with or withouth an initial B character
  
  -K <16 bit key from a mist AP41> , format deadbeefdeadbeefdeadbeeefdeadbeef 
  
  -i show info
  
  -h Show this help message

  

-F or -K are mandatory arguments.
# example challenge and key
challenge = "BRHw1Yy01Yi0zNS0yZi00Zi1iNHxkZXZlbG9wZXJ8qrvM3e7/qqusra6vuru8vQ==" 

key = "396eff7c8d576d51fc2025420a2a97df"


