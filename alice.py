from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from base64 import b64encode
import sys
import argparse
import random

# function that performs modular exponentiation
def modularExponentiate(x,e,N):
    """
     calculates the  x**e mod N     
     using successive squaring method
    """
    
    bits = turn_to_bits(e)

    power = 1
    for i in range(0,len(bits)):
        power = (power * power) % N
        
        if ("1" == bits[i]):
           power = (power * x) % N  
               
    return power       

# turns exponent into binary bit representation
def turn_to_bits(e):
    bits = ""
    
    while ((e / 2) != 0):
          bit = str((e % 2))
          bits =  bit + bits
          e = (e // 2)
          
    # at the end of the while loop we get the 
    # bit representation of number
    return bits


# Miller-Rabin primality test. It either returns True in 
# case of prime number or False in cas of composite number
def miller_rabin_test(n):
    ### Step-1
    b = n-1
    
    k = 1
    while (b % (2**k) == 0):
           k += 1            
    
    k -= 1
    q = b // (2**k)
    ### Step-2
    a = random.randint(1,n-2)
        
    if (1 == modularExponentiate(a,q,n)):
        return False
    
    ### Step-3
    for i in range(k):
         if ((n-1) == modularExponentiate(a,(2**i)*q,n)):
             return False
    
    # if we have reached the end of the loop without
    # any False return number is definitely composite
    return True
    
     
# function that checks for argument 
# match in dhke initialization                  
def check_arguments_initialization(arg):
    valid_args = ["-p","-g"]
    if (arg not in valid_args):
        print("Please provide p and g to initialize the key exchange")
        exit(0)  

# function that checks for argument 
# match in dhke finalization  
def check_arguments_finalization(arg):
    valid_args = ["-a","-B","-p"] 
    if (arg not in valid_args):
        print("Please provide a,B,and p to calculate the key")
        exit(0) 

# function that finds the 
# command line argument position
def find_arg_pos(arg):
    if (arg == sys.argv[2]):
        return 3
    
    elif (arg == sys.argv[4]):
        return 5
    
    else:
        return 7
    
# function that checks
# for plaintext and key     
def check_plaintext_and_key(arg):
    valid_args = ["-p","-k"]
    if (arg not in valid_args):
        print("Please provide a plaintext and key")   
        exit(0)
           
if (len(sys.argv) < 2):
    print("Please provide whole command line parameters after script name 'alice.py'")
    exit(0)


if (sys.argv[1] == "dhke"):
    if (len(sys.argv) == 6):
        parser = argparse.ArgumentParser(exit_on_error=False) 
        parser.add_argument("dhke")
        parser.add_argument("-p",type=check_arguments_initialization(sys.argv[2])) 
        parser.add_argument("-g",type=check_arguments_initialization(sys.argv[4]))
        parser.add_argument(sys.argv[3])
        parser.add_argument(sys.argv[5])
        
        if (sys.argv[2] == "-p"):
            p = int(sys.argv[3])
            g = int(sys.argv[5])
        
        else:
            p = int(sys.argv[5])    
            g = int(sys.argv[3])
            
        flag = 1
        for i in range(1200):
            if (miller_rabin_test(p)):
                flag = 0
                break
        
        if (flag):
            print("p = ",p,"OK (This is a prime number)")
        
        else:
            print("p = ",p,"NO (This is NOT a prime number)")     
            exit(0)
        
        generator_check_list = []
        for i in range(1,p):
            residue = modularExponentiate(g,i,p)
            generator_check_list.append(residue)
        
        for i in range(1,p):
            if (i not in generator_check_list):
                print("g = ",g,"NO (This is NOT a primitive root modulo",p)
                exit(0)
        
        print("g = ",g,"OK (This is a primitve root modulo",p)        
        print("Alice and Bob publicly agree on the values of p and g")
        print("However,it is advised to use any pair of p and g only once")    
        # alice randomly generates value 'a' (private key)
        # and calculates public key A
        a = random.randint(1,p-1)   
        A = modularExponentiate(g,a,p)
        
        print("a = ",a,"(This must be kept secret)")
        print("A = ",A,"(This can be sent to Bob)")        
                
     
    elif (len(sys.argv) == 8):
        parser = argparse.ArgumentParser(exit_on_error=False) 
        parser.add_argument("dhke")
        parser.add_argument("-a",type=check_arguments_finalization(sys.argv[2])) 
        parser.add_argument("-B",type=check_arguments_finalization(sys.argv[4]))
        parser.add_argument("-p",type=check_arguments_finalization(sys.argv[6])) 
        parser.add_argument(sys.argv[3])
        parser.add_argument(sys.argv[5])
        parser.add_argument(sys.argv[7])
        
        a = int(sys.argv[find_arg_pos("-a")])
        B = int(sys.argv[find_arg_pos("-B")])  
        p = int(sys.argv[find_arg_pos("-p")])      
        # alice calculates s (shared secret key)
        s = modularExponentiate(B,a,p) 
        print("s = ",s)
        print("This must be kept secret. However, Bob should be able to calculate this as well.")
  
    else:
        print("Invalid number of positional arguments are given")
              
     
elif (sys.argv[1] == "des"):
     if (len(sys.argv) == 6):
         parser = argparse.ArgumentParser(exit_on_error=False)
         parser.add_argument("des")
         parser.add_argument("-p",type=check_plaintext_and_key(sys.argv[2])) 
         parser.add_argument("-k",type=check_plaintext_and_key(sys.argv[4]))
         parser.add_argument(sys.argv[3])
         parser.add_argument(sys.argv[5])
         
         if (sys.argv[2] == "-p"):
             p = sys.argv[3]
             k = int(sys.argv[5])
         
         else:
             p = sys.argv[5]
             k = int(sys.argv[3])    
         
         
         p = p.encode("utf-8")
         # adding leading zeros
         # if key size doesn't match
         key = k.to_bytes(8,byteorder="big")    
 
         """"
         leading_zero_number = 0
         if (len(key) < 64):
             leading_zero_number = 64 - len(key)
         
         leading_zeros = "0"*leading_zero_number   
         """
         cipher = DES.new(key,DES.MODE_ECB)
         cipher_bytes = cipher.encrypt(pad(p,DES.block_size))
         cipher_text = b64encode(cipher_bytes).decode("utf-8") 
         print("Raw ciphertext: ")
         print(cipher_bytes)
         print("Readable ciphertext: ")
         print(cipher_text)
                     
   
     else:
         print("Invalid number of positional arguments are given")     
 
else:
    print("Invalid mode of operation,you should either give 'dhke' or 'des'")    