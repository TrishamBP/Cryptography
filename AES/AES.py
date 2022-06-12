# Author-Trisham Bharat Patil
# License-Free

# Given a message with 128 bits, two subkeys subkey0 and subkey1, the program will be able to
# perform one AddKey before Round 1 and the corresponding operations (SubBytes, ShiftRows, Mix-
# Columns, and AddKey) in Round 1, and output the result of the encryption after Round 1.
# The subkey on the first line is subkey0 and the subkey on the second line is subkey1. Each has 128 bits.
# 5468617473206 d79204b756e67204675
# e232fcf191129188b159e4e6d679a293

# Importing modules
import math

# Reading the message from a text file
f = open('message.txt', 'r')
txt_msg = f.read()
f.close()

# Converting the message to binary.
msg_binary = ''.join(format(i, '08b') for i in bytearray(txt_msg, encoding='utf-8'))

# Defining our functions.
# Function to convert bits from message to a byte matrix.
def bytes2matrix(text):
    return [list(text[i:i + 8]) for i in range(0, len(text), 8)]

# Hexadecimal to binary conversion
def hex2bin(s):
    mp = {'0': "0000",
          '1': "0001",
          '2': "0010",
          '3': "0011",
          '4': "0100",
          '5': "0101",
          '6': "0110",
          '7': "0111",
          '8': "1000",
          '9': "1001",
          'a': "1010",
          'b': "1011",
          'c': "1100",
          'd': "1101",
          'e': "1110",
          'f': "1111"}
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin

# calculating xor of two strings of binary number a and b
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

# Binary to hexadecimal conversion
def bin2hex(s):
    mp = {"0000": '0',
          "0001": '1',
          "0010": '2',
          "0011": '3',
          "0100": '4',
          "0101": '5',
          "0110": '6',
          "0111": '7',
          "1000": '8',
          "1001": '9',
          "1010": 'a',
          "1011": 'b',
          "1100": 'c',
          "1101": 'd',
          "1110": 'e',
          "1111": 'f'}
    hex = ""
    for i in range(0, len(s), 4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]

    return hex

# Sub bytes/S box operation.
def subbyte(myhexstring):
    loop2 = 0
    temp = ""
    temp2 = ""
    part0 = ['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76']
    part1 = ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0']
    part2 = ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15']
    part3 = ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75']
    part4 = ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84']
    part5 = ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf']
    part6 = ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8']
    part7 = ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2']
    part8 = ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73']
    part9 = ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db']
    part10 = ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79']
    part11 = ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08']
    part12 = ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a']
    part13 = ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e']
    part14 = ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df']
    part15 = ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']

    lookuptable = [part0, part1, part2, part3, part4, part5, part6, part7, part8, part9, part10, part11, part12, part13,
                   part14, part15]


    for loop in range(0, math.ceil(len(myhexstring) / 2)):
        x = ""
        y = ""
        x = myhexstring[loop2]
        y = myhexstring[loop2 + 1]
        # convert character to integer
        if (x == '0'):
            x = 0
        elif (x == '1'):
            x = 1
        elif (x == '2'):
            x = 2
        elif (x == '3'):
            x = 3
        elif (x == '4'):
            x = 4
        elif (x == '5'):
            x = 5
        elif (x == '6'):
            x = 6
        elif (x == '7'):
            x = 7
        elif (x == '8'):
            x = 8
        elif (x == '9'):
            x = 9
        elif (x == 'a'):
            x = 10
        elif (x == 'b'):
            x = 11
        elif (x == 'c'):
            x = 12
        elif (x == 'd'):
            x = 13
        elif (x == 'e'):
            x = 14
        elif (x == 'f'):
            x = 15

        if (y == '0'):
            y = 0
        elif (y == '1'):
            y = 1
        elif (y == '2'):
            y = 2
        elif (y == '3'):
            y = 3
        elif (y == '4'):
            y = 4
        elif (y == '5'):
            y = 5
        elif (y == '6'):
            y = 6
        elif (y == '7'):
            y = 7
        elif (y == '8'):
            y = 8
        elif (y == '9'):
            y = 9
        elif (y == 'a'):
            y = 10
        elif (y == 'b'):
            y = 11
        elif (y == 'c'):
            y = 12
        elif (y == 'd'):
            y = 13
        elif (y == "e"):
            y = 14
        elif (y == "f"):
            y = 15
        temp = lookuptable[x][y]
        loop2 = loop2 + 2
        temp2 = temp2 + temp
    return temp2

# Shifting rows operation.
def shiftrow(temp2):

    if(len(temp2)==8):
        temp3=temp2[2]+temp2[3]+temp2[4]+temp2[5]+temp2[6]+temp2[7]+temp2[0]+temp2[1]
        return temp3
    else:
        temp3=temp2[0]+temp2[1]+temp2[10]+temp2[11]+temp2[20]+temp2[21]+temp2[30]+temp2[31]+temp2[8]+temp2[9]+temp2[18]+temp2[19]+temp2[28] + temp2[29] + temp2[6] + temp2[7] + temp2[16] + temp2[17] + temp2[26] + temp2[27] + temp2[4] + temp2[5] + temp2[14] + temp2[15] + temp2[24] + temp2[25] + temp2[2] + temp2[3] + temp2[12] + temp2[13] + temp2[22] + temp2[23]
        return temp3

########################################################################################################################
# AES operation : Converting plaintext block into byte matrix
# Step 1
# Converting the binary message to a byte matrix.
bytes2matrix(msg_binary)
########################################################################################################################
# Step 2
# Adding key operation.
# Representing subkey0 as a byte matrix.
subkey_zero = "5468617473206d79204b756e67204675"
subkey_zero_bin = hex2bin(subkey_zero)

# Converting subkey0 to byte matrix.
subkey_zero_byte_matrix = bytes2matrix(subkey_zero_bin)
add_key_bin = xor(msg_binary, subkey_zero_bin)

add_key_bin_hex = (bin2hex(add_key_bin))
hex_string = add_key_bin_hex
########################################################################################################################
# Step 3- Round 1 operation
# S box table
sbox_hexstring= subbyte(hex_string)

# Shifting rows operation.
shiftrow_hexstring=shiftrow(sbox_hexstring)
shiftrow_binary_string=hex2bin(shiftrow_hexstring)

# Adding Next Round Keys
subkey_one='e232fcf191129188b159e4e6d679a293'
subkey_one_bin=hex2bin(subkey_one)
encrypted_msg_binary=xor(shiftrow_binary_string,subkey_one_bin)
print(encrypted_msg_binary)
encrypted_msg_hex=bin2hex(encrypted_msg_binary)
print(encrypted_msg_hex)
