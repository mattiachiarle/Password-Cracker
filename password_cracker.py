import hashlib
import time


# This function compares all the possible hashes of encoding with the hash of the current password to crack
def check_hash(encoding, hash_to_check):
    if (hashlib.md5(encoding).hexdigest() == hash_to_check or
            hashlib.sha1(encoding).hexdigest() == hash_to_check or
            hashlib.sha224(encoding).hexdigest() == hash_to_check or
            hashlib.sha256(encoding).hexdigest() == hash_to_check or
            hashlib.sha384(encoding).hexdigest() == hash_to_check or
            hashlib.sha512(encoding).hexdigest() == hash_to_check or
            hashlib.sha3_224(encoding).hexdigest() == hash_to_check or
            hashlib.sha3_256(encoding).hexdigest() == hash_to_check or
            hashlib.sha3_384(encoding).hexdigest() == hash_to_check or
            hashlib.sha3_512(encoding).hexdigest() == hash_to_check or
            hashlib.blake2b(encoding).hexdigest() == hash_to_check or
            hashlib.blake2s(encoding).hexdigest() == hash_to_check):
        return 1
    else:
        return 0


# This function cracks the password by using the Caesar Cipher
def caesar_check(hash):
    for word in dictionary:
        for index_let in range(26):  # Outer loop: analyze all the letter shifts
            tmp_word = list(word)  # Not to overwrite the word. In this way we can use it in the following iterations. We create a list so that we can replace single characters (strings are immutable)
            for letter in range(len(tmp_word)):  # We iterate on all the characters of the word
                if 65 <= ord(tmp_word[letter]) <= 122:  # Check to understand if the character is a letter
                    new_ascii = ord(tmp_word[letter]) + index_let
                    if new_ascii >= 91 and 65 <= ord(tmp_word[letter]) <= 91:  # otherwise we risk overlaps with lowercase letters
                        new_ascii = new_ascii - 91 + 65
                    if new_ascii > 122:  # We need to compute the offset with respect to 'a' since we went out of bounds
                        new_ascii = new_ascii - 123 + 97
                    tmp_word[letter] = chr(new_ascii)  # We replace the character with the updated letter

            # Since letters and numbers have distinct values of the offset, for each proposed letter offset we test
            # all the available number offsets

            for index_num in range(10):  # inner loop: analyze all the number shifts
                current_tmp_word = tmp_word[:]  # Again we make a copy of tmp_word to reuse it in the following iterations
                for number in range(len(current_tmp_word)):
                    if 48 <= ord(current_tmp_word[number]) <= 57:  # The character is a number
                        new_ascii = ord(current_tmp_word[number]) + index_num
                        if new_ascii > 57:  # Again to achieve a circular buffer
                            new_ascii = new_ascii - 58 + 48
                        current_tmp_word[number] = chr(new_ascii)
                current_tmp_word = "".join(current_tmp_word)  # We obtain a string
                if check_hash(current_tmp_word.encode(),hash):  # We check the hash
                    print("Recognized password for user3 in {} seconds: ".format(time.time()-start) + current_tmp_word)
                    return


# Recursive function to generate all the possible combinations of leet speak
def leet(word,index):
    if index == len(word):  # End of recursion. We check if we found a match and we return the result
        return check_hash("".join(word).encode(), hash)

    match word[index]:  # For each replaceable letter we run two tests: one where we don't perform the replacement and one where we do it
        case 'a':
            if leet(word, index + 1):
                return 1
            word[index] = '4'  # The previous attempt failed, so we replace and we call the recursion
            if leet(word, index + 1):
                return 1
            word[index] = 'a'  # This attempt was unsuccessful. We restore the original situation and we return the failure.
            return 0
        case 'b':
            if leet(word, index + 1):
                return 1
            word[index] = '8'
            if leet(word, index + 1):
                return 1
            word[index] = 'b'
            return 0
        case 'e':
            if leet(word, index + 1):
                return 1
            word[index] = '3'
            if leet(word, index + 1):
                return 1
            word[index] = 'e'
            return 0
        case 'g':
            if leet(word, index + 1):
                return 1
            word[index] = '9'
            if leet(word, index + 1):
                return 1
            word[index] = 'g'
            return 0
        case 'i':
            if leet(word, index + 1):
                return 1
            word[index] = '1'
            if leet(word, index + 1):
                return 1
            word[index] = 'i'
            return 0
        case 'o':
            if leet(word, index + 1):
                return 1
            word[index] = '0'
            if leet(word, index + 1):
                return 1
            word[index] = 'o'
            return 0
        case 'r':
            if leet(word, index + 1):
                return 1
            word[index] = '2'
            if leet(word, index + 1):
                return 1
            word[index] = 'r'
            return 0
        case 's':
            if leet(word, index + 1):
                return 1
            word[index] = '5'
            if leet(word, index + 1):
                return 1
            word[index] = 's'
            return 0
        case 't':
            if leet(word, index + 1):
                return 1
            word[index] = '7'
            if leet(word, index + 1):
                return 1
            word[index] = 't'
            return 0
        case _:  # default case: simply proceed with the next character
            return leet(word, index + 1)


tmp_dct = open("dictionary.txt", "r")
dictionary = []
pws = open("shadow", "r")

for word in tmp_dct:
    dictionary.append(word.strip())  # In this way we read just once the file, saving time.

for i in range(6):  # This program will analyze just the first six users
    start = time.time()
    found = 0
    password = ""
    hash = pws.readline().rsplit(":")[1].strip()  # In the following command we read a line from the file, we extract only the hash by splitting and we remove \n by using strip.
                                                  # The value of hash is the hash in the file

    if i == 2:  # We know what the third user uses the Caesar cipher. Since this check is an overhead,
                # we perform it only for him
        caesar_check(hash)
        continue  # We can only succeed with caesar cipher, so after we return we analyze the following user

    # STEP 1: just try to compute the hash of the words in the dictionary and see if we match

    for word in dictionary:
        if check_hash(word.encode(), hash):
            password = word
            found = 1
            break

    if found:
        print("Recognized password for user{} ".format(i + 1) + "in {} seconds: ".format(time.time()-start) + password)
        continue

    # STEP 2: try with leet speak

    for word in dictionary:
        word = list(word)
        if leet(word, 0):  # We call leet with index=0
            password = "".join(word)
            found = 1
            break

    if found:
        print("Recognized password for user{} ".format(i + 1) + "in {} seconds: ".format(time.time()-start) + password)
        continue

    # STEP 3: try with salt

    for word in dictionary:
        for x in range(100000):  # To generate numbers from 0 to 99999
            salt_word = word + "{:05d}".format(x)  # We use this format so that all numbers will have 5 digits. For example, 0 will be 00000
            if check_hash(salt_word.encode(), hash):
                password = salt_word
                found = 1
                break
        if found:  # We need to break twice since we have 2 nested iterations
            break

    if found:
        print("Recognized password for user{} ".format(i + 1) + "in {} seconds: ".format(time.time()-start) + password)
