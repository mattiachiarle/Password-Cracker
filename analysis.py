import hashlib
import time


# Same function used in password_cracker
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


# This function will be used to encode the password by using the retrieved mappings
def encode(word):
    tmp = list(word)  # Again we need to use a list to replace individual characters
    for i in range(len(tmp)):
        if tmp[i] in decode_dict:  # If the character currently has a mapping, we replace it
            tmp[i] = decode_dict[tmp[i]]
    tmp = "".join(tmp)  # We get a string

    return tmp


text_file = open("encrypted.txt", "r")
sentence = text_file.readline()  # We read the encrypted sentence

mapping = {}  # Dictionary to store the mappings
frequency = {}  # Dictionary to compute the frequency of the words

# The only english words of one letter are a and i. Based on the text and on trials, we can easily retrieve the following mappings
mapping['m'] = 'i'
mapping['s'] = 'a'

# We perform a frequency analysis that will help the user while decoding
# Furthermore, since we know that the most used english letter is e, we can enforce another statical mapping
sentence_letters = list(sentence)

for let in sentence_letters:
    if 97 <= ord(let) <= 122:
        if let in frequency:
            frequency[let] = frequency[let] + 1
        else:
            frequency[let] = 1  # If it isn't in the dictionary, we insert it

most_freq = max(frequency, key=frequency.get)  # We compute the maximum value of frequency and we retrieve the related letter
mapping[most_freq] = 'e'

print("Frequency computation:\n")
for elem in frequency:
    print(elem + ": {}".format(frequency[elem]))

done = 0


# This function allows us to print the encrypted text with all the letters already mapped replaced.
# In this way, the user can see the intermediate status of the text and understand more easily the other mappings
def print_updated_sentence():
    test = list(sentence)

    for i in range(len(test)):
        if 97 <= ord(test[i]) <= 122 and test[i] in mapping:  # We replace only the letters that have been already mapped
            test[i] = mapping[test[i]]

    test = "".join(test)

    print(test)


while not done:
    print_updated_sentence()  # At the beginning of each iteration, we print the sentence with the current mappings
    res = input("Is the sentence correct? 0=no, 1=yes: ")  # We ask the user if the sentence is correct
    if res == '1':
        done = 1  # We found the mapping, so we can crack the password
        continue
    map = input("Do you want to insert mappings? letter=letter for yes, 0 for no: ")  # We ask the user if he found some mappings that he wants to try
    while map != '0':
        letters = map.rsplit("=")
        mapping[letters[0]] = letters[1]
        map = input("Do you want to insert mappings? letter=letter for yes, 0 for no: ")

# Here the mapping is complete. Now, we can exploit it to bruteforce the password of user 7

dictionary = open("dictionary.txt", "r")
pws = open("shadow", "r")

for i in range(6):
    pws.readline()  # We ignore the first six hashes

start = time.time()

hash = pws.readline().rsplit(":")[1].strip()  # Same as in the task 1

# Now we invert the dictionary to perform the encoding
# In fact, currently the dictionary is encoded -> decoded, while here we want to do decoded->encoded
# Furthermore, we replicate the same mapping for uppercase letters too

decode_dict = {}

for key in mapping:
    decode_dict[mapping[key]] = key  # To invert the dictionary
    decode_dict[mapping[key].upper()] = key.upper()  # We do the same operation with uppercase letters

for word in dictionary:
    encoded_word = encode(word.strip())  # We get the encoded word
    if check_hash(encoded_word.encode(), hash):
        print("Recognized password for user7 in {} seconds: ".format(time.time()-start) + encoded_word)
        break
