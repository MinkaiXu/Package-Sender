'''a packet process library'''

'''
this function can translate int numbers into hexstrings
number is int
'''
def inttohex(num,halfbytes):
    tmp = hex(num)
    tmp = tmp[2:]
    length = len(tmp)
    return ((halfbytes-length) * "0" + tmp).upper()



'''
this function can translate ip_address like "127.0.0.1" into hex(string) 
'''
def addresstohex(st):
    tmp = st.split(".")
    s = ''
    for i in tmp:
        s = s + inttohex(int(i),2)
    return s.upper()



'''
this function can translate hexstring into real asc bytes
for example, '96' to '\x96'
'''
def hexinput(data):
    length = len(data)
    outcome = ''
    if length % 2 != 0:
        return hexinput('0'+data)
    for i in range(length/2):
        s = data[2*i:2*i+2]
        outcome += chr(int(s,16))
    return outcome



'''
    hexouput() is the reverse of hexinput()
'''
def hexoutput(data):
    reserve = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    feedback = ''
    for i in range(len(data)):
        tmp = ord(data[i])
        feedback += reserve[tmp / 16]
        feedback += reserve[tmp % 16]
    return feedback

'''
Mac_decode can translate standard MAC inputs into bytes form
'''
def Mac_decode(s):
    feedback = ''
    for i in range(len(s)):
        if (s[i].isalnum()):
            feedback += s[i]
    return feedback.upper()


