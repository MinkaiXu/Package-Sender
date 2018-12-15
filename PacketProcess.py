'''a packet process library'''

'''
int to hex can translate int numbers into hexstrings
type(num) is int, halfbytes shoule be the number of halfbytes(4bit) the result has
'''
def inttohex(num,halfbytes):
    tmp = hex(num)
    tmp = tmp[2:]
    length = len(tmp)
    return ((halfbytes-length) * "0" + tmp).upper()

#print inttohex(1,4)
#result should be "0001"

'''
addresstohex can translate ipaddress like "127.0.0.1" into hexforms(string) 
'''
def addresstohex(st):
    tmp = st.split(".")
    s = ''
    for i in tmp:
        s = s + inttohex(int(i),2)
    return s.upper()

#print addresstohex("192.168.1.102")
#result shoule be "C0A80166"

'''
hexinput can translate hexstring into real asc bytes
for example, '97' to '\x97'
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

#print hexinput("3b782190eeff00a0")
#result shoule translate '973b' as '\x97\x3b', etc

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
stupidDescodeMac can translate standard MAC inputs into bytes form
'''
def stupidDecodeMac(s):
    feedback = ''
    for i in range(len(s)):
        if (s[i].isalnum()):
            feedback += s[i]
    return feedback.upper()

#print stupidDecodeMac("bb:bc:aa:00:ff:04")
#result should be "BBBCAA00FF04"

'''
print hexinput("746869736973666F7269636D707465737")
print hexoutput("thisisforicmptest")
'''