import gmpy2,random

FLAG = open('./flag', 'rb').read()
FLAG = int.from_bytes(FLAG, byteorder='big')
p = random.randint(0, 2 ** 1024)
q = random.randint(0, 2 ** 512)

p = gmpy2.next_prime(p)
q = gmpy2.next_prime(p * 31)

e = 65537
d = pow(e, -1, (p - 1) * (q - 1))
N = p * q

print("N:", N)
print("e: 65537")
print("c:", pow(FLAG, e, N))