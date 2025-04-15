#/bin/python3
import random,os
r = random.Random()
r.seed(os.urandom(16))
while True:
    rnd1 = r.getrandbits(32)
    rnd2 = r.getrandbits(32)
    ans = rnd1 ^ rnd2
    guess = int(input())
    if guess != ans:
        count=0
        print("Wrong, answer should be :", ans)
        continue
    count += 1
    if count < 50:
        print("Your guess is correct")
        continue
    break
FLAG = open('./flag', 'rb').read()
print(str(FLAG))