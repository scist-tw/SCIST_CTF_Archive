# Junior RSA
> author : killua4564

## Challenge
```
該從 Baby RSA 成長為 Junior RSA 了

仔細看懂題目後，用國中數學就可以解決掉！

或許用得到的東西：

- [itertools.count](https://docs.python.org/3/library/itertools.html#itertools.count)
- [gmpy2](https://gmpy2.readthedocs.io/en/latest/mpz.html)
    - gmpy2.iroot
    - gmpy2.isqrt
    - gmpy2.next_prime
- [Quadratic equation](https://en.wikipedia.org/wiki/Quadratic_equation)

<br>

Author : killua4564
```

---
## Connection Info
`nc lab.scist.org 10301`

---
## Hint
```
包著 RSA 外皮的代數題目

1. 分解出 n2，可以參考上課題目 factor-attack3
2. 利用 n1 和 r + s 透過一元二次方程求出 rs
3. 再次透過方程分解出 r 和 s

想成單純的代數題目用程式解起來比較簡單

真正的 RSA 在別的地方XD
```

---
## Flag
```
SCIST{JuNi0r 5ch00l s7ud3nt c@n So1v3 RSA.}
```