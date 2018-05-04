#! /usr/bin/python

#   rc4.py - A simple RC4 implementation in Python3. Useful for testing and studing RC4 properties
#
#   Copyright (c) 2018 Filippo Ranza <filipporanza@gmail.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.


import random
import re
import matplotlib.pyplot as plt
import numpy as np


class RC4:
    """
    Encrypt or decrypt (NOT both) given message with RC4
    change key or change action requires a new istance.

    Collect statistics about Key scheduling:
        - store S-box i-th value after the i-th iteration during Key-scheduling.

    define members and initialize permutation array.
    key : RC4 key
    n : S-box length
    """

    def __init__(self, key, n=256):

        # internal status
        # S-box
        self.s = []

        # pointer, used in next function
        self.i = 0
        self.j = 0

        # number of bytes
        self.n = n

        # RC4 Key
        self.key = key

        # Contains the value in i-th position after the i-th iteration in ks
        self.swap = []

    """
    RC4's Key scheduling algorithm
    """

    def ks(self):

        self.s = list(range(0, self.n))
        self.swap = [0] * self.n

        l = len(self.key)
        j = 0
        for i in range(0, self.n):
            tmp = self.key[i % l]
            j = (j + self.s[i] + tmp) % self.n
            self.s[i], self.s[j] = self.s[j], self.s[i]
            self.swap[i] = self.s[i]

    """
    RC4's Pseudo random generator
    """

    def next(self):
        self.i = (self.i + 1) % self.n
        tmp = self.s[self.i]
        self.j = (self.j + tmp) % self.n

        self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]

        k = (self.s[self.i] + self.s[self.j]) % self.n

        return self.s[k]

    """
    encrypt or decrypt given message.
    result is returned.
    """

    def crypt(self, msg):

        # initialize a new keystream
        self.ks()
        l = len(msg)
        out = [0] * l
        for i in range(l):
            m = msg[i]
            c = m ^ self.next()
            out[i] = c

        return out


class RC4Tester:
    """
        A general purpose RC4 test class:
        init the algorithm with a random key,
        stores key and s-box's size.
    """

    def __init__(self, key_sz=13, sb_sz=256):
        self.ks = key_sz
        self.sb_sz = sb_sz
        self.rc4 = None

    def initRC4(self):
        k = self.make_key()
        self.rc4 = RC4(k, self.sb_sz)
        self.rc4.ks()

    def make_key(self):
        rnd = random.Random()
        out = [0] * self.ks
        for i in range(self.ks):
            out[i] = rnd.randint(0, self.ks)

        return out


class RC4RandomTest(RC4Tester):
    """
        Implement a very simple test to evaluate
        the quality of RC4 as random number generator
    """

    def __init__(self, key_sz=13, sb_sz=256):
        super().__init__(key_sz, sb_sz)

    def test(self, count):
        values = [0] * len(self.rc4.s)
        for i in range(count):
            tmp = self.rc4.next()
            values[tmp] += 1

        return values


class RC4SwapTest(RC4Tester):
    """
        Test the probability that, after the i-th iteration
        the value in the i-th position doesn't move
    """

    def __init__(self, key_sz=13, sb_sz=256):
        super().__init__(key_sz, sb_sz)

    def test(self, count):
        unchanged = [0] * self.sb_sz
        for i in range(count):
            self.initRC4()

            s_box = self.rc4.s
            swap = self.rc4.swap

            for j in range(self.sb_sz):
                if s_box[j] == swap[j]:
                    unchanged[j] += 1

        return unchanged


def int_list(s):
    out = [0] * len(s)
    for i in range(len(s)):
        out[i] = ord(s[i])
    return out


def get_file_name(mode='e'):
    if mode == 'e':
        in_file = input("Insert input file name: ")
        msg = "Insert output file name[%s.rc4]: " % in_file
        out_file = input(msg)
        if out_file == "":
            out_file = "%s.rc4" % in_file

        return in_file, out_file

    else:
        in_file = input("Insert input file name: ")

        if in_file.endswith('.rc4'):
            tmp = in_file.replace('.rc4', '')
            msg = "Insert output file name[%s]: " % tmp
        else:
            msg = "Insert output file name[%s]: " % in_file

        out_file = input(msg)
        if out_file == "":
            if tmp:
                out_file = tmp
            else:
                out_file = "%s.plain" % in_file

        return in_file, out_file


def get_rc4():
    user_key = input("Insert a Key: ")
    key = int_list(user_key)

    return RC4(key)


def check_int(s):
    return re.match('^[1-9]\d*$', s) != None


def normalize(r, n):
    l = len(r)
    out = [0] * l
    for i in range(l):
        out[i] = r[i] / n

    return out


def avg(l):
    a = sum(l) / len(l)

    print("obtained", a)
    print("expected", 1 / len(l))

    out = [a] * len(l)
    return out


def approx(n, i):
    return (1 - (1 / n)) ** (n - i)


def plot_random(r, n):
    o = normalize(r, n)
    x = range(len(o))

    a = avg(o)

    plt.figure()
    plt.plot(x, o)
    plt.plot(x, a)
    plt.show()


def plot_changes(r, n):
    o = normalize(r, n)
    x = range(len(o))

    plt.figure()

    plt.plot(x, o)

    x = np.arange(len(o))
    a = approx(len(o), x)

    plt.plot(x, a)
    plt.show()


def get_count():
    count = input("Insert extraction count: ")
    if check_int(count):
        c = int(count)
    else:
        print(count, "is not an integer")
        c = 100000
    return c


def test_random():
    c = get_count()

    tmp = RC4RandomTest()
    tmp.initRC4()
    result = tmp.test(c)
    plot_random(result, c)


def test_changes():
    c = get_count()

    tmp = RC4SwapTest()
    tmp.initRC4()
    result = tmp.test(c)
    plot_changes(result, c)


def encrypt():
    rc4 = get_rc4()
    in_file, out_file = get_file_name('e')

    with open(out_file, 'wb') as w:
        with open(in_file) as r:
            data = int_list(r.read())
            tmp = rc4.crypt(data)
            w.write(bytes(tmp))


def decrypt():
    rc4 = get_rc4()
    in_file, out_file = get_file_name('d')

    with open(out_file, 'wb') as w:
        with open(in_file, 'rb') as r:
            data = r.read()
            tmp = rc4.crypt(data)
            w.write(bytes(tmp))


operations = {
    'a': 'test random',
    'b': 'encrypt',
    'c': 'decrypt',
    'd': 'test changes'
}

actions = {
    'a': test_random,
    'b': encrypt,
    'c': decrypt,
    'd': test_changes
}

for k in operations.keys():
    msg = "%s) %s" % (k, operations[k])
    print(msg)

o = input("Select: ")
f = actions.get(o)

if callable(f):
    f()
else:
    print("unknown", o)



