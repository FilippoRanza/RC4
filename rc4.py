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
        """
        create a new RC4 object
        :param key: RC4 key
        :param n: s-box length
        """

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


    def ks(self):
        """
        RC4's Key scheduling algorithm
        """
        self.s = list(range(0, self.n))
        self.swap = [0] * self.n

        l = len(self.key)
        j = 0
        for i in range(0, self.n):
            tmp = self.key[i % l]
            j = (j + self.s[i] + tmp) % self.n
            self.s[i], self.s[j] = self.s[j], self.s[i]
            self.swap[i] = self.s[i]

    def next(self):
        """
        RC4's Pseudo random generator
        """
        self.i = (self.i + 1) % self.n
        tmp = self.s[self.i]
        self.j = (self.j + tmp) % self.n

        self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]

        k = (self.s[self.i] + self.s[self.j]) % self.n

        return self.s[k]



    def crypt(self, msg):
        """
        encrypt or decrypt given message.
        result is returned.
        """
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
        """
        initialize a new RC4Tester, use subclasses
        to run a specific test
        :param key_sz: key size
        :param sb_sz: s-box size
        """
        self.ks = key_sz
        self.sb_sz = sb_sz
        self.rc4 = None

    def initRC4(self):
        """
        initialize inner RC4 object
        :return:
        """
        k = self.make_key()
        self.rc4 = RC4(k, self.sb_sz)
        self.rc4.ks()

    def make_key(self):
        """
        generate a new random key
        :return:  a new key
        """
        rnd = random.Random()
        out = [0] * self.ks
        for i in range(self.ks):
            out[i] = rnd.randint(0, self.ks)

        return out

    def test(self, count):
        """
        start a new test
        :param count: number of execution for the test
        :return: test result
        """
        pass


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


class Executor:
    """
    provide a common interface for every executor class
    """
    def run(self):
        pass


class TestRunner(Executor):
    """
    runs RC$ tests: RC4RandomTest or RC4SwapTest
    """
    def __init__(self, rc4, output):
        """
        initialize a TestRunner object, use run method to
        run the test.
        :param rc4: Test to run, RC4RandomTest RC4SwapTest
        :param output: function to display test result, requires result list and test count
        """
        self.rc4 = rc4
        self.count = 100000
        self.output = output

    def get_count(self):
        count = input("Insert extraction count: ")
        if TestRunner.check_int(count):
            self.count = int(count)
        else:
            print(count, "is not an integer")

    def run(self):
        tmp = self.rc4()
        tmp.initRC4()
        result = tmp.test(self.count)
        self.output(result, self.count)

    @staticmethod
    def check_int(s):
        return re.match('^[1-9]\d*$', s) != None


class Cipher(Executor):
    """
    encrypt or decrypt given files
    """
    def __init__(self, mode):
        """
        create a Cipher object, call rum method to
        encrypt or decrypt given files
        :param mode: 'e' to encrypt, 'd' to decrypt
        """
        key = Cipher.get_key()
        self.rc4 = RC4(key)
        self.in_file, self.out_file = Cipher.get_file_name(mode)

    def run(self):
        with open(self.out_file, "wb") as o:
            with open(self.in_file, "rb") as i:
                data = i.read()
                out = self.rc4.crypt(data)
                o.write(bytes(out))

    @staticmethod
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

            tmp = ""
            if in_file.endswith('.rc4'):
                tmp = in_file.replace('.rc4', '')
                msg = "Insert output file name[%s]: " % tmp
            else:
                msg = "Insert output file name[%s.plain]: " % in_file

            out_file = input(msg)
            if out_file == "":
                if tmp == "":
                    out_file = tmp
                else:
                    out_file = "%s.plain" % in_file

            return in_file, out_file

    @staticmethod
    def get_key():
        kstr = input("Insert a Key: ")
        return Cipher.int_list(kstr)

    @staticmethod
    def int_list(s):
        out = [0] * len(s)
        for i in range(len(s)):
            out[i] = ord(s[i])
        return out


class Runner:
    """
    this class it's a container for
    function that initialize program's
    operations
    """

    @staticmethod
    def encrypt():
        return Cipher('e')

    @staticmethod
    def decrypt():
        return Cipher('d')

    @staticmethod
    def swap_test():
        tmp = TestRunner(RC4SwapTest, plot_changes)
        tmp.get_count()
        return tmp

    @staticmethod
    def random_test():
        tmp = TestRunner(RC4RandomTest, plot_random)
        tmp.get_count()
        return tmp


def normalize(r, n):
    """
    takes absolute values from a test
    and normalize them into range [0,1]
    :param r: values from test
    :param n: number of tests
    :return: normalized values
    """
    l = len(r)
    out = [0] * l
    for i in range(l):
        out[i] = r[i] / n
    return out


def avg(l):
    """
    calculate the average value of input
    list.
    This function also print expected distribution
    :param l: input list, usually from a RC4RandomTest
    :return: the average value
    """
    a = sum(l) / len(l)

    print("obtained", a)
    print("expected", 1 / len(l))

    out = [a] * len(l)
    return out


def approx(n, i):
    """
    The approximation,according to Klain, of changes
    after the i-th iteration of RC4's Key scheduling inside RC4's s-box
    :param n: s-box length
    :param i: iteration
    :return: probability the i-th value won't change
    """
    return (1 - (1 / n)) ** (n - i)


def plot_random(r, n):
    """
    plot result from RC4RandomTest
    :param r: test result
    :param n: test count
    :return: None
    """
    o = normalize(r, n)
    x = range(len(o))

    a = avg(o)

    plt.figure()
    plt.plot(x, o)
    plt.plot(x, a)
    plt.show()


def plot_changes(r, n):
    """
    plot result from RC4SwapTest
    :param r: test result
    :param n: test count
    :return: None
    """
    o = normalize(r, n)
    x = range(len(o))

    plt.figure()

    plt.plot(x, o)

    x = np.arange(len(o))
    a = approx(len(o), x)

    plt.plot(x, a)
    plt.show()


# let use this script as a program or a library
if __name__ == '__main__':
    operations = {
        'a': Runner.encrypt,
        'b': Runner.decrypt,
        'c': Runner.swap_test,
        'd': Runner.random_test
    }

    choices = {
        'a': "encrypt",
        'b': "decrypt",
        'c': "swap test",
        'd': "random test"
    }

    for k in choices.keys():
        tmp = "%c) %s" % (k, choices[k])
        print(tmp)

    cmd = input("Insert command: ")
    f = operations.get(cmd)

    if callable(f):
        test = f()
        test.run()
    else:
        print(f, "is not a valid choice")

