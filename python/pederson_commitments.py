import unittest
from Crypto import Random
from Crypto.Random import random
from Crypto.Util import number
from functools import reduce

class Verifier:
    def __init__(self):
        pass

    # Validate a commitment according to the message, h and r.
    def validate(self, c, g, m, h, q, *r):
        r_total = reduce((lambda x, y: x + y), r)
        return c == ((g**m % q) * (h**r_total % q) % q)
    
class Sender:
    def __init__(self, q=None, g=None, s=None, h=None):
        self.Q = q
        self.G = g
        self.S = s
        self.H = h

    # This class method will allow generation of a commitment using
    # pre-determined variables.
    @classmethod
    def new_with_args(cls, q, g, s):
        # Calculate H.
        h = pow(g, s, q)

        return cls(q, g, s, h)

    # Create the commitment given the variable set and a message as a
    # parameter.
    def create_commitment(self, m):
        # r is a randomely generated number used for hiding.
        r = number.getRandomRange(1, self.Q-1)

        # Commitment = (G^m (mod Q)) * (H^r (mod Q))
        c = (pow(self.G, m, self.Q) * pow(self.H, r, self.Q)) % self.Q

        return c, r

    # Add the commitments together using multiplication.
    # *cm is the equivalent to variadic declaration.
    def add(self, *cm):
        # Multiply each value in tuple *cm.
        return reduce((lambda x, y: x * y), cm) % self.Q


class SenderTest(unittest.TestCase):
    # Test that we can create an instance of Sender with pre-determined
    # variables.
    def test_init_sender(self):
        sender = Sender().new_with_args(q=11, g=7, s=5)
        self.assertIsNotNone(sender)
        self.assertEqual(sender.Q, 11)
        self.assertEqual(sender.G, 7)
        self.assertEqual(sender.S, 5)
        self.assertEqual(sender.H, 10)

    # Test that we can create a commitment.
    def test_create_commitment(self):
        sender = Sender().new_with_args(q=11, g=7, s=5)
        
        # c is the commitment, r is the random number.
        msg = 1
        c, r = sender.create_commitment(msg)

        # r should be within the order of Q.
        self.assertTrue(0 < r < sender.Q)

    # Test that the sender can prove a claim to the verifier.
    def test_prove_claim(self):
        sender = Sender().new_with_args(q=11, g=7, s=5)

        # c is the commitment, r is the random number.
        msg = 1
        c, r = sender.create_commitment(msg)

        # Validate the commitment.
        verifier = Verifier()
        valid_commitment = verifier.validate(c, sender.G, msg, sender.H, sender.Q, r)
        self.assertTrue(valid_commitment) 

    # Testing Homomorphic Encryption.
    # We can use the same principle for a pederson commitment to perform
    # homomorphic encryption.
    def test_homomorphic_encryption(self):
        sender = Sender().new_with_args(q=11, g=7, s=5)

        # Create two messages to combine.
        msg1 = 13
        msg2 = 17
        
        # Create x2 commitments and random value.
        c1, r1 = sender.create_commitment(msg1)
        c2, r2 = sender.create_commitment(msg2)
        
        # Multiply the the two commitments.
        combined_cm = sender.add(c1, c2)

        # We can provide a combined commitment, plus both messages and random values to be verified.
        verifier = Verifier()
        valid_commitment = verifier.validate(combined_cm, sender.G, msg1 + msg2, sender.H, sender.Q, r1, r2)
        self.assertTrue(valid_commitment) 



if __name__ == "__main__":
    unittest.main()
