import hashlib
import os
import base64
import json

class User:
    DIGEST = 'sha384'
    ROUNDS = 100000

    def __init__(self, **document):
        self.name = document['name']
        self.year = document['year']
        self.email = document['email']
        self.twitter = document['twitter']
        self.password = None

    def set_password(self, password):
        salt = os.urandom(30)
        # Password-Based Key Derivation Function 2
        hash = hashlib.pbkdf2_hmac( 
            self.DIGEST, password.encode('utf-8'), salt, self.ROUNDS)
        self.password = '$'.join(
            [self.DIGEST,
            base64.urlsafe_b64encode(salt).decode('ascii'),
            base64.urlsafe_b64encode(hash).decode('ascii')
            ]
        )

    def check_password(self, password):
        digest, b64_salt, b64_expected_hash = self.password.split('$')
        salt = base64.urlsafe_b64decode(b64_salt)
        expected_hash = base64.urlsafe_b64decode(b64_expected_hash)
        computed_hash = hashlib.pbkdf2_hmac(
            digest, password.encode('utf-8'), salt, self.ROUNDS)
        return computed_hash == expected_hash

    def to_json(self):
        return {
        "__class__": "User",
        'name': self.name,
        'year': self.year,
        'email':self.email,
        'twitter': self.twitter,
        'password': self.password
        }

