#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import json
import string
import base64
import hashlib

from .settings import RDS


class Base(object):
    SecretKey = "SW12KOMINSA0MM8NSAK"

    @classmethod
    def json_load(cls, msg):
        data = json.loads(msg)
        return data

    @classmethod
    def json_dump(cls, msg, ensure_ascii=False):
        data = json.dumps(msg, ensure_ascii=ensure_ascii)
        return data

    @classmethod
    def generate_id(cls, num):
        return str(random.randint(0000000000000000, 9999999999999999))[:num]

    @classmethod
    def generate_state(cls, num):
        rnd = random.sample(string.ascii_letters + string.digits + string.punctuation, num)
        return base64.b64encode(''.join(rnd).encode())

    @classmethod
    def generate_code(cls, sid):
        code = hashlib.md5(cls.generate_state(32)).hexdigest()
        RDS.set(code, sid, ex=300)
        return code

    @classmethod
    def generate_secret(cls, client_id):
        return base64.b64encode("{0}.{1}".format(cls.SecretKey, client_id).encode())
