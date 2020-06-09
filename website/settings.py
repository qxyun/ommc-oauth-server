#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
app settings for oauth-server project.

For more information on this file, see
http://docs.jinkan.org/docs/flask/
"""

import os
import redis

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# prod or dev
ENV = 'dev'
DEBUG = True
TESTING = False

# oauth key
OAUTH_KEY = 'CC196e700a72be80a355a0e0c68b42e9'

# keep the secret key used in production secret!
SECRET_KEY = 'ygtes75w5o7&ejq&o+9998r4co4m)^+mz)@mnlyrv7iu9'

# Database
SQLALCHEMY_DATABASE_URI = "mysql://{user}:{password}@{host}:{port}/{database}".format(
    user="root",
    password="123456",
    host="127.0.0.1",
    port=3306,
    database="oauth"
)

SQLALCHEMY_POOL_SIZE = 10
SQLALCHEMY_POOL_TIMEOUT = 10
SQLALCHEMY_POOL_RECYCLE = 30
SQLALCHEMY_MAX_OVERFLOW = 100
SQLALCHEMY_TRACK_MODIFICATIONS = False
SQLALCHEMY_COMMIT_ON_TEARDOWN = True

# Redis
RDS = redis.StrictRedis(host="127.0.0.1", port=6379, password="", db=0)
