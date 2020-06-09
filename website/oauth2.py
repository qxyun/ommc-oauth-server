#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import hashlib
import time
import json

from .models import User
from .settings import RDS
from .common import Base


class GenerateState(object):
    def __init__(self, data=None):
        self.SecretKey = "SW12KOMINSA0MM8NSAK"
        self.ClientSecret = "clientSecret"
        self.request_data = data

    def gen_jsonp(self):
        return json.loads(self.request_data)

    def generate_state(self):
        return Base.generate_state(32)

    def hash_state_code(self, code, seed):
        line_str = code + self.SecretKey + seed
        hash_bytes = hashlib.sha256(line_str.encode())
        return hash_bytes.hexdigest()

    def get_state(self):
        state = self.generate_state().decode()
        oauth_state = self.hash_state_code(state, self.ClientSecret)
        RDS.set(oauth_state, self.request_data, ex=1296000)
        return {
            "state": state,
            "oauth_state": oauth_state
        }


class AuthorizationCode(object):
    def __init__(self, state=None, redirect_uri="", response_type=[], client_id="", scope=None, oauth_grafana=None):
        self.state = state
        self.redirect_uri = redirect_uri
        self.response_type = response_type
        self.client_id = client_id
        self.scope = scope
        self.oauth_grafana = oauth_grafana

    def code(self):
        header = chr(random.randint(97, 122))
        code = random.randint(0000000000, 9999999999)
        return "{header}{code}".format(header=header, code=code)

    def verify_client_id(self, sid):
        info = {"ret": False, "msg": ""}
        rows = User.query.filter_by(sid=sid).first()
        if rows is not None:
            info["msg"] = self.redirect_uri + "?code=" + str(sid) + "&state=" + self.state
            info["ret"] = True
        else:
            info["msg"] = "client_id {0}不存在".format(
                self.client_id
            )
        return info

    def get_json(self):
        info = {"ret": False, "msg": ""}
        oauth_data = RDS.get(self.oauth_grafana)
        if oauth_data is not None:
            user = json.loads(oauth_data)
            info = self.verify_client_id(user["sid"])
        else:
            info["msg"] = "oauth_grafana 认证失败"
        return info


class AuthorizationToken(object):
    def __init__(self, code=None, client_id="", client_secret="", redirect_uri=None, grant_type=None):
        self.code = code
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.grant_type = grant_type

    def token(self):
        info = {"ret": False, "msg": "", "token": ""}
        sid = RDS.get(self.code)
        if sid is not None:
            if Base.generate_secret(self.client_id).decode().strip("=") == self.client_secret:
                token = hashlib.md5(':'.join([self.code, str(time.time() + 7200)]).encode()).hexdigest()
                RDS.set(token, sid, ex=60)
                info["ret"] = True
                info["token"] = token
            else:
                info["msg"] = "client_secret 验证失败"
        else:
            info["msg"] = "无效的code参数"
        return info

    def get_token(self):
        token = hashlib.md5(':'.join([self.code, str(time.time() + 7200)]).encode()).hexdigest()
        RDS.set(token, self.code, ex=60)
        return {
            "access_token": token,
            "token_type": "bearer",
            "scope": ""
        }


class UserInfo(object):
    def __init__(self, authorization=None):
        self.authorization = authorization

    def get_info(self):
        auth = self.authorization.split(" ")
        if len(auth) == 2:
            if auth[0] == "Bearer":
                sid = RDS.get(auth[1])
                if sid is not None:
                    user = User.query.filter_by(sid=int(sid)).first()
                    return {
                        "name": user.nickname,
                        "login": user.username,
                        "id": user.sid,
                        "type": "User",
                        "email": user.email
                    }
