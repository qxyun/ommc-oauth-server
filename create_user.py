#!/usr/bin/env python
# -*- coding: utf-8 -*-

from website.models import User
from werkzeug.security import generate_password_hash
from website import db


def create_user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        admin = User()
        admin.sid = 111111
        admin.username = username
        admin.password = generate_password_hash("123456")
        admin.email = "admin@qxyun.net"
        admin.nickname = "超级管理员"
        admin.is_superuser = True
        db.session.add(admin)
        db.session.commit()


if __name__ == '__main__':
    create_user("admin")
    print("ok")
