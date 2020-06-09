#!/usr/bin/env python
# -*- coding: utf-8 -*-


from .app import login_manager
from . import db
from flask_login import UserMixin
from werkzeug.security import check_password_hash
from datetime import datetime


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.Integer, unique=True, nullable=False)
    username = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    nickname = db.Column(db.String(64), unique=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_superuser = db.Column(db.Boolean, default=False, nullable=False)
    app_id = db.relationship("App", backref="users")
    last_login = db.Column(db.DateTime, default=datetime.now, nullable=False)
    create_time = db.Column(db.DateTime, default=datetime.now, nullable=False)

    @property
    def is_valid(self):
        if self.is_active:
            return True
        return False

    def verify_password(self, password):
        return check_password_hash(self.password, password)

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict

    def __str__(self):
        return '<UserName %s>' % self.username


class App(UserMixin, db.Model):
    __tablename__ = "apps"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, index=True)
    client_id = db.Column(db.Integer, unique=True, index=True, nullable=False)
    client_secret = db.Column(db.String(56), nullable=False)
    redirect_uri = db.Column(db.String(512), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    create_time = db.Column(db.DateTime, default=datetime.now, nullable=False)

    def to_json(self):
        dict = self.__dict__
        if "_sa_instance_state" in dict:
            del dict["_sa_instance_state"]
        return dict

    def __str__(self):
        return '<Name %s>' % self.name


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

