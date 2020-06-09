#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask
from logging.config import dictConfig
from flask_login import LoginManager

# 实例化登录对象
login_manager = LoginManager()
# 设置用户登录视图（入口）
login_manager.login_view = "/login"


def create_app(config=None):
    dictConfig({
        'version': 1,
        'formatters': {'default': {
            'format': '[%(asctime)s] %(levelname)s in %(filename)s[line:%(lineno)d]: %(message)s',
        }},
        'handlers': {'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'default'
        }},
        'root': {
            'level': 'INFO',
            'handlers': ['wsgi']
        }
    })
    app = Flask(__name__, static_folder="../static", template_folder="../templates")

    # load default configuration
    app.config.from_object('website.settings')
    if app.config.get('DEBUG') is not None:
        debug = app.config['DEBUG']
        app.debug = debug

    # 初始化app
    login_manager.init_app(app)

    return app
