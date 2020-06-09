#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask_sqlalchemy import SQLAlchemy
from .app import create_app

# 实例化DB
app = create_app()
db = SQLAlchemy(app)


def init_create_app():
    with app.app_context():
        # # 初始化db
        db.init_app(app)
        # 创建所有未创建的table
        from .models import User
        db.create_all()

    from .context import build_toolbar
    app.add_template_global(build_toolbar, "build_toolbar")

    # 注册蓝图
    from .route import bp
    app.register_blueprint(bp, url_prefix='')

    return app