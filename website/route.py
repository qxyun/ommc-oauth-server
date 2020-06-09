#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Blueprint, request, session, make_response
from flask import render_template, redirect, jsonify
from .oauth2 import AuthorizationCode, AuthorizationToken, UserInfo, GenerateState
from .settings import OAUTH_KEY
from flask import current_app
from .models import User, App

from flask_login import login_required, login_user, logout_user, current_user
from .lang.zh_cn import Lang
from . import db
from werkzeug.security import generate_password_hash
from .common import Base
from datetime import datetime
bp = Blueprint(__name__, 'home')


@bp.route('/', methods=['GET'])
@login_required
def index():
    return render_template("index.html", user=current_user)


@bp.route('/app', methods=['GET'])
@login_required
def app():
    return render_template("app.html", user=current_user)


@bp.route("/login", methods=["GET", "POST"])
def login():
    info = {"ret": False, "msg": "", "next": "", "code":""}
    next = request.args.get("next", None)
    if request.method == "POST":
        username = request.form.get("username", None)
        password = request.form.get("password", None)

        if username != "" and password != "":
            user = User.query.filter_by(username=username).first()
            if user is not None:
                if user.is_active:
                    if user.verify_password(password):
                        login_user(user, remember=False)
                        info["ret"] = True
                        user.last_login = datetime.now()
                        db.session.add(user)
                        db.session.commit()
                        if next is not None:
                            info["next"] = next
                        info["code"] = Base.generate_code(user.sid)
                    else:
                        info["msg"] = "密码验证失败！"
                else:
                    info["msg"] = "用户被禁用了！"
            else:
                info["msg"] = "{0}用户不存在！".format(username)
        else:
            info["msg"] = "用户或密码不能为空！"
    else:
        if current_user.is_authenticated:
            return redirect("/")
        return render_template("login.html")

    return jsonify(info)


@bp.route("/user/list", methods=["GET"])
@login_required
def user_list():
    info = {"ret": False, "msg": ""}
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 10, type=int)
    search = request.args.get("search", None)
    try:
        if current_user.is_superuser:
            if search is not None and search != "":
                user_list_show = User.query.filter_by(username=search).paginate(page, per_page=limit, error_out=False)
            else:
                user_list_show = User.query.order_by().paginate(page, per_page=limit, error_out=False)
        else:
            user_list_show = User.query.filter_by(username=current_user.username).paginate(page, per_page=limit, error_out=False)
        result = {
            "ret": True,
            "total": user_list_show.total,
            "page": user_list_show.page,
            "next_num": user_list_show.next_num,
            "prev_num": user_list_show.prev_num,
            "pages": user_list_show.pages,
            "rows": []
        }
        for line in user_list_show.items:
            line_user = line.to_json()
            line_user["password"] = ""
            result["rows"].append(line_user)

        return result
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "用户列表获取出错！"
    return info


@bp.route("/app/list", methods=["GET"])
@login_required
def app_list():
    info = {"ret": False, "msg": ""}
    page = request.args.get("page", 1, type=int)
    limit = request.args.get("limit", 10, type=int)
    search = request.args.get("search", None)
    try:
        if current_user.is_superuser:
            if search is not None and search != "":
                app_list_show = App.query.filter_by(username=search).paginate(page, per_page=limit, error_out=False)
            else:
                app_list_show = App.query.order_by().paginate(page, per_page=limit, error_out=False)
        else:
            app_list_show = App.query.filter_by(user_id=current_user.id).paginate(page, per_page=limit, error_out=False)
        result = {
            "ret": True,
            "total": app_list_show.total,
            "page": app_list_show.page,
            "next_num": app_list_show.next_num,
            "prev_num": app_list_show.prev_num,
            "pages": app_list_show.pages,
            "rows": []
        }
        for line in app_list_show.items:
            line_user = line.to_json()
            result["rows"].append(line_user)

        return result
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "应用列表获取出错！"
    return info


@bp.route("/user/add", methods=["POST"])
@login_required
def user_add():
    info = {"ret": False, "msg": ""}
    request_data = request.form.get("data", None)
    try:
        if request.method == "POST":
            try:
                data = Base.json_load(request_data)
                if data["id"] == "":
                    u = User.query.filter_by(username=data["username"]).first()
                    if u is None:
                        user = User()
                        user.username = data["username"]
                        user.nickname = data["nickname"]
                        user.email = data["email"]
                        user.is_active = int(data["status"])
                        user.sid = Base.generate_id(6)
                        user.password = generate_password_hash(data["password"])

                        db.session.add(user)
                        db.session.commit()
                        info["ret"] = True
                    else:
                        info["msg"] = "{0}已存在!".format(data["username"])
                else:
                    u = User.query.filter_by(id=int(data["id"])).first()
                    u.username = data["username"]
                    u.nickname = data["nickname"]
                    u.email = data["email"]
                    u.is_active = int(data["status"])

                    db.session.add(u)
                    db.session.commit()
                    info["ret"] = True
            except Exception as e:
                info["msg"] = "参数解析出错!"
        else:
            info["msg"] = "不支持{0}方法".format(request.method)
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "创建用户出错！"
    return info


@bp.route("/app/add", methods=["POST"])
@login_required
def app_add():
    info = {"ret": False, "msg": ""}
    request_data = request.form.get("data", None)
    try:
        if request.method == "POST":
            try:
                data = Base.json_load(request_data)
                if data["id"] == "":
                    u = App.query.filter_by(name=data["name"]).first()
                    if u is None:
                        app = App()
                        app.name = data["name"]
                        app.redirect_uri = data["address"]
                        app.client_id = Base.generate_id(6)
                        app.client_secret = Base.generate_secret(app.client_id).decode().strip("=")

                        u = User.query.get(current_user.id)
                        app.users = u
                        db.session.add(app)
                        db.session.commit()
                        info["ret"] = True
                    else:
                        info["msg"] = "{0}已存在!".format(data["name"])
                else:
                    u = App.query.filter_by(id=int(data["id"])).first()
                    u.name = data["name"]
                    u.redirect_uri = data["address"]

                    db.session.add(u)
                    db.session.commit()
                    info["ret"] = True
            except Exception as e:
                current_app.logger.error(str(e))
                info["msg"] = "参数解析出错!"
        else:
            info["msg"] = "不支持{0}方法".format(request.method)
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "创建应用出错！"
    return info


@bp.route("/user/delete", methods=["POST"])
@login_required
def user_delete():
    info = {"ret": False, "msg": ""}
    ids = request.form.get("ids", None)
    try:
        if current_user.is_superuser:
            for id in ids.split(","):
                u = User.query.filter_by(id=int(id)).first()
                db.session.delete(u)
            db.session.commit()
            info["ret"] = True
        else:
            info["msg"] = "权限拒绝！"
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "删除用户出错！"
    return info


@bp.route("/app/delete", methods=["POST"])
@login_required
def app_delete():
    info = {"ret": False, "msg": ""}
    ids = request.form.get("ids", None)
    try:
        for id in ids.split(","):
            u = App.query.filter_by(id=int(id)).first()
            db.session.delete(u)
        db.session.commit()
        info["ret"] = True
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "删除用户出错！"
    return info


@bp.route("/user/detail/ids/<int:id>", methods=["GET"])
@login_required
def user_detail_id(id):
    info = {"ret": False, "msg": ""}
    try:
        user = User.query.filter_by(id=id).first()
        line_user = user.to_json()
        line_user["password"] = ""
        info["msg"] = line_user
        info["ret"] = True
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "获取用户信息出错！"
    return info


@bp.route("/app/detail/ids/<int:id>", methods=["GET"])
@login_required
def app_detail_id(id):
    info = {"ret": False, "msg": ""}
    try:
        user = App.query.filter_by(id=id).first()
        line_user = user.to_json()
        info["msg"] = line_user
        info["ret"] = True
    except Exception as e:
        current_app.logger.error(str(e))
        info["msg"] = "获取用户信息出错！"
    return info


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@bp.route('/oauth/authorize', methods=['GET'])
def oauth_authorize():
    info = {"ret": False, "msg": ""}
    redirect_uri = request.args.get("redirect_uri")
    client_id = request.args.get("client_id")
    try:
        if client_id is not None:
            client = App.query.filter_by(client_id=int(client_id)).first()
            if client is not None:
                if redirect_uri is not None and redirect_uri == client.redirect_uri:
                    # session 方式检验是否已经登录
                    if current_user.is_authenticated:
                        return redirect(redirect_uri + "?code={0}".format(Base.generate_code(current_user.sid)))
                    else:
                        return render_template("login.html")
                else:
                    info["msg"] = "无效的redirect_uri"
            else:
                info["msg"] = "无效的client_id"
        else:
            info["msg"] = "无效的client_id"
    except Exception as e:
        info["msg"] = str(e)
        current_app.logger.error(str(e))
    return info


@bp.route('/oauth/access_token', methods=['POST'])
def access_token():
    code = request.form.get("code", None)
    client_id = request.form.get("client_id", None)
    client_secret = request.form.get("client_secret", None)
    redirect_uri = request.form.get("redirect_uri", None)
    grant_type = request.form.get("grant_type", None)
    if request.method == 'POST':
        try:
            token = AuthorizationToken(code, client_id, client_secret, redirect_uri, grant_type)
            if grant_type is not None and grant_type == "authorization_code":
                return token.get_token()
            else:
                return token.token()
        except Exception as e:
            current_app.logger.error(str(e))
    else:
        return jsonify(ret=False, msg="不支持{0}方法".format(request.method))


@bp.route('/oauth/user', methods=['GET'])
def user_info():
    if request.method == 'GET':
        try:
            authorization = request.headers.get('Authorization')
            if authorization is not None:
                user = UserInfo(authorization)
                return user.get_info()
            else:
                current_app.logger.error("认证失败")
        except Exception as e:
            current_app.logger.error(str(e))
    else:
        return jsonify(ret=False, msg="不支持{0}方法".format(request.method))


@bp.route('/lang', methods=['GET'])
def lang_zh_cn():
    callback = request.args.get("callback", None)
    controller = request.args.get("controller", None)
    if controller == "index":
        pass
    if callback is None:
        callback = "define"
    response = make_response("{0}({1})".format(callback, Base.json_dump(Lang, ensure_ascii=False)))
    response.headers["Content-Type"] = "application/javascript"
    response.headers["Cache-Control"] = "public"
    response.headers["Pragma"] = "cache"
    return response
