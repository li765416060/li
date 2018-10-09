# 后台
from flask import Blueprint
from flask.views import MethodView
from flask import render_template, session, g
from apps.cms.forms import UserForm, ResetPwdForm, ResetEailForm, ResetEmailSendCode
from flask import request, jsonify
from apps.common.baseResp import *
from exts import db, mail
from flask_mail import Message
from apps.cms.models import *
from config import REMBERME, LOGIN, CURRENT_USER_ID, CURRENT_USER
import string
import random
from apps.common.memcachedUtil import saveCache, getCache
from functools import wraps

bp = Blueprint('cms', __name__, url_prefix="/cms")


def loginDecotor(func):
    """限制登录的装饰器"""
    @wraps(func)
    def inner(*args, **kwargs):
        login = session.get(REMBERME)
        if login == LOGIN:
            return func(*args, **kwargs)
        else:
            return render_template("cms/login.html")
    return inner

def checkPermission(permission):
    def outer(func):
        @wraps(func)
        def inner(*args,**kwargs):
            # 取出来当前的用户， 判断这个用户有没有这个权限
            userid = session[CURRENT_USER_ID]
            user = User.query.get(userid)
            r = user.checkpermission(permission)
            if r:
                return func(*args,**kwargs)
            else:
                return render_template("cms/login.html")
        return inner
    return outer

@bp.route("/")
def loginView():
    return render_template("cms/login.html")


@bp.route('/login/', methods=['post'])
def login():
    fm = UserForm(formdata=request.form)
    if fm.validate():
        email = fm.email.data  # name=email的值
        pwd = fm.password.data
        user = User.query.filter(User.email == email).first()
        if not user:  # 没有查询到用户
            return jsonify(respParamErr('用户名不对'))
        # if user.password == pwd : # 登陆成功
        if user.checkPwd(pwd):
            remberme = request.values.get("remberme")
            session[REMBERME] = LOGIN
            session[CURRENT_USER_ID] = user.id
            if remberme == '1':  # 前端勾选了记住我
                session.permanent = True  # 设置这个属性之后回去config访问过期天数，如果没有设置，默认是31天
            return jsonify(respSuccess('登陆成功'))
        else:  # 密码错误
            return jsonify(respParamErr("密码错误"))
    else:
        return jsonify(respParamErr(msg=fm.err))


@bp.route('/index/')
@loginDecotor
def cms_index():
    return render_template('cms/cms_index.html')


@bp.route("/logout/")
@loginDecotor
def logout():
    session.clear()
    return render_template("cms/login.html")


@bp.route("/user_infor/")
@loginDecotor
@checkPermission(Permission.USER_INFO)
def user_infor():
    return render_template("cms/userInfo.html")


class ResetPwd(MethodView):
    # 给类视图添加装饰器
    decorators = [checkPermission(Permission.USER_INFO),loginDecotor]

    def get(self):
        return render_template('cms/resetpwd.html')

    def post(self):
        fm = ResetPwdForm(formdata=request.form)
        if fm.validate():
            # 拿到原来的密码数据库查询
            userid = session[CURRENT_USER_ID]
            user = User.query.get(userid)
            r = user.checkPwd(fm.oldpwd.data)
            if r:  # 旧密码是对
                user.password = fm.newpwd.data
                db.session.commit()
                return jsonify(respSuccess(msg='修改成功'))
            else:
                return jsonify(respParamErr(msg='修改失败,旧密码错误'))
        else:
            return jsonify(respParamErr(msg=fm.err))


class ResetEmail(MethodView):
    # 给类视图添加装饰器
    decorators = [loginDecotor,checkPermission(Permission.USER_INFO)]

    def get(self):
        '''渲染修改邮箱的模板'''
        return render_template('cms/resetemail.html')

    def post(self):
        '''修改邮箱'''
        fm = ResetEailForm(formdata=request.form)
        if fm.validate:
            # # 判断邮箱在不在
            # user = User.query.filter(User.email == fm.email.data).first()
            # if user:
            #     return jsonify(respParamErr(msg='邮箱已注册'))
            # 判断验证码
            # emailcode = getCache(fm.email.data)
            # # upper()  不区别大小写
            # if not emailcode or emailcode != fm.emailCode.data.upper():
            #     return jsonify(respParamErr(msg='请输入正确的邮箱验证码'))
            # 修改邮箱
            user = User.query.get(session[CURRENT_USER_ID])
            user.email = fm.email.data
            db.session.commit()
            return jsonify(respSuccess(msg='修改邮箱成功'))
        else:
            return jsonify(respParamErr(msg=fm.err))


@bp.route("/send_email_code/", methods=['post'])
@loginDecotor
@checkPermission(Permission.USER_INFO)
def sendEmailCode():
    '''发送邮箱验证码'''
    fm = ResetEmailSendCode(formdata=request.form)
    if fm.validate():
        # 查询邮箱有没有
        # user = User.query.filter(User.email == fm.email.data).first()
        # if user :
        #     return jsonify(respParamErr(msg='邮箱已注册'))
        # else:   # 发送邮件
        r = string.ascii_letters + string.digits
        r = ''.join(random.sample(r, 6))
        saveCache(fm.email.data, r.upper(), 30 * 60)
        msg = Message("破茧科技更新邮箱验证码", recipients=[fm.email.data], body="验证码为" + r)
        mail.send(msg)
        return jsonify(respSuccess(msg='发送成功，请查看邮箱'))
    else:
        return jsonify(respParamErr(msg=fm.err))


# 轮播图管理
@bp.route('/banner/')
@checkPermission(Permission.BANNER)
def banner_view():
    # 取出来当前的用户， 判断这个用户有没有这个权限
    userid = session[CURRENT_USER_ID]
    user = User.query.get(userid)
    r = user.checkpermission(Permission.BANNER)
    if r :
        return render_template("cms/banner.html")
    else:
        return render_template("cms/login.html")

bp.add_url_rule('/resetpwd/', endpoint='resetpwd', view_func=ResetPwd.as_view('resetpwd'))
bp.add_url_rule('/resetemail/', endpoint='resetemail', view_func=ResetEmail.as_view('resetemail'))


# 每次请求的时候都会执行，返回字典可以直接在模板中使用
@bp.context_processor
def requestUser():
    login = session.get(REMBERME)
    if login == LOGIN:
        userid = session[CURRENT_USER_ID]
        user = User.query.get(userid)
        return {'user': user}
    return {}
