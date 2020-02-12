from flask import Flask, render_template, request, flash, session, redirect, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField, FileField, TextAreaField, SelectField
from wtforms.validators import DataRequired
from functools import wraps
import re
import os
from werkzeug.utils import secure_filename
from flask_redis import FlaskRedis


def EmailCheck(email):
    if re.match("^.+\\@(\\[?)[a-zA-Z0-9\\-\\.]+\\.([a-zA-Z]{2,3}|[0-9]{1,3})(\\]?)$", email) is not None:
        return True
    else:
        return False


def PhoneCheck(phone):
    if re.match(r"^1[35678]\d{9}$", phone) is not None:
        return True
    else:
        return False


# def user_login_req(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if "user" not in session:
#             return redirect(url_for("Login", next=request.url))
#         return f(*args, **kwargs)
#     return decorated_function


app = Flask(__name__)
app.secret_key = 'yjs'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:123456@127.0.0.1/flask_sql_demo"
app.config["REDIS_URL"] = "redis://localhost:6379/0"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config["UP_DIR"] = os.path.join(os.path.dirname((__file__)), 'static/upload/')
rd = FlaskRedis(app)


# 用户
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(20), unique=True)  # 昵称
    password = db.Column(db.String(20))  # 密码
    email = db.Column(db.String(20), unique=True)  # 邮箱
    phone = db.Column(db.String(11), unique=True)  # 手机号
    info = db.Column(db.Text, default="这个人很懒，什么都没写···")  # 简介
    avatar = db.Column(db.String(255), unique=True)  # 头像
    # userlogs = db.relationship('Userlog', backref='user')   # 用户日志外键关联
    videos = db.relationship('Video', backref='user')  # 视频外键关联
    comments = db.relationship('Comment', backref='user')  # 评论外键关联
    collects = db.relationship('Collect', backref='user')  # 收藏外键关联

    def __repr__(self):
        return "<User %r>" % self.name

    def check_password(self, password):  # 验证密码
        if self.password == password:
            return True
        else:
            return False


# 用户登录日志
'''
class Userlog(db.Model):
    __tablename__ = 'userlog'
    id = db.Column(db.Integer, primary_key=True)  # 编号
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 用户id
    ip = db.Column(db.String(20))  # 用户ip
    time = db.Column(db.DateTime, index=True, default=datetime. now)  # 用户登录时间

    def __repr__(self):
        return "<Userlog %r>" % self.id
'''


# 标签
class Tag(db.Model):
    __tablename__ = 'tag'
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(50), unique=True)  # 标签名
    videos = db.relationship('Video', backref='tag')  # 视频外键关联

    def __repr__(self):
        return "<Tag %r>" % self.name


# 视频
class Video(db.Model):
    ___tablename__ = 'video'
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(50), unique=True)  # 标题
    url = db.Column(db.String(100), unique=True)  # 地址
    video_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 上传作者
    info = db.Column(db.Text)  # 简介
    logo = db.Column(db.String(255), unique=True)  # 封面
    like = db.Column(db.SmallInteger)  # 点赞
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))  # 所属标签
    comments = db.relationship('Comment', backref='video')  # 评论外键关联
    collects = db.relationship('Collect', backref='video')  # 收藏外键关联

    def __repr__(self):
        return "<Video %r>" % self.name


# 评论
class Comment(db.Model):
    __tablename__ = 'comment'
    id = db.Column(db.Integer, primary_key=True)  # 编号
    content = db.Column(db.Text)  # 评论内容
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'))  # 评论所属视频
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 评论所属用户
    time = db.Column(db.DateTime, index=True, default=datetime.now)  # 用户评论时间

    def __repr__(self):
        return "<Comment %r>" % self.id


# 收藏
class Collect(db.Model):
    __tablename__ = 'collect'
    id = db.Column(db.Integer, primary_key=True)  # 编号
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'))  # 收藏所属视频
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 收藏所属用户
    time = db.Column(db.DateTime, index=True, default=datetime.now)  # 用户收藏时间

    def __repr__(self):
        return "<Comment %r>" % self.id


# 管理员
class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)  # 管理员编号
    name = db.Column(db.String(20), unique=True)  # 管理员昵称
    password = db.Column(db.String(20))  # 管理员密码

    def __repr__(self):
        return "<Admin %r>" % self.id

    def check_password(self, password):  # 验证密码
        if self.password == password:
            return True
        else:
            return False


# 用户登录表单
class UserLoginForm(FlaskForm):
    username = StringField(
        label=u'账号',
        validators=[
            DataRequired(u"请输入用户名")
        ],
        render_kw={
            "placeholder": "请输入用户名",
            "required": False
        }
    )
    password = PasswordField(
        label=u'密码',
        validators=[
            DataRequired(u"请输入密码")
        ],
        render_kw={
            "placeholder": "请输入密码",
            "required": False
        }
    )
    submit = SubmitField(u'登录')


# 管理员登录表单
class AdminLoginForm(FlaskForm):
    username = StringField(
        label=u'账号',
        validators=[
            DataRequired(u"请输入用户名")
        ],
        render_kw={
            "placeholder": "请输入用户名",
            "required": False
        }
    )
    password = PasswordField(
        label=u'密码',
        validators=[
            DataRequired(u"请输入密码")
        ],
        render_kw={
            "placeholder": "请输入密码",
            "required": False
        }
    )
    submit = SubmitField(u'登录')


# 注册表单
class RegisterForm(FlaskForm):
    username = StringField(
        label=u'账号',
        validators=[
            DataRequired("请输入用户名")
        ],
        render_kw={
            "placeholder": "请输入用户名",
            "required": False
        }
    )
    password = PasswordField(
        label=u'密码',
        validators=[
            DataRequired("请输入密码")
        ],
        render_kw={
            "placeholder": "请输入密码",
            "required": False
        }
    )
    repassword = PasswordField(
        label=u'确认密码',
        validators=[
            DataRequired("请输入确认密码"),
        ],
        render_kw={
            "placeholder": "请输入确认密码",
            "required": False
        }
    )
    email = StringField(
        label=u'邮箱',
        validators=[
            DataRequired("请输入邮箱")
        ],
        render_kw={
            "placeholder": "请输入邮箱",
            "required": False
        }
    )
    phone = StringField(
        label='手机号码',
        validators=[
            DataRequired("请输入手机号")
        ],
        render_kw={
            "placeholder": "请输入手机号",
            "required": False
        }
    )
    submit = SubmitField(u'提交')


# 用户修改资料表单
class UserDetailForm(FlaskForm):
    avatar = FileField(
        label="头像"
    )
    username = StringField(
        label=u'账号',
        validators=[
            DataRequired("请输入用户名")
        ],
        render_kw={
            "placeholder": "请输入用户名",
            "required": False
        }
    )
    email = StringField(
        label=u'邮箱',
        validators=[
            DataRequired("请输入邮箱")
        ],
        render_kw={
            "placeholder": "请输入邮箱",
            "required": False
        }
    )
    phone = StringField(
        label='手机号码',
        validators=[
            DataRequired("请输入手机号")
        ],
        render_kw={
            "placeholder": "请输入手机号",
            "required": False
        }
    )
    info = TextAreaField(
        label="简介",
    )
    submit = SubmitField(u'保存')


tags = Tag.query.all()
# 视频上传表单
class VideoUpload(FlaskForm):
    name = StringField(
        label=u'标题',
        validators=[
            DataRequired("请输入标题")
        ],
        render_kw={
            "placeholder": "请输入标题",
            "required": False
        }
    )
    url = FileField(
        label="视频",
        validators=[
            DataRequired("请上传视频")
        ],
        render_kw={
            "placeholder": "请上传视频",
            "required": False
        }
    )
    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired("请上传封面")
        ],
        render_kw={
            "placeholder": "请上传封面",
            "required": False
        }
    )
    logo = FileField(
        label="封面",
        validators=[
            DataRequired("请上传封面")
        ],
        render_kw={
            "placeholder": "请上传封面",
            "required": False
        }
    )
    tag_id = SelectField(
        label="分区",
        validators=[
            DataRequired("请选择分区")
        ],
        render_kw={
            "placeholder": "请选择分区",
            "required": False
        },
        coerce=int,
        choices=[(v.id, v.name) for v in tags]
    )
    submit = SubmitField(u'上传')


# 密码修改表单
class PasswordForm(FlaskForm):
    oldpassword = PasswordField(
        label=u'旧密码',
        validators=[
            DataRequired("请输入旧密码")
        ],
        render_kw={
            "placeholder": "请输入旧密码",
            "required": False
        }
    )
    newpassword = PasswordField(
        label=u'密码',
        validators=[
            DataRequired("请输入密码")
        ],
        render_kw={
            "placeholder": "请输入密码",
            "required": False
        }
    )
    repassword = PasswordField(
        label=u'确认密码',
        validators=[
            DataRequired("请输入确认密码"),
        ],
        render_kw={
            "placeholder": "请输入确认密码",
            "required": False
        }
    )
    submit = SubmitField(u'保存修改')


# 评论表单
class CommentForm(FlaskForm):
    content = TextAreaField(
        label="评论",
        validators=[
            DataRequired("请输入内容：")
        ],
        render_kw={
            "placeholder": "请输入评论",
            "required": False
        }
    )
    submit = SubmitField("提交")


# 首页用户登录页面
@app.route('/', methods=['GET', 'POST'])
def Login():
    form = UserLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # print(username,password)
        check1 = User.query.filter_by(name=username).count()
        # print(check1)
        if check1 == 0:
            flash(u"账号不存在!!!")
        else:
            check2 = User.query.filter_by(name=username).first()
            # print(check2)
            if check2.check_password(password):
                session["user"] = username
                return redirect(url_for('Index', user=username, page=1))
            else:
                flash(u"密码错误!!!")

    return render_template('login.html', form=form)


# 注册页面
@app.route('/register/', methods=['GET', 'POST'])
def Register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        repassword = form.repassword.data
        email = form.email.data
        phone = form.phone.data
        check1 = User.query.filter_by(name=username).count()
        check2 = User.query.filter_by(email=email).count()
        check3 = User.query.filter_by(phone=phone).count()
        if check1 == 0:
            if check2 == 0:
                if check3 == 0:
                    if password == repassword:
                        if EmailCheck(email):
                            if PhoneCheck(phone):
                                user = User(name=username, password=password, email=email, phone=phone)
                                db.session.add(user)
                                db.session.commit()
                                session["user"] = username
                                return redirect(url_for("Index", user=username, page=1))
                            else:
                                flash("请输入正确手机号")
                        else:
                            flash("请输入正确邮箱格式")
                    else:
                        flash("两次密码输入不一致")
                else:
                    flash("电话号码已被注册")
            else:
                flash("邮箱已被注册")
        else:
            flash("该用户名已被注册")
    return render_template('register.html', form=form)


# 用户首页
@app.route('/index/<user>/<int:page>')
def Index(user, page=None):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    if page is None:
        page = 1
    page_data = Video.query.join(User).join(Tag).filter(
        User.id == Video.video_id,
        Tag.id == Video.tag_id
    ).paginate(page=page, per_page=5)
    return render_template("index.html", name=user, page_data=page_data)


# 登出
@app.route("/logout/<user>")
def Logout(user):
    if user not in session:
        return redirect(url_for("Login", next=request.url))
    session.pop("user")
    return redirect(url_for("Login"))


# 管理员登录
@app.route("/adminlogin/", methods=['GET', 'POST'])
def AdminLogin():
    form = AdminLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        check1 = Admin.query.filter_by(name=username).count()
        # print(check1)
        if check1 == 0:
            flash(u"账号不存在!!!")
        else:
            check2 = Admin.query.filter_by(name=username).first()
            # print(check2)
            if check2.check_password(password):
                session["Admin"] = username
                return redirect(url_for("AdminIndex", admin=username, page=1))
            else:
                flash(u"密码错误!!!")
    return render_template("adminlogin.html", form=form)


# 管理员界面
@app.route("/adminindex/<admin>/<int:page>")
def AdminIndex(admin,page=None):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    if page is None:
        page = 1
    page_data = User.query.paginate(page=page, per_page=5)
    return render_template("adminindex.html", name=admin, page_data=page_data)


# 封号处理
@app.route("/adminindex/<admin>/userdelete/<int:id>")
def UserDelete(admin, id):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    try:
        Video.query.filter_by(video_id=id).delete()
        Collect.query.filter_by(user_id=id).delete()
        Comment.query.filter_by(user_id=id).delete()
        db.session.commit()
    except Exception as e:
        print(e)
        db.session.rollback()
    users = User.query.get(id)
    db.session.delete(users)
    db.session.commit()
    session.pop("user")
    return redirect(url_for("AdminIndex", admin=admin, page=1))


# 视频管理
@app.route("/adminvideo/<admin>/<int:page>")
def AdminVideo(admin, page=None):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    if page is None:
        page = 1
    page_data = Video.query.join(User).join(Tag).filter(
        User.id == Video.video_id,
        Tag.id == Video.tag_id
    ).paginate(page=page, per_page=5)
    return render_template("adminvideo.html", admin=admin, page_data=page_data)


# 管理员登出
@app.route("/adminlogout/<admin>")
def AdminLogout(admin):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    session.pop("Admin")
    return redirect(url_for("AdminLogin"))


#管理员删除视频
@app.route("/adminvideo/delete/<admin>/<int:id>")
def AdminViodeoDelete(admin, id):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    try:
        Comment.query.filter_by(video_id=id).delete()
        db.session.commit()
    except Exception as e:
        print(e)
        db.session.rollback()
    video = Video.query.get(id)
    db.session.delete(video)
    db.session.commit()
    return redirect(url_for("AdminVideo", admin=admin, page=1))


# 管理员评论管理
@app.route("/admincomment/<admin>/<int:id>/<int:page>")
def AdminComment(admin, id, page=None):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    video = Video.query.get(id)
    page_data = Comment.query.join(Video).join(User).filter(
        Video.id == id,
        # User.id == Comment.user_id
    ).paginate(page=page, per_page=8)
    return render_template("admincomment.html", video=video, page_data=page_data, admin=admin)


# 管理员删除评论
@app.route("/admincommentdelete/<admin>/<int:id>")
def AdminCommentDelete(admin, id):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    comment = Comment.query.get(id)
    video_id = Comment.query.get(id).video_id
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for("AdminComment", admin=admin, id=video_id, page=1))



# 管理员点赞清零
@app.route("/adminlike/<admin>/<int:id>")
def AdminLike(admin, id):
    if session.get("Admin") != admin:
        return redirect(url_for("AdminLogin", next=request.url))
    video = Video.query.get(id)
    video.like = 0
    db.session.commit()
    return redirect(url_for("AdminComment", admin=admin, id=id, page=1))



# 用户上传视频
@app.route('/index/<user>/upload', methods=["POST", "GET"])
def Upload(user):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    form = VideoUpload()
    usermessage = User.query.filter_by(name=user).first()
    if form.validate_on_submit():
        name = form.name.data
        info = form.info.data
        video_id = usermessage.id
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)
        tag_id = form.tag_id.data
        if file_url.split(".")[1] in ["avi", "mp4"]:
            if file_logo.split(".")[1] in ["png", "jpg", "jpeg", "gif"]:
                if not os.path.exists(app.config["UP_DIR"]):
                    os.makedirs(app.config["UP_DIR"])
                    os.chmod(app.config["UP_DIR"], "rw")
                form.url.data.save(app.config["UP_DIR"] + file_url)
                form.logo.data.save(app.config["UP_DIR"] + file_logo)
                video = Video(
                    name=name,
                    info=info,
                    video_id=video_id,
                    url=file_url,
                    like=0,
                    logo=file_logo,
                    tag_id=int(tag_id)
                )
                db.session.add(video)
                db.session.commit()
                flash("上传成功")
                return redirect(url_for("Index", user=user, page=1))
            else:
                flash("请上传图片文件")
        else:
            flash("请上传视频文件")

    return render_template('videoupload.html', form=form, name=user)


# 个人中心
@app.route('/index/space/<user>/<int:page>')
def Space(user,page=None):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    usermessage = User.query.filter_by(name=user).first()
    page_data = Collect.query.join(Video).join(User).filter(
        # Video.id == Collect.video_id,
         usermessage.id == Collect.user_id
    ).paginate(page=page, per_page=10)
    return render_template("space.html",name=user, usermessage=usermessage, page_data=page_data)


# 已上传视频
@app.route("/index/space/videouploaded/<user>/<int:page>")
def VideoUploaded(user, page=None):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    if page is None:
        page = 1
    uid = User.query.filter_by(name=user).first()
    page_data = Video.query.filter_by(video_id=uid.id).paginate(page=page, per_page=5)
    return render_template("videouploaded.html", name=user, page_data=page_data, usermessage=uid)


# 删除视频
@app.route('/index/space/<user>/videodelete/<int:id>')
def VideoDelete(user, id):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    try:
        Comment.query.filter_by(video_id=id).delete()
        db.session.commit()
    except Exception as e:
        print(e)
        db.session.rollback()
    video = Video.query.get(id)
    db.session.delete(video)
    db.session.commit()
    return redirect(url_for("VideoUploaded", user=user, page=1))


# 删除收藏
@app.route('/index/space/<user>/collectdelete/<int:id>')
def CollectDelete(user, id):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    collect = Collect.query.get(id)
    db.session.delete(collect)
    db.session.commit()
    return redirect(url_for("Space", user=user, page=1))


# 密码修改
@app.route('/index/space/password/<user>/', methods=["POST", "GET"])
def Password(user):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    form = PasswordForm()
    usermessage = User.query.filter_by(name=user).first()
    if form.validate_on_submit():
        oldpassword = form.oldpassword.data
        newpassword = form.newpassword.data
        repassword = form.repassword.data
        if oldpassword == usermessage.password:
            if newpassword == repassword:
                usermessage.password = newpassword
                db.session.commit()
                flash("修改成功")
                return redirect(url_for("Space", user=user))
            else:
                flash("两次密码输入不一致")
        else:
            flash("原密码错误")
    return render_template("password.html",form=form, name=user, usermessage=usermessage)


# 信息修改
@app.route('/index/space/change/<user>/', methods=["POST", "GET"])
def UserChange(user):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    form = UserDetailForm()
    usermessage = User.query.filter_by(name=user).first()
    if request.method == "GET":
        form.username.data = usermessage.name
        form.email.data = usermessage.email
        form.phone.data = usermessage.phone
        form.info.data = usermessage.info
    if form.validate_on_submit():
        check1 = User.query.filter_by(name=form.username.data).count()
        check2 = User.query.filter_by(email=form.email.data).count()
        check3 = User.query.filter_by(phone=form.phone.data).count()
        if check1 == 0 or form.username.data == usermessage.name:
            if check2 == 0 or form.email.data == usermessage.email:
                if check3 == 0 or form.phone.data == usermessage.phone:
                    if EmailCheck(form.email.data):
                        if PhoneCheck(form.phone.data):
                            file_face = secure_filename(form.avatar.data.filename)
                            try:
                                if file_face.split(".")[1] in ["png", "jpg", "jpeg", "gif"]:
                                    if not os.path.exists(app.config["UP_DIR"]):
                                        os.makedirs(app.config["UP_DIR"])
                                        os.chmod(app.config["UP_DIR"],"rw")
                                    form.avatar.data.save(app.config["UP_DIR"] + file_face)
                                    usermessage.avatar = file_face
                                else:
                                    flash("文件类型不正确(仅支持png、jpg、jpeg、gif格式)")
                            except:
                                pass
                            usermessage.name = form.username.data
                            usermessage.email = form.email.data
                            usermessage.phone = form.phone.data
                            usermessage.info = form.info.data
                            db.session.commit()
                            flash("修改成功！")
                            session["user"] = form.username.data
                            return redirect(url_for("Space", user=user))
                        else:
                            flash("请输入正确手机号")
                    else:
                        flash("请输入正确邮箱格式")
                else:
                    flash("电话号码已被注册")
            else:
                flash("邮箱已被注册")
        else:
            flash("该用户名已被注册")
    return render_template('userchange.html', name=user, usermessage=usermessage, form=form)


#评论删除
@app.route("/video/<user>/commentdelete/<int:id>")
def CommentDelete(user, id):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    video_id = Comment.query.get(id).video_id
    comment = Comment.query.get(id)
    db.session.delete(comment)
    db.session.commit()
    return redirect(url_for("VideoPlay", user=user, id=video_id, page=1))


# 视频页面
@app.route("/video/<user>/<int:id>/<int:page>", methods=["POST", "GET"])
def VideoPlay(user, id, page=None):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    form = CommentForm()
    video = Video.query.get(id)
    uid = User.query.filter_by(name=user).first()
    page_data = Comment.query.join(Video).join(User).filter(
        Video.id == id,
        # User.id == Comment.user_id
    ).paginate(page=page, per_page=8)
    if Collect.query.filter(
        Collect.video_id == id,
        Collect.user_id == uid.id
    ).count() == 0:
        collect_check = 1
    else:
        collect_check = 0
    if form.validate_on_submit():
        comment = Comment(
            content=form.content.data,
            video_id=id,
            user_id=uid.id
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("VideoPlay", user=user, id=id, page=1))
    return render_template("video.html", video=video, form=form, page_data=page_data, name=user, collect_check=collect_check)


# 点赞
@app.route("/video/<user>/<int:id>/like")
def Like(user, id):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    video = Video.query.get(id)
    video.like = video.like + 1
    print(video.like)
    db.session.commit()
    return redirect(url_for("VideoPlay", user=user, id=id, page=1))


# 收藏
@app.route("/video/<user>/<int:id>/collect", methods=["GET"])
def VideoCollect(user, id):
    if session.get("user") != user:
        return redirect(url_for("Login", next=request.url))
    uid = User.query.filter_by(name=user).first()
    if Collect.query.filter(
        Collect.video_id == id,
        Collect.user_id == uid.id
    ).count() == 0:
        video = Video.query.get(id)
        uid = User.query.filter_by(name=user).first()
        collect = Collect(video_id=video.id, user_id=uid.id)
        db.session.add(collect)
        db.session.commit()
        return redirect(url_for("VideoPlay", user=user, id=id, page=1))
    else:
        print("1")
        return redirect(url_for("VideoPlay", user=user, id=id, page=1))


# 弹幕接口
@app.route("/dm/v3/", methods=["GET", "POST"])
def danmaku():
    import json
    if request.method == "GET":
        id = request.args.get("id")
        key = "video" + str(id)
        if rd.llen(key):
            msgs = rd.lrange(key, 0, 2999)
            # res = {
            #     "code": 1,
            #     "danmaku": [json.loads(v) for v in msgs]
            #
            # }
            # print([json.loads(v) for v in msgs])
            temp_data = []
            for msg in msgs:
                msg = json.loads(msg)
                temp = [msg['time'], msg["type"], msg['color'], msg['author'], msg['text']]
                temp_data.append(temp)
            res = {
                "code": 0,
                "data": temp_data
            }
        else:
            res = {
                "code": 1,
                "danmaku": []
            }
        resp = json.dumps(res)
        print(resp)
    if request.method == "POST":
        data = json.loads(request.get_data())
        msg = {
            "author": data["author"],
            "color": data["color"],
            "id": request.remote_addr,
            "player": data["id"],
            "text": data["text"],
            "time": data["time"],
            "type": data["type"],
            "__v": 0,
        }
        res = {
            "code": 1,
            "data": msg
        }
        resp = json.dumps(res)
        rd.lpush("video" + str(data["id"]), json.dumps(msg))
    return  Response(resp, mimetype="application/json")



if __name__ == '__main__':
    # db.drop_all()
    # db.create_all()
    # user1 = User(name="JoshuaYu", password="123456", email="1239299797@qq.com", phone="13850236448" )
    # user2 = User(name="余佳硕", password="123456", email="12312123213@qq.com", phone="13607733852")
    # tag1 = Tag(name="动画")
    # tag2 = Tag(name="音乐")
    # tag3 = Tag(name="舞蹈")
    # tag4 = Tag(name="科技")
    # tag5 = Tag(name="生活")
    # tag6 = Tag(name="游戏")
    # video1 = Video(name='hello', url="VID_20190616_162459.mp4", video_id=1, info="海南", logo="IMG_20190619_095821.jpg", like=0, tag_id=5)
    # admin = Admin(name="bilibili蓝图规划", password="123456")
    # db.session.add_all([admin, tag1, tag2, tag3, tag4, tag5, tag6, user1, user2, video1])
    # db.session.commit()
    app.run(debug=True)
