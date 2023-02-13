from flask import Flask, render_template, redirect, url_for, flash, request, current_app,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from functools import wraps

from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, SubmitField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Email, Length

from forms import CreatePostForm
from flask_gravatar import Gravatar

from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
# Base = declarative_base()




def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

WTF_CSRF_SECRETE_KEY='1234GDG'
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# authenticating with Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
 #----------- many to one (posts to author)-------
    author = relationship("UserData", back_populates="posts")
    author_id = db.Column(Integer, db.ForeignKey('users.id'))

 #----------- many to one (posts to comments)-------
    comments = relationship("Comment", back_populates="posts")



class UserData(UserMixin,db.Model):
    __tablename__= "users"
    id= db.Column(db.Integer, primary_key=True)
    name=db.Column(db.String(250), nullable=False)
    phone_no=db.Column(db.String(250),unique=True, nullable=False)
    password=db.Column(db.String(250), nullable=False)
    email=db.Column(db.String(250),unique=True, nullable=False)
 #----------- one to many ( author to posts)-------
    posts = relationship("BlogPost", back_populates="author")

 #----------- one to many ( author to comment)-------
    comments = relationship("Comment", back_populates="author")






class Comment(db.Model):
    __tablename__ = "comments"
    id= db.Column(db.Integer, primary_key=True)
    text=db.Column(db.String(250), nullable=False)
 #----------- many to one (comments to author)-------
    author_id = db.Column(Integer, ForeignKey('users.id'))
    author = relationship("UserData", back_populates="comments")

    # ----------- many to one (comments to posts)-------
    post_id = db.Column(Integer, ForeignKey('blog_posts.id'))
    posts = relationship("BlogPost", back_populates="comments")


#
# with app.app_context():
#     db.create_all()


class RegisterForm(FlaskForm):
    name= StringField('Name', validators=[DataRequired(),Length(min=4, max=25, message=None)])
    email= StringField('Email', validators=[DataRequired(),Email()])
    password=PasswordField('Password',validators=[DataRequired()])
    phone_no=IntegerField('Phone_no',validators=[DataRequired()])
    submit=SubmitField('Register')

class LoginForm(FlaskForm):
    email=StringField('Email', validators=[DataRequired(),Email()])
    password=PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField('LOGIN')



@login_manager.user_loader
def load_user(user_id):
    return UserData.query.filter_by(id=user_id).first()

@app.route('/')
# @login_required
def get_all_posts():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST','GET'])
def register():
    form=RegisterForm()
    if request.method=='POST':
        if form.validate_on_submit():
            name=request.form.get('name')
            email=request.form.get('email')
            if UserData.query.filter_by(email=email).first():
                flash('You are already registered. Trying logging in instead')
                return redirect(url_for('login'))
            password = request.form.get('password')
            new_password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            phone_no = request.form.get('phone_no')

            new_user=UserData(name=name,email=email,password=new_password,phone_no=phone_no)
            with app.app_context():
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
            return redirect(url_for('get_all_posts'))

    return render_template("register.html",form=form)


@app.route('/login',methods=["GET","POST"])
def login():
    form=LoginForm()
    if request.method=="POST":
        email=request.form.get('email')
        password=request.form.get('password')
        user = UserData.query.filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Invalid password. Try again')
                return redirect(url_for('login'))
        flash('Invalid Email. please try again')
        return redirect(url_for('login'))
    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>",methods=['GET',"POST"])
@login_required
def show_post(post_id):
    if request.method=="POST":
        comment=request.form.get('ckeditor')
        new_comment=Comment(text=comment,author_id=current_user.id,post_id=post_id)
        with app.app_context():
            db.session.add(new_comment)
            db.session.commit()

    all_comments = db.session.query(Comment).all()

    print(current_user.is_authenticated)
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post,comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['GET','POST'])
# @login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method=='POST':
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
# @login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
# @login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
