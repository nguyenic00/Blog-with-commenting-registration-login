from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///blog.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ----- setup relational database ----- #
Base = declarative_base()

# ------ Logging in and logging out ------- #
login_manager = LoginManager()  # lets your code and flask-login work together
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
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    comment_user_parent_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    comment_user_parent = relationship("User", back_populates="user_comments")
    comment_blog_parent_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    comment_blog_parent = relationship("BlogPost", back_populates="comment_children")


class User(UserMixin, db.Model):
    __tablename__ = "User"  # creates new table w/in same database
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    children = relationship("BlogPost", back_populates="parent")
    user_comments = relationship("Comment", back_populates="comment_user_parent")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('User.id'))
    parent = relationship("User", back_populates="children")
    comment_children = relationship("Comment", back_populates="comment_blog_parent")


with app.app_context():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    print(User.query.filter_by(id=user_id).first())
    print("loaded after login_user() removed after logout_user()")
    return User.query.filter_by(id=user_id).first()


# ------- DOES NOT WORK WHEN LOGGING IN TO USER 1, MUST BE FLASK-ERROR ------- #
# ------- WORKS WHEN MOVED INTO THE CODE FOR THE NEW-POST FUNCTION -------- #
def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("decorator running")
        print(current_user.id)
        if current_user.id == 1:
            print("is_admin")
            return func(*args, **kwargs)
        else:
            print("not_admin")
            return abort(403, description="Only Admins have access to this page")
    return wrapper


@app.route('/')
def get_all_posts():
    print("posting")
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    new_user = RegisterForm()
    if new_user.validate_on_submit():
        with app.app_context():
            existing_user = User.query.filter_by(email=request.form["email"]).first()
            # print(existing_user)
            if existing_user:
                flash("Email has already been registered")
                return redirect(url_for('login'))
            else:
                add_user = User(
                    name=request.form["name"],
                    email=request.form["email"],
                    password=generate_password_hash(request.form["password"], method='pbkdf2:sha256', salt_length=8),
                )

                with app.app_context():
                    db.session.add(add_user)
                    db.session.commit()

                    login_user(add_user)

                    return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=new_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    authenticate = LoginForm()
    if authenticate.validate_on_submit():
        with app.app_context():
            user = User.query.filter_by(email=request.form["email"]).first()
            # print(user)

            if user:
                print(user.password)
                # rehash password entry
                match = check_password_hash(user.password, request.form["password"])
                print(match)

                if not match:
                    flash('Invalid Password')
                else:
                    login_user(user)
                    # flash('Logged in successfully')

                    return redirect(url_for('get_all_posts'))

            else:
                flash('Invalid Username')
    return render_template("login.html", form=authenticate)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    add_comment = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    # print(requested_post.comment_children[0].comment_user_parent)  # IMPORTANT, gets list of all the comments related to the blog post

    # with app.app_context():
    #     all_comments = Comment.query.all()
    #     for comment in all_comments:
    #         print(comment.comment_user_parent)

    if add_comment.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=request.form["text"],
                comment_user_parent_id=current_user.id,
                comment_blog_parent_id=post_id
            )
            with app.app_context():
                db.session.add(new_comment)
                db.session.commit()

            return render_template("post.html", post=requested_post, form=add_comment)

        else:
            flash("Login or register to post a comment")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=add_comment)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    # if current_user.id == 1:
    #     print("is_admin")
    form = CreatePostForm()
    if form.validate_on_submit():
        # print(current_user.id)
        print(current_user.name)
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            parent_id=current_user.id
        )
        with app.app_context():
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)
    # else:
    #     print("not_admin")
    #     return abort(403, description="Only Admins have access to this page")


@app.route("/edit-post/<int:post_id>")
@login_required
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
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
# if __name__ == "__main__":
#     app.run(host='0.0.0.0', port=5000)
