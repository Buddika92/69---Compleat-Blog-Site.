from datetime import date
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

# Import your forms from the forms.py
from forms import CommentForm, CreatePostForm, LoginForm, RegisterForm

app = Flask(__name__)
app.config["SECRET_KEY"] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login with flask app
login_manager = LoginManager()
login_manager.init_app(app)

# Configure Gravatar with Flask App.
gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default="retro",
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None,
)


# CONNECT TO DB
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///posts.db"
db = SQLAlchemy()
db.init_app(app)


# TODO: Create a User table for all your registered users.
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=True)
    email = db.Column(db.String, unique=True, nullable=True)
    password = db.Column(db.String, nullable=True)

    # _____ ADD PARENT RELATIONSHIP_____ #
    # This will like act a list of BlogPost objects attached to each User.
    # The "author" refer to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # The "comment_author" refer to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    # _____ ADD PARENT RELATIONSHIP_____ #
    id = db.Column(db.Integer, primary_key=True)
    # Create ForeignKey, 'users.id' the users refers to the table name of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the 'posts' refer to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    # Create reference to the Comment object, the 'parent_post' refer to the parent_post property in the Comment class.
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# TODO: Create Comment table for any users.
class Comment(db.Model):
    __tablename__ = "comments"

    # _____ ADD PARENT RELATIONSHIP_____ #
    id = db.Column(db.Integer, primary_key=True)
    # Create ForeignKey, 'users.id' the users refers to the table name of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the 'comments' refer to the comment property in the User class.
    comment_author = relationship("User", back_populates="comments")
    # Create ForeignKey, "blog_post.id" the comments refers to the table name of comment.
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # Create reference to the BlogPost Object, the "comments" refer to the comment property in the BlogPost class.
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


def admin_only(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        # If id is not 1 then return abort with 404 error.
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue withe the route function.
        return func(*args, **kwargs)

    return decorated_view


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route("/register", methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        # Check user email already present in the database.
        email = request.form.get("email")
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if user:
            # User already exist.
            flash("You have already signed up with that email")
            return redirect(url_for("login"))

        password = request.form.get("password")
        hashed_pws = generate_password_hash(password=password, salt_length=8)
        new_user = User(
            name=request.form.get("name"),
            email=email,
            password=hashed_pws,
        )
        db.session.add(new_user)
        db.session.commit()
        # This line will authenticate the user with Flask-login.
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template(
        "register.html", register_form=register_form, current_user=current_user
    )


# TODO: Retrieve a user from the database based on their email.
@app.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = request.form.get("email")
        password = request.form.get("password")
        # Note; Email in db is unique so will only have one result.
        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        # Email dose't exist
        if not user:
            flash("That email dose not exist, Pleas try again!")
            return redirect(url_for("login"))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, Pleas try again!")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("get_all_posts"))
    return render_template(
        "login.html", login_form=login_form, current_user=current_user
    )


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/")
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if comment_form.validate_on_submit():
        # Only allow logged in user to comment on post.
        if not current_user.is_authenticated:
            flash("You need to login or register to Comment.")
            return redirect(url_for("login"))
        new_comment = Comment(
            text=comment_form.body.data,
            comment_author=current_user,
            parent_post=requested_post,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template(
        "post.html",
        post=requested_post,
        current_user=current_user,
        form=comment_form,
    )


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            author=current_user,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template(
        "make-post.html", form=edit_form, is_edit=True, current_user=current_user
    )


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
