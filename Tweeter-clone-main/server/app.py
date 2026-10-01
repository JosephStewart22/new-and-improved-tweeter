import os
import re
from datetime import timedelta

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from werkzeug.exceptions import HTTPException

from models import InvalidToken, Tweet, User, db
from security import checkpwd, encpwd


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.abspath(os.path.join(BASE_DIR, "../client/build"))

app = Flask(__name__, static_folder=BUILD_DIR, static_url_path="/")
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///twitter.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "change-this-secret-in-production"),
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=30),
    JWT_REFRESH_TOKEN_EXPIRES=timedelta(days=30),
)

db.init_app(app)
CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "*").split(",")}})
jwt = JWTManager(app)

with app.app_context():
    db.create_all()


@jwt.token_in_blocklist_loader
def is_token_revoked(_jwt_header, jwt_payload):
    return db.session.query(InvalidToken.id).filter_by(jti=jwt_payload["jti"]).first() is not None


def user_payload(user):
    return {"id": user.id, "username": user.username, "email": user.email, "createdAt": user.created_at.isoformat()}


def tweet_payload(tweet):
    return {
        "id": tweet.id,
        "title": tweet.title,
        "content": tweet.content,
        "createdAt": tweet.created_at.isoformat(),
        "user": user_payload(tweet.user),
    }


def error(message, status=400):
    return jsonify({"error": message}), status


@app.errorhandler(Exception)
def handle_unexpected(exc):
    if isinstance(exc, HTTPException):
        return exc
    app.logger.exception("Unhandled server error")
    return jsonify({"error": "Something went wrong on the server."}), 500


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("pwd", ""))
    if not email or not password:
        return error("Enter your email and password.")

    user = User.query.filter_by(email=email).first()
    if not user or not checkpwd(password, user.pwd):
        return error("Invalid email or password.", 401)

    return jsonify({
        "token": create_access_token(identity=user.id),
        "refreshToken": create_refresh_token(identity=user.id),
    })


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("pwd", ""))

    if not username or not email or not password:
        return error("Complete every field.")
    if len(username) < 2 or len(username) > 24 or not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return error("Username must be 2–24 characters and use only letters, numbers, or underscores.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return error("Enter a valid email address.")
    if len(password) < 8:
        return error("Password must be at least 8 characters.")
    if User.query.filter((User.email == email) | (User.username.ilike(username))).first():
        return error("That email or username is already in use.")

    user = User(username=username, email=email, pwd=encpwd(password))
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True}), 201


@app.post("/api/checkiftokenexpire")
@jwt_required()
def check_token():
    return jsonify({"success": True})


@app.post("/api/refreshtoken")
@jwt_required(refresh=True)
def refresh():
    return jsonify({"token": create_access_token(identity=get_jwt_identity())})


@app.post("/api/logout/access")
@jwt_required()
def logout_access():
    db.session.add(InvalidToken(jti=get_jwt()["jti"]))
    db.session.commit()
    return jsonify({"success": True})


@app.post("/api/logout/refresh")
@jwt_required(refresh=True)
def logout_refresh():
    db.session.add(InvalidToken(jti=get_jwt()["jti"]))
    db.session.commit()
    return jsonify({"success": True})


@app.get("/api/tweets")
def get_tweets():
    tweets = Tweet.query.order_by(Tweet.created_at.desc()).all()
    return jsonify([tweet_payload(tweet) for tweet in tweets])


@app.post("/api/addtweet")
@jwt_required()
def add_tweet():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    content = str(data.get("content", "")).strip()
    if not content:
        return error("Write something before posting.")
    if len(title) > 256 or len(content) > 2048:
        return error("Your post is too long.")

    user = db.session.get(User, get_jwt_identity())
    if not user:
        return error("Your account could not be found.", 404)
    tweet = Tweet(user=user, title=title, content=content)
    db.session.add(tweet)
    db.session.commit()
    return jsonify({"success": True, "tweet": tweet_payload(tweet)}), 201


@app.delete("/api/deletetweet/<int:tid>")
@jwt_required()
def delete_tweet(tid):
    tweet = db.session.get(Tweet, tid)
    if not tweet:
        return error("Post not found.", 404)
    if tweet.uid != get_jwt_identity():
        return error("You can only delete your own posts.", 403)
    db.session.delete(tweet)
    db.session.commit()
    return jsonify({"success": True})


@app.get("/api/getcurrentuser")
@jwt_required()
def get_current_user():
    user = db.session.get(User, get_jwt_identity())
    if not user:
        return error("User not found.", 404)
    return jsonify(user_payload(user))


@app.post("/api/changepassword")
@jwt_required()
def change_password():
    data = request.get_json(silent=True) or {}
    current = str(data.get("password", ""))
    new = str(data.get("npassword", ""))
    if not current or not new:
        return error("Enter both passwords.")
    if len(new) < 8:
        return error("New password must be at least 8 characters.")
    user = db.session.get(User, get_jwt_identity())
    if not user or not checkpwd(current, user.pwd):
        return error("Current password is incorrect.")
    user.pwd = encpwd(new)
    db.session.commit()
    return jsonify({"success": True})


@app.delete("/api/deleteaccount")
@jwt_required()
def delete_account():
    user = db.session.get(User, get_jwt_identity())
    if not user:
        return error("User not found.", 404)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"success": True})


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    if path.startswith("api/"):
        return error("Not found.", 404)
    index_path = os.path.join(BUILD_DIR, "index.html")
    if os.path.exists(index_path):
        return send_from_directory(BUILD_DIR, "index.html")
    return jsonify({"message": "Tweeter API is running. Build the React client to serve the web app."})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5555")), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
