from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, get_jwt_identity, jwt_refresh_token_required)
from flask_sqlalchemy import SQLAlchemy
from marshmallow import fields, Schema
from passlib.hash import pbkdf2_sha256


app = Flask(__name__)
jwt = JWTManager(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'my-awesome-jwt-flask-project'
app.config['JWT_SECRET_KEY'] = 'super-jwt-top-secret-key'

db = SQLAlchemy(app)


class UserSchema(Schema):

    email = fields.Email(required=True)
    password = fields.Str(required=True)


class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

    def gen_hash(self):
        self.password = pbkdf2_sha256.hash(self.password)

    def verify_password(self, password):
        return pbkdf2_sha256.verify(password, self.password)


@app.route('/users', methods=['POST'])
def register():
    schema = UserSchema()    
    user_schema = schema.load(request.get_json()).data
    user = User(**user_schema)
    user.gen_hash()

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'message': 'User {} created!'.format(user.email)
    }), 201


@app.route('/auth/login', methods=['POST'])
def login():
    user_schema = UserSchema().load(request.get_json()).data
    user = User.query.filter_by(email=user_schema['email']).first()

    if user and user.verify_password(user_schema['password']):
        access_token = create_access_token(identity=user.email)
        refresh_token = create_refresh_token(identity=user.email)

        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'message': 'Success'
        }), 200
    
    return jsonify({
        'message': 'Bad credentials'
    }), 401


@app.route('/auth/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh_token():
    return jsonify({
        'access_token': create_access_token(identity=get_jwt_identity())
        }), 200


@jwt.unauthorized_loader
def missing_jwt(callback):
    return jsonify({
        'message': 'Authorization Header is Missing'
    }), 401


db.create_all()
app.run(debug=True)
