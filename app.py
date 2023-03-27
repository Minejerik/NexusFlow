from flask import Flask, jsonify, make_response, request, redirect, render_template, url_for
import sys
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
from flaskext.markdown import Markdown
from sqlalchemy.inspection import inspect
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = '6012b733dee6fdc6dee94bfa23c2af1c'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///faceclone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
md = Markdown(
 app,
 extensions=['footnotes'],
)
db = SQLAlchemy(app)

def contains_sql_statement(input_string):
    sql_pattern = re.compile(r'\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|DROP)\b', re.IGNORECASE)
    match = sql_pattern.search(input_string)
    return match is not None

@app.context_processor
def inject_now():
	return {'now': datetime.utcnow()}


class Serializer(object):

	def serialize(self):
		return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

	@staticmethod
	def serialize_list(l):
		return [m.serialize() for m in l]


class Users(db.Model, Serializer):
	id = db.Column(db.Integer, primary_key=True)
	public_id = db.Column(db.Integer)
	badges = db.Column(db.Integer)
	bio = db.Column(db.String(150))
	name = db.Column(db.String(50))
	password = db.Column(db.String(50))
	pfpurl = db.Column(db.String(150))
	likedposts = db.Column(db.String())
	admin = db.Column(db.Boolean)

	def serialize(self):
		d = Serializer.serialize(self)
		del d['password']
		return d


class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	pub_id = db.Column(db.String(75))
	date_created = db.Column(db.DateTime, default=datetime.utcnow)
	content = db.Column(db.String(2000))
	parentpost = db.Column(db.Integer)
	creator = db.Column(db.String(50))
	subpost = db.Column(db.Integer)
	likes = db.Column(db.Integer)
	comments = db.Column(db.Integer)
	del_allow = db.Column(db.Boolean)
	edited = db.Column(db.Boolean)


with app.app_context():
	db.create_all()


@app.route('/register', methods=['POST', 'GET'])
def signup_user():
	if request.method == 'GET':
		return render_template('newlogin.html', log="register")
	else:
		data = request.form
		userlist = Users.query.filter_by(name=data['name']).first()
		if userlist:
			return render_template('login.html',
			                       log="register",
			                       error="User already exists")
		app.logger.info(data)
		hashed_password = generate_password_hash(data['password'], method='sha256')
		new_user = Users(public_id=str(uuid.uuid4()),
		                 name=data['name'],
		                 badges=0,
		                 bio="This is the test biography",
		                 password=hashed_password,
		                 pfpurl="https://placekitten.com/512/512",
		                 admin=False)
		db.session.add(new_user)
		db.session.commit()
		return redirect("/login")


def token_required(f):

	@wraps(f)
	def decorator(*args, **kwargs):
		token = request.cookies.get('token')
		if not token:
			return jsonify({'message': 'a valid token is missing'})
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
			current_user = Users.query.filter_by(public_id=data['public_id']).first()
		except Exception as e:
			return jsonify({'message': 'token is invalid', 'error': str(e)})

		return f(current_user, *args, **kwargs)

	return decorator


filters = ["<script>", "</script>", "<br>", "<", ">"]


def getuserfromtoken(token):
	if not token:
		return None
	try:
		data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
		current_user = Users.query.filter_by(public_id=data['public_id']).first()
		return current_user
	except:
		return None


@app.route('/api/createpost', methods=['POST'])
@token_required
def createpost(user):
	test = request.get_json()
	delable = True
	try:
		content = test['content']
		for filter in filters:
			if filter in content:
				content = f"This post by {user.name}, Did not pass the HTML filter"
				delable = False
		if contains_sql_statement(content):
			content = f"I {user.name}, tried to inject SQL into NexusFlow."
			delable = False
		new_post = Posts(pub_id=str(uuid.uuid4()),
		                 content=content,
		                 creator=test['creator'],
		                 parentpost=test['parentpost'],
		                 subpost=test['subpost'],
		                 likes=0,
		                 comments=0,
										del_allow = delable)
		db.session.add(new_post)
		db.session.commit()
	except Exception as e:
		return jsonify({'error': str(e)})
	return jsonify({"error": False, "id": new_post.pub_id})


@app.route('/p/<string:post_id>')
def getpost(post_id):
	try:
		post = Posts.query.filter_by(pub_id=post_id).first()
		create = Users.query.filter_by(public_id=post.creator).first()
		post = post.__dict__
		create = create.__dict__
		time = post['date_created'].strftime("%Y-%m-%d %H:%M:%S")
		return render_template('postview.html', post=post, create=create, time=time)
	except Exception as e:
		return "Unknown Post<br>" + str(e)


@app.route('/')
def maintemp():
	temp = Posts.query.all()
	posts = []
	creates = []
	for post in temp:
		posts.append(post.__dict__)
		create = Users.query.filter_by(public_id=post.creator).first()
		creates.append(create)
	myuser = getuserfromtoken(request.cookies.get('token'))
	if myuser == None:
		myuser = {}
	return render_template('index.html',
	                       posts=posts,
	                       creates=creates,
	                       myuser=myuser)



@app.route('/api/deletepost', methods=['POST'])
@token_required
def deletepost(user):
	test = request.form
	try:
		post = Posts.query.filter_by(pub_id=test['id']).first()
		if post.del_allow == False:
			return jsonify({"error": True})
		db.session.delete(post)
		db.session.commit()
		return jsonify({"error": False})
	except Exception as e:
		return jsonify({"error": str(e)})

@app.route('/api/like', methods=['POST'])
@token_required
def likepost(user):
	test = request.form
	try:
		if test['id'] not in str(user.likedposts).split(','):
			post = Posts.query.filter_by(pub_id=test['id']).first()
			if post.creator == user.public_id:
				return jsonify({"error": False})
			post.likes = int(post.likes) + 1
			user.likedposts = str(user.likedposts) + "," + str(test['id'])
			db.session.commit()
			return jsonify({"error": False})
		else:
			post = Posts.query.filter_by(pub_id=test['id']).first()
			if post.creator == user.public_id:
				return jsonify({"error": False})
			post.likes = int(post.likes) - 1
			user.likedposts = str(user.likedposts).replace("," + str(test['id']), '')
			db.session.commit()
			return jsonify({"error": False})
	except Exception as e:
		return jsonify({"error": str(e)})


# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST':
		auth = request.form
		user = Users.query.filter_by(name=auth['name']).first()
		if not user:
			return jsonify({"correct": False})
		if check_password_hash(user.password, auth['password']):
			token = jwt.encode(
			 {
			  'public_id': user.public_id,
			  'exp': datetime.utcnow() + timedelta(minutes=240)
			 }, app.config['SECRET_KEY'], 'HS256')
			ret = make_response(jsonify({"correct": True, "token": token}))
			ret.set_cookie('token', token)
			print('YIPPE')
			return ret
		print('bad')
		return jsonify({"correct": False})
	else:
		return render_template('newlogin.html', error=error, log="login")


@app.route('/admin')
@token_required
def admin(user):
	if not user or user.admin == False:
		return "Not Found", 404
	else:
		return render_template('admin.html', user=user.__dict__)


@app.route("/home")
def home():
	return redirect('')


badgelist = {
 "0": "User",
 '1': "Admin",
 '2': "Owner",
 '3': "Veteran",
 '4': "Beta-Tester"
}


@app.route('/api/getsettings')
@token_required
def getsettings(current_user):
	return jsonify({"name": current_user.name,"bio": current_user.bio,"pfpurl": current_user.pfpurl})


@app.route('/settings')
@token_required
def settings(user):
	return render_template('settings.html',myuser=user)


@app.route('/u/<string:user>')
def showuser(user):
	userlist = Users.query.filter_by(name=user).first()
	if not userlist:
		return f"User {user}: not found"
	return render_template('user.html',
	                       user=userlist,
	                       badges=[*str(userlist.badges)],
	                       badgelist=badgelist)

@app.route('/api/setsettings', methods=['POST'])
@token_required
def setsettings(user):
	try:
		test = request.json
		user.name = test['name']
		user.bio = test['bio']
		if test['password'] != None and test['password'] != '':
			user.password = generate_password_hash(test['password'], method='sha256')
		db.session.commit()
		return jsonify({"error": False})
	except Exception as e:
		return jsonify({"error": str(e)})


@app.route('/api/getid')
def getid():
	token = request.cookies.get('token')
	if not token:
		return jsonify({"userid": False})
	try:
		data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
		current_user = Users.query.filter_by(public_id=data['public_id']).first()
		id = current_user.public_id
	except Exception as e:
		return jsonify({"userid": False, 'error': str(e)})
	return jsonify({"userid": id})

@app.route('/api/getpost', methods=['POST'])
@token_required
def getpostcontent(user):
	id = request.form['id']
	post = Posts.query.filter_by(pub_id=id).first()
	if not post:
		return jsonify({"error": True,"post":"post not found"})
	return jsonify({"error": False, "post": post.content})

@app.route('/api/editpost', methods=['POST'])
@token_required
def editpost(user):
	id = request.form['id']
	content = request.form['content']
	post = Posts.query.filter_by(pub_id=id).first()
	if not post:
		return jsonify({"error": True})
	post.content = content
	post.edited = True
	db.session.commit()
	return jsonify({"error": False})

@app.route('/post/create')
@token_required
def postcreate(user):
	token = request.cookies.get('token')
	if not token:
		return redirect("/login")
	try:
		jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
	except:
		return redirect('/login')
	return render_template('post_create.html',myuser = user)


@app.route('/header')
def header():
	myuser = getuserfromtoken(request.cookies.get('token'))
	if myuser == None:
		myuser = {}

	return render_template('header.html', user=myuser)

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=81, debug=True)
