import jwt
from flask import Flask, request, jsonify, make_response, render_template, redirect, url_for, session   
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import datetime
from functools import wraps
import os
import os.path

app = Flask(__name__) 

package_dir = os.path.abspath(os.path.dirname(__file__))
# database_path = os.path.join(package_dir, 'AndroidFileTransfer.db')
db_path = os.path.join(os.path.dirname(__file__), 'AndroidFileTransfer.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SECRET_KEY']='Th1s1ss3cr3t'
app.config['SQLALCHEMY_DATABASE_URI']=db_uri 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True 

db = SQLAlchemy(app)   

# encoded = jwt.encode({"some": "payload"}, app.config['SECRET_KEY'], algorithm="HS256")
# print(encoded)
# decode = jwt.decode(encoded, app.config['SECRET_KEY'], algorithms=["HS256"])
# print(decode)

class Users(db.Model):  
  id = db.Column(db.Integer, primary_key=True)
  public_id = db.Column(db.Integer)  
  name = db.Column(db.String(50))
  password = db.Column(db.String(50))
  admin = db.Column(db.Boolean)


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']

        if not token:
            return jsonify({'message': 'a valid token is missing', 'tokennya':token})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(public_id=data['public_id']).first()
            # return jsonify({'message': current_user.name})
        except:
            return jsonify({'message': 'token is invalid'})

        return f(current_user, *args, **kwargs)
    return decorator

def web_token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = session.get('login')

        if not token:
            return redirect(url_for('wrong'))
        else:
            try:
                # token = session.get('login')
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = Users.query.filter_by(public_id=data['public_id']).first()
                # return jsonify({'message': current_user.name})
            except:
                return redirect(url_for('wrong'))

            return f(current_user, *args, **kwargs)
    return decorator


@app.route('/api/register', methods=['GET', 'POST'])
def signup_user():  
 data = request.get_json()  

 hashed_password = generate_password_hash(data['password'], method='sha256')
 
 new_user = Users(public_id=str(uuid.uuid4()), name=data['username'], password=hashed_password, admin=False) 
 db.session.add(new_user)  
 db.session.commit()    

 return jsonify({'message': 'registered successfully'})   

@app.route('/register', methods=['GET', 'POST'])
def signup_user_web():  
    if request.method == 'POST':
        usernames = request.form['username']
        passwords = request.form['password']
        user = Users.query.filter_by(name=usernames).first()   
        if usernames or passwords:  
            hashed_password = generate_password_hash(passwords, method='sha256')
            new_user = Users(public_id=str(uuid.uuid4()), name=usernames, password=hashed_password, admin=False) 
            db.session.add(new_user)  
            db.session.commit()    
            return redirect(url_for('login'))
        
    error = "invalid username and password"    
        
    return render_template('register.html', error=error)
  

# Route for handling the login page logic
@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.form.get("username", None) or request.form.get("password", None):
        usernames = request.form['username']
        passwords = request.form['password']
        user = Users.query.filter_by(name=usernames).first()
        if user:   
            if check_password_hash(user.password, passwords):
                token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
                session['login'] = token
                tokensess = session.get('login')
                return redirect(url_for('visits'))
        
        error = "invalid username and password"    
        
    return render_template('index.html', error=error)




@app.route('/api/login', methods=['POST'])  
def login_user(): 
    auth = request.authorization   
    msg = jsonify({'message': 'Wrong Authentication'})      
    if not auth or not auth.username or not auth.password:
        return make_response(msg, 401, {'WWW.Authentication': 'Basic realm: "login required"'})    

    user = Users.query.filter_by(name=auth.username).first()   
    if user :

        if check_password_hash(user.password, auth.password):  
            token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'token' : token})
    return make_response(msg,  401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):  
   
   users = Users.query.all() 

   result = []   

   for user in users:   
       user_data = {}   
       user_data['public_id'] = user.public_id  
       user_data['name'] = user.name 
       user_data['password'] = user.password
       user_data['admin'] = user.admin 
       
       result.append(user_data)   

   return jsonify({'users': result})  


@app.route('/users/<name>', methods=['DELETE'])
@token_required
def delete_user(current_user, name):  
    if not current_user:   
       return jsonify({'message': 'user id not exist or you must login again'})

    user = Users.query.filter_by(name=name, id=current_user.id).first()   
    if not user:   
       return jsonify({'message': 'user does not exist'})   


    db.session.delete(user)  
    db.session.commit()   

    return jsonify({'message': 'User deleted'})


@app.route('/visits', methods=['GET'])
@web_token_required
def visits(current_user):
    nama = current_user.name
    users = Users.query.all()
    result = []   

    for user in users:   
        user_data = {}   
        user_data['Username'] = user.name 
        user_data['admin'] = user.admin 
        result.append(user_data)    
    return render_template('home.html', name=nama, len = len(result), Userdata = result)


@app.route('/wrong', methods=['GET'])
def wrong():
    return render_template('wrong.html')

@app.route('/proccess')
def proccess():
    stream = os.popen('runCxConsole.cmd Scan -v -ProjectName "CxServer\dariapi" -CxServer http://localhost -cxuser ari3f -cxpassword #1sasajiMu -locationtype folder -locationpath "C:\work\project\webapi_file_and_presentation\itsec" -preset "Checkmarx Default"')
    output = stream.read()
    return output
#    session.pop('login', None)
#    return redirect(url_for('login'))


@app.route('/logout')
def logout():
   session.pop('login', None)
   return redirect(url_for('login'))

if  __name__ == '__main__':  
     app.run(debug=True) 