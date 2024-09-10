from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
import bcrypt
import os
from dotenv import load_dotenv
from cryptography.fernet import Fernet

load_dotenv()





app = Flask(__name__)
app.secret_key = os.urandom(24)


app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)


encryption_key = os.getenv("ENCRYPTION_KEY").encode()
cipher_suite = Fernet(encryption_key)




@app.route('/')
def home():
    if 'username' in session:
        user = mongo.db.users.find_one({'username': session['username']})
        
        user['phone'] = cipher_suite.decrypt(user['phone']).decode('utf-8')
        return render_template('home.html', user=user)
    return redirect(url_for('login'))






@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = mongo.db.users.find_one({'username': username})

        if user and bcrypt.checkpw(password.encode('utf-8'), user['passcode']):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')






@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        age = request.form['age']
        phone = request.form['phone']
        username = request.form['username']
        passcode = request.form['passcode']
        
        hashed_passcode = bcrypt.hashpw(passcode.encode('utf-8'), bcrypt.gensalt())
        
        if mongo.db.users.find_one({'username': username}):
            return 'Username already exists'

        encrypted_phone = cipher_suite.encrypt(phone.encode('utf-8'))
        
        mongo.db.users.insert_one({
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'age': age,
            'phone': encrypted_phone,
            'username': username,
            'passcode': hashed_passcode
        })
        return redirect(url_for('login'))
    return render_template('register.html')




@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False)
