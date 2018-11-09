from flask import Flask, render_template, session, request, redirect, flash
from mysqlconnection import connectToMySQL
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
from flask_bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
mysql = connectToMySQL('mydb')
app.secret_key = "ThisIsSecret!"


@app.route('/', methods = ['GET'])
def index():
    mysql = connectToMySQL('mydb')
    all_users = mysql.query_db('SELECT * FROM users')
    print('Fetched all users', all_users)
    return render_template('login.html', users = all_users)

@app.route('/register', methods = ['POST'])
def register():


    if len(request.form['first_name']) < 1:
        flash("Name cannot be blank!", 'first_name')
    elif len(request.form['first_name']) <= 2:
        flash("Name must be 2+ characters", 'first_name')

    if len(request.form['last_name']) < 1:
        flash("Name cannot be blank!", 'last_name')
    elif len(request.form['last_name']) <= 2:
        flash("Name must be 2+ characters", 'last_name')

    if len(request.form['email']) < 1:
        flash("Email cannot be blank!", 'email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!", 'email')
    
    if len(request.form['password']) < 1:
        flash("Password cannot be blank!", 'password')
    elif len(request.form['password']) < 8:
        flash("Password must be at least 8 characters!", 'password')

    if request.form['con_password'] != request.form['password']:
        flash('Password confirmation does not match Password', 'con_password')

    if '_flashes' in session.keys():
        return redirect("/")

    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        print(pw_hash)
        mysql = connectToMySQL("mydb")
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password_hash)s, NOW(), NOW());"
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password_hash': pw_hash
            }
        new_user_id = mysql.query_db(query, data)
        session["first_name"] = request.form['first_name']
        return redirect("/success")

@app.route('/login', methods = ['POST'])
def login():
	session["email"] = request.form["emaillogin"]
	session["password"] = request.form["passwordlogin"]

	if len(request.form['passwordlogin']) < 1:
		flash("Password cannot be blank.", "password")

	if len(request.form['emaillogin']) < 1:
		flash("Please input your email!", "email")

	else:
		mysql = connectToMySQL("mydb")
		query = "SELECT * FROM users WHERE email = %(email)s"
		data = {
			"email": request.form['emaillogin']
		}
		user = mysql.query_db(query, data)
		if not user:
			flash("Email not registered. Please register", "emaillogin")
		else:
			if not bcrypt.check_password_hash(user[0]['password'], request.form['passwordlogin']):
				flash("Incorrect Password", "passwordlogin")

	if '_flashes' in session.keys():
		return redirect("/")

	else:
		session["id"] = user[0]["id"]
		session["first_name"] = user[0]["first_name"]
		return redirect('/success')

@app.route('/success')
def success():
    return "Thank you " + session["first_name"] + ". You are now logged in!"

if __name__ == "__main__":
    app.run(debug=True)