from flask import Flask, render_template, redirect, send_file, session 
from flask import url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename

app = Flask(__name__) #app instance
db = SQLAlchemy(app) #databse instance
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' #connectes the app file to the database 
app.config['SECRET_KEY'] = 'thisisasecretkey' #secret key is used to secure the session cookie

login_manager = LoginManager() #allows the app and flask login to handle things when logging in, by loading users and their attributes
login_manager.init_app(app)
login_manager.login_view = 'login'

#used to reload the user object from the user id stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#User table for the database which stores user attributes which are User id,username,password
class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(20), nullable=False, unique=True) #username has a max of 20 char, has to befilled in to register and cannot have 2 or more usernames that are the same.
        password = db.Column(db.String(80), nullable=False) #passwaord has a max of 80 char once it has been hashed, has to be filled in to register

#creates a username input field where input is mandatory to register, with a min and max of 4 and 20 char, with a default placeholder name of "username"
#creates a password input field where input is mandatory and disgused as black dots. Has a min and max of 4 and 20 char before hashing, with a default placeholder name of "password"
class RegisterForm(FlaskForm):

    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register') #register button

    #validates whether or not if there is a username that is similar to the one typed in
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first() #querys the User database table by the username to check if there is a similar username
        if existing_user_username: #if there is a similar username it will raise a validation error
            raise ValidationError('That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
        return render_template('home.html') #returns the content inside the home.html file

@app.route('/login', methods=['GET','POST'])
def login():
        form = LoginForm()
        if form.validate_on_submit():
                user = User.query.filter_by(username=form.username.data).first() #first query the users to check if registered
                if user:
                        if bcrypt.check_password_hash(user.password, form.password.data): #if registered , checks if password in form matches password in the database
                                login_user(user) #if they do match login the user
                                return redirect(url_for('dashboard'))
        return render_template('login.html', form = form) #creates a form variable in the html template 


@app.route('/logout', methods=['GET', 'POST'])
@login_required #can only logout if logged in.
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required #can only access the dashboard if logged in
def dashboard(): 
        return render_template('dashboard.html') 


@app.route('/register', methods=['GET','POST'])
def register():
        form = RegisterForm()
        if form.validate_on_submit():
                hashed_password = bcrypt.generate_password_hash(form.password.data) #hashes the supplied input so that registration process is secure.
                new_user = User(username=form.username.data, password=hashed_password)
                db.session.add(new_user) #add the new user to databse
                db.session.commit()
                return redirect(url_for('login'))
        return render_template('register.html', form = form)   

#app = Flask(__name__) #app instance
app.secret_key = 'xyz'
app.config['UPLOAD_FOLDER'] = './uploads/'
app.config['ALLOWED_EXTENSIONS'] = set(['txt','py', 'docx', 'csv','pdf']) 

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

#@app.route('/')
#def dashboard(): 
        #return render_template('dashboard.html') 


# handle 'make directory' command
@app.route('/md')
def md():
    # create new folder
    folders= os.mkdir(request.args.get('folder'))
    #foldername = secure_filename(folders.filename)
    foldernames = []
    foldernames.append(folders)
    session['foldernames'] = foldernames
    return render_template('dashboard.html', foldernames=foldernames)

    

@app.route('/download')
def download():
   return send_file('3-prototype.pdf', as_attachment=True)  #sends file to user

app.config['UPLOAD_FOLDER'] = 'upload' 
@app.route('/upload', methods = ['GET', 'POST'])
def uploadfile():
   if request.method == 'POST': # check method
      files = request.files.getlist("file_list[]")# get the file 
      filenames = []
      
      for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            filenames.append(filename)
            
    # This line is essential, store the data in session
      session['filenames'] = filenames
      return render_template('dashboard.html', filenames=filenames)


if __name__ == '__main__':
        app.run(debug=True) 

#references
#Arpan Neupane (13 march 2021) Python Flask Authentication Tutorial - Learn Flask Login https://www.youtube.com/watch?v=71EU8gnZqZQ               