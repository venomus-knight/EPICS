# from flask import Flask, render_template, redirect, url_for,session,flash,Response
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import DataRequired, Email
# import bcrypt
# from flask_mysqldb import MySQL
# import cv2
# from tensorflow.keras.models import load_model
# import numpy as np


# app = Flask(__name__)
# model = load_model(r'C:\Users\Dell\Documents\Python\EPICS\Crime_Detection_Model\finalmodel.h5')  # Crime detection model


# #Camera Connection
# CAMERA_URL = 0

# camera = cv2.VideoCapture(CAMERA_URL)  

# if not camera.isOpened():
#     print("Cannot open camera")
#     exit()


# def generate_frames():
#     while True:
#        success, frame = camera.read()
#        if label == "Violence Detected":
#         cursor = mysql.connection.cursor()
#         cursor.execute("INSERT INTO events (user_id, label) VALUES (%s, %s)", (session.get('user_id'), label))
#         mysql.connection.commit()
#         cursor.close()

#        if not success:
#             break
#        else:
#             # Resize and preprocess the frame (adjust according to your model's training!)
#             input_frame = cv2.resize(frame, (64, 64))  # Adjust size to match training input
#             input_frame = input_frame / 255.0            # Normalize if trained this way
#             input_frame = np.expand_dims(input_frame, axis=0)

#             # Make prediction
#             prediction = model.predict(input_frame)
#             label = "Violence Detected" if prediction[0][0] > 0.5 else "Safe"

#             # Display label on the frame
#             color = (0, 0, 255) if label == "Violence Detected" else (0, 255, 0)
#             cv2.putText(frame, label, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)

#             # Encode and yield frame
#             _, buffer = cv2.imencode('.jpg', frame)
#             frame = buffer.tobytes()

#             yield (b'--frame\r\n'
#                    b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            
# # Database connection
# app.config['MYSQL_HOST'] = 'localhost'  
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'test1'
# app.secret_key = 'MYKEY'

# mysql = MySQL(app)

# # Registration form
# class RegisterForm(FlaskForm):
#     name = StringField("Name", validators=[DataRequired()])
#     email = StringField("Email", validators=[DataRequired(), Email()])
#     password = PasswordField("Password", validators=[DataRequired()])  # Changed to PasswordField
#     submit = SubmitField("Register")

# class LoginForm(FlaskForm):
#     email = StringField("Email", validators=[DataRequired(), Email()])
#     password = PasswordField("Password", validators=[DataRequired()])  # Changed to PasswordField
#     submit = SubmitField("Login")

# # Define routes



# @app.route('/')
# def home():
#     return render_template("home.html")

# @app.route('/login',methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         email = form.email.data
#         password = form.password.data

#         #hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

#         cursor = mysql.connection.cursor()
#         cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
#         user = cursor.fetchone()
#         cursor.close()
#         if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
#             session['user_id']=user[0]
#             return redirect(url_for('dashboard')) 
#         else:
#             flash('Login Unsuccessful. Please check email and password', 'danger')
#             # return redirect(url_for('login'))

#     return render_template('login.html', form=form)

# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     form = RegisterForm()
#     if form.validate_on_submit():
#         name = form.name.data
#         email = form.email.data
#         password = form.password.data

#         hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

#         cursor = mysql.connection.cursor()
#         cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
#         existing_user = cursor.fetchone()
#         if existing_user:
#             cursor.close()
#             return "User already exists!", 400  

#         cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
#         mysql.connection.commit()
#         cursor.close()

#         return redirect(url_for('login'))

#     return render_template('signup.html', form=form)

# @app.route('/dashboard', methods=['GET', 'POST'])
# def dashboard():
#     if 'user_id' in session:
#         user_id=session['user_id']
#         cursor = mysql.connection.cursor()
#         cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
#         user = cursor.fetchone()
#         cursor.close()
#         if user:
#             return render_template('dashboard.html', user=user)
#     return redirect(url_for('login')) 

# @app.route('/video_feed')
# def video_feed():
#     return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

# @app.route('/logout')
# def logout():
#     session.pop('user_id',None)
#     flash('You have been logged out succesfully')
#     return redirect(url_for('login'))

# if __name__ == '__main__':
#     app.run(debug=True)

from flask import Flask, render_template, redirect, url_for, session, flash, Response , request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import bcrypt
from flask_mysqldb import MySQL
import cv2
from tensorflow.keras.models import load_model
import numpy as np
import time , telepot ,pytz , requests 
from datetime import datetime
from collections import deque


app = Flask(__name__)
model = load_model(r'C:\Users\Dell\Documents\Python\EPICS\Crime_Detection_Model\finalmodel.h5')  # Crime detection model
Q = deque(maxlen=128)
bot = telepot.Bot("7911172290:AAEp6Ar4OW5mQ04g6mDjgJDcKjm0YX2U1RM")
chat_id = -1002448977692

def send_telegram_alert(message):
    BOT_TOKEN = '7911172290:AAEp6Ar4OW5mQ04g6mDjgJDcKjm0YX2U1RM'
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message
    }
    try:
        response = requests.get(url, params=payload)
        if response.status_code != 200:
            print("Failed to send alert:", response.text)
    except Exception as e:
        print("Telegram alert error:", e)
def getTime():
    IST = pytz.timezone('Asia/Kolkata')
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")

# Camera Connection
CAMERA_URL = 0
camera = cv2.VideoCapture(CAMERA_URL)  
if not camera.isOpened():
    print("Cannot open camera")
    exit()

last_logged = 0  # To avoid repeated logs

def test_video_for_violence(video_path, model_path):
    model = load_model(model_path)
    Q = deque(maxlen=128)
    trueCount = 0

    cap = cv2.VideoCapture(video_path)
    while True:
        ret, frame = cap.read()
        if not ret:
            break

        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        frame = cv2.resize(frame, (128, 128)).astype("float32") / 255.0
        frame = frame.reshape(128, 128, 3)

        preds = model.predict(np.expand_dims(frame, axis=0))[0]
        Q.append(preds)

        results = np.array(Q).mean(axis=0)
        violence = (results > 0.5)[0]
        if violence:
            trueCount += 1
  
    cap.release()

    # Set a threshold like 10+ violent frames to consider it "True Violence"
    if trueCount > 10:
        print("🚨 Violence Detected!")
        
        return True
    else:
        print("✅ No Violence Detected.")
        return False
   
def generate_frames():
   # camera = cv2.VideoCapture(0)
    trueCount = 0
    sendAlert = 0
    imageSaved = 0

    while True:
        success, frame = camera.read()
        if not success:
            break
        else:
            # Preprocess frame
            output = frame.copy()
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            resized_frame = cv2.resize(rgb_frame, (128, 128)).astype("float32") / 255.0

            # Prediction
            preds = model.predict(np.expand_dims(resized_frame, axis=0))[0]
            Q.append(preds)
            results = np.array(Q).mean(axis=0)
            label = (results > 0.5)[0]

            color = (0, 255, 0)
            if label:
                color = (0, 0, 255)
                trueCount += 1

            # Draw label
            text = "Violence: {}".format(label)
            cv2.putText(output, text, (10, 40), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)

            # Trigger alert
            if trueCount >= 50 and sendAlert == 0:
                timestamp = getTime()
                filename = 'alert_frame.jpg'
                cv2.imwrite(filename, output)

                try:
                    bot.sendMessage(chat_id, f"⚠️ VIOLENCE DETECTED!\n🕒 Time: {timestamp}\n📍 Location: Delhi NCR")
                    bot.sendPhoto(chat_id, photo=open(filename, 'rb'))
                    send_telegram_alert(f"Violence detected{filename}at{datetime.now()}")
                    sendAlert = 1
                except Exception as e:
                    print("Telegram alert error:", e)

            # Encode for streaming
            ret, buffer = cv2.imencode('.jpg', output)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    camera.release()
app.config['MYSQL_HOST'] = 'localhost'  
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'test1'
app.secret_key = 'MYKEY'

mysql = MySQL(app)

# Registration form
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

# Define routes
@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    print("Form submitted:", form.is_submitted())
    print("Form validated:", form.validate_on_submit())
    if request.method == 'POST':
        print("Errors:", form.errors)
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        print("Email:", email)

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            print("User found in database")
            if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                print("Password matched")
                session['user_id'] = user[0]
                return redirect(url_for('dashboard'))
            else:
                print("Incorrect password")
        else:
            print("No user found with this email")

        flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            return "User already exists!", 400  

        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('signup.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            return render_template('dashboard.html', user=user)
    return redirect(url_for('login')) 

@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out successfully')
    return redirect(url_for('login'))
@app.route('/detect')
def detect_violence():
    video_path = r"C:\Users\Dell\Documents\Python\EPICS\Crime_Detection_Model\V_116.mp4"
    model_path = r'C:\Users\Dell\Documents\Python\EPICS\Crime_Detection_Model\finalmodel.h5'

    # Run detection
    result = test_video_for_violence(video_path, model_path)

    # Pass result to dashboard
    return render_template("dashboard.html", detection_result=result)

@app.route('/crime-map')
def crime_map():
   return render_template("crime_heatmap.html")
 
if __name__ == '__main__':
    app.run(debug=True)

