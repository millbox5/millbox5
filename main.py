from flask import Flask, flash, jsonify, render_template, request, redirect, url_for, session
from flask_session import Session
import os
import requests
from werkzeug.utils import secure_filename
import db
import jwt
from datetime import datetime
import firebase_admin
from firebase_admin import credentials
from firebase_admin import messaging

app = Flask(__name__)
app.template_folder = "statics"
app.static_folder = "static"
cred = credentials.Certificate("app.json")
firebase_admin.initialize_app(cred)

# Set the folder to store uploaded images
UPLOAD_FOLDER = 'uploads'

# Ensure the upload folder exists, create it if it doesn't
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Configure session to use filesystem (you can change it to use other storage options)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SECRET_KEY'] = "0790467621"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # Set the UPLOAD_FOLDER configuration

Session(app)

# Ensure the allowed extensions for file upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Check if a filename has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    

# Send OTP via InTouch SMS API
def send_otp_via_sms(phone, otp):
    username = "millbox"
    password = "kalilinux"
    sms_data = {
        'recipients': phone,
        'message': f'Your OTP for password reset is: {otp}',
        'sender': 'KacaFix'
    }
    r = requests.post(
        'https://www.intouchsms.co.rw/api/sendsms/.json',
        data=sms_data,
        auth=(username, password)
    )
    return r.json(), r.status_code

# Send OTP via InTouch SMS API
def garagesms(phone, otp,code):
    username = "millbox"
    password = "kalilinux"
    sms_data = {
        'recipients': phone,
        'message': f'Code: {otp} Igaraje ryanyu ryandikishijwe umubare w`ibanga ni: {code}',
        'sender': 'KacaFix'
    }
    r = requests.post(
        'https://www.intouchsms.co.rw/api/sendsms/.json',
        data=sms_data,
        auth=(username, password)
    )
    return r.json(), r.status_code

# Send OTP via InTouch SMS API
def welcome_message(phone, otp):
    username = "millbox"
    password = "kalilinux"
    sms_data = {
        'recipients': phone,
        'message': f'Konti yanyu yafunguwe umubare wibanga ni {otp} Murakoze. \n Your account was created succefully your account pin is {otp} Thanks !',
        'sender': 'KacaFix'
    }
    r = requests.post(
        'https://www.intouchsms.co.rw/api/sendsms/.json',
        data=sms_data,
        auth=(username, password)
    )
    return r.json(), r.status_code

# Send OTP via InTouch SMS API
def reset_pin_password(phone, otp):
    username = "millbox"
    password = "kalilinux"
    sms_data = {
        'recipients': phone,
        'message': f'Umubare w`ibanga wahinduwe pin code ni: {otp} Murakoze. \n Your account password was reseted successfully',
        'sender': 'KacaFix'
    }
    r = requests.post(
        'https://www.intouchsms.co.rw/api/sendsms/.json',
        data=sms_data,
        auth=(username, password)
    )
    return r.json(), r.status_code

def reset_pin_send(phone2, otp):
    username = "millbox"
    password = "kalilinux"
    sms_data = {
        'recipients': phone2,
        'message': f'Umubare wibanga mushaya {otp} wubike neza  Your pin was changed successfully reset is: {otp}',
        'sender': 'KacaFix'
    }
    r = requests.post(
        'https://www.intouchsms.co.rw/api/sendsms/.json',
        data=sms_data,
        auth=(username, password)
    )
    return r.json(), r.status_code

@app.route('/reset_pin', methods=['POST'])
def reset_pin():
    data = request.get_json()
    phone_number = data.get('phone_number')

    new_pin = ''.join([str(random.randint(0, 9)) for _ in range(4)])
    reset_pin_send(phone_number,new_pin)
    reset = "update garages set pin = %s where id = %s"
    db.cursor.execute(reset,(new_pin,phone_number))
    db.db_connection.commit()

    return jsonify({'message': 'New PIN code generated and sent successfully.'})

@app.route('/garagepin', methods=['POST'])
def verify_code():
    data = request.get_json()
    phone_number = data.get('phoneNumber')
    code = data.get('code')

    db.cursor.execute("SELECT pin FROM garages WHERE id=%s", (phone_number,))
    stored_code = db.cursor.fetchone()

    if stored_code and stored_code[0] == code:
        return jsonify({'message': 'good'}), 200
    else:
        return jsonify({'message': 'bad'}), 400

@app.route('/driverpin', methods=['POST'])
def verify_code22():
    data = request.get_json()
    phone_number = data.get('phoneNumber')
    code = data.get('code')

    db.cursor.execute("SELECT pin FROM users WHERE phone=%s", (phone_number,))
    stored_code = db.cursor.fetchone()

    if stored_code and stored_code[0] == code:
        return jsonify({'message': 'good'}), 200
    else:
        return jsonify({'message': 'bad'}), 400

@app.route('/api/add_garage', methods=['POST'])
def add_garage():
    if request.method == 'POST':
        province = request.form['province']
        district = request.form['district']
        sector = request.form['sector']
        cell = request.form['cell']
        village = request.form['village']
        name = request.form['name']
        lon = request.form['lon']
        lat = request.form['lat']
        phone = request.form['phone']
        fctoken = request.form['fcm_token']
        random_otp = str(random.randint(100000, 999999))
        code = ''.join([str(random.randint(0, 9)) for _ in range(4)])

        if 'image' in request.files:
            image = request.files['image']
            if image.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if image and allowed_file(image.filename):
                filename = "pop"
            else:
                flash('Invalid file format')
                return redirect(request.url)
        else:
            image_path = None

        checkuserexist = "SELECT id FROM garages WHERE id = %s"
        db.cursor.execute(checkuserexist, (phone,))
        db.db_connection.commit()
        garage_exist = db.cursor.fetchone()

        if garage_exist:
            return jsonify({'message': 'Garage already exists'}), 201
        else:
            sql = "INSERT INTO garages (id, province, district, sector, cell, village, name, image, lon, lat, otp,fcm_token,pin) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s)"
            val = (phone, province, district, sector, cell, village, name, image_path, lon, lat, random_otp,fctoken,code)
            db.cursor.execute(sql, val)
            db.db_connection.commit()
            garagesms(phone, random_otp,code)

            return jsonify({'message': 'Garage added successfully'}), 201

@app.route('/get_garages', methods=['POST'])
def get_garages():
    district = request.json.get('district')

    db.cursor.execute("SELECT `id`, `province`, `district`, `sector`, `cell`, `village`, `name`, `image`, `lon`, `lat`, `otp`, `status`,`fcm_token` FROM  `garages`  WHERE `district` = %s", (district,))
    garages = db.cursor.fetchall()
    db.db_connection.commit()

    garage_list = []

    for garage in garages:
        garage_dict = {
            'id': garage[0],
            'province': garage[1],
            'district': garage[2],
            'sector': garage[3],
            'cell': garage[4],
            'village': garage[5],
            'name': garage[6],
            'image': garage[7].decode('utf-8'),
            'lon': garage[8],
            'lat': garage[9],
            'otp': garage[10],
            'status': garage[11],
            'fcm_token':garage[12]
        }
        garage_list.append(garage_dict)

    return jsonify({'garages': garage_list})

@app.route('/api/garage_otp', methods=['POST'])
def verify_otp():
    if request.method == 'POST':
        phone = request.form['phone']
        otp = request.form['otp']

        db.cursor.execute("SELECT otp FROM garages WHERE id = %s", (phone,))
        garage_otp = db.cursor.fetchone()

        if garage_otp and garage_otp[0] == otp:
            db.cursor.execute("UPDATE garages SET otp = '0' WHERE id = %s", (phone,))
            db.db_connection.commit()
            return jsonify({'message': 'OTP code verified successfully'}), 200
        else:
            return jsonify({'message': 'Invalid OTP code or expired'}), 400

def generate_otp():
    return str(random.randint(100000, 999999))

def store_otp(phone, otp):
    try:
        db.cursor.execute("UPDATE users SET otp = %s WHERE phone = %s", (otp, phone))
        db.db_connection.commit()
    except Exception as e:
        print("Error storing OTP:", e)

@app.route("/api/request-password-reset", methods=["POST"])
def request_password_reset():
    data = request.json
    phone = data.get("phone")

    db.cursor.execute("SELECT phone FROM users WHERE phone = %s", (phone,))
    user = db.cursor.fetchone()
    db.db_connection.commit()

    if user:
        otp = generate_otp()
        store_otp(phone, otp)

        sms_response, sms_status_code = send_otp_via_sms(phone, otp)

        if sms_status_code == 200:
            return jsonify({"message": "OTP sent successfully"}), 200
        else:
            return jsonify({"error": "Failed to send OTP via SMS"}), sms_status_code
    else:
        return jsonify({"error": "User notfound"}), 404

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    phone = data.get("phone")
    otp = data.get("otp")
    new_password = data.get("new_password")

    db.cursor.execute("SELECT phone FROM users WHERE phone = %s AND otp = %s", (phone, otp))
    user = db.cursor.fetchone()
    db.db_connection.commit()

    if user:
        try:
            db.cursor.execute("UPDATE users SET password = %s, otp = NULL WHERE phone = %s", (new_password, phone))
            db.db_connection.commit()
            return jsonify({"message": "Password reset successful"}), 200
        except Exception as e:
            print("Error resetting password:", e)
            return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": "Invalid OTP"}), 401

@app.route('/users', methods=['GET'])
def get_users():
    try:

        db.cursor.execute("SELECT * FROM `garages` where status =1 ")
        users = db.cursor.fetchall()
        db.db_connection.commit()

        users_list = []
        for user in users:
            user_dict = {
                'id': user[0],
                'phone': user[1],
                'status': user[4],
                'fcm_token': user[12],
                'lon': user[8],
                'lat': user[9]
            }
            users_list.append(user_dict)

        return jsonify(users_list)

    except Exception as e:
        return jsonify({'error': str(e)})

def send_fcm_message(token, title, body):
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=token,
    )

    response = messaging.send(message)
    print("Successfully sent message:", response)

@app.route('/send-fcm-message', methods=['POST'])
def send_message_fcm():
    data = request.json
    if 'token' not in data :
        return jsonify({'error': 'Token are required.'}), 400

    token = data['token']
    title = 'AndroidChatController'
    body = 'Refresh App'

    send_fcm_message(token, title, body)

    return jsonify({'message': 'FCM message sent successfully.'})

@app.route("/register", methods=["POST"])
def register():
    if request.method == "POST":
        try:
            data = request.json
            phone = data.get("phone")
            password = data.get("password")
            fcm_token = data.get("fcm_token")

            sql = "INSERT INTO users (phone, password, fcm_token) VALUES (%s, %s, %s)"
            db.cursor.execute(sql, (phone, password, fcm_token))
            db.db_connection.commit()

            welcome_message(phone, '1234')

            return jsonify({"message": "User registered successfully"}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    phone_number = data.get('phone')
    password = data.get('password')

    # Execute SQL query to validate user credentials
    db.cursor.execute("SELECT * FROM users WHERE phone = %s AND password = %s", (phone_number, password))
    users = db.cursor.fetchall()  # Fetch all rows

    if not users:
        return jsonify({'message': 'Invalid phone number or password'}), 401

    # Assuming user_id is the first column in the user table
    user_id = users[0][0]  # Select the user_id from the first row

    # Set user_id in the session
    session['user_id'] = user_id
    
    db.db_connection.commit()

    return jsonify({'message': 'Login successful'}), 200






@app.route('/send_message', methods=['POST'])
def send_message():
  
    data = request.form

    phone = data['phone']
    problem = data['problem']
    status = data['status']
    lon = data['lon']
    lat = data['lat']
    token = data['token']
    Mid = data['Mid']

    db.cursor.execute("INSERT INTO customers (phone, problem, status, lon, lat, fcm_token, Mid) VALUES (%s, %s, %s, %s, %s, %s, %s)", (phone, problem, status, lon, lat, token, Mid))
    db.db_connection.commit()
    
    return jsonify({'message': 'Message sent successfully'})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    receiver = request.args.get('receiver')

    db.cursor.execute("SELECT content, sender, timestamp FROM message WHERE receiver=%s", (receiver,))
    messages = db.cursor.fetchall()

    message_list = [{'content': message[0], 'sender': message[1], 'timestamp': message[2]} for message in messages]

    return jsonify({'messages': message_list})

if __name__ == '__main__':
    app.run(y)
