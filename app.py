from ctypes import alignment
from os import abort
from flask import Flask, render_template, request, redirect, url_for, jsonify
from service import acak, getresult, angka, new_simbol, simbol, alphabet, gen_pass
import secrets
import random
from flaskext.mysql import MySQL
import pymysql
import hashlib
from flask_recaptcha import ReCaptcha
import re
from datetime import timedelta, datetime
from flask import session, app
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_paranoid import Paranoid
from flask_paginate import Pagination, get_page_parameter
from flask_qrcode import QRcode
from pymysql import cursors
import os
from flask_uploads import IMAGES, UploadSet, configure_uploads

app = Flask(__name__)
app.secret_key = "BisMilaahHanya4allAhY4n6TauAamiin!#"
mysql = MySQL()
mail = Mail(app)
QRcode(app)
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'ecsa'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
# site key - Google ReChapta
app.config['RECAPTCHA_SITE_KEY'] = '6LeUK3cfAAAAAIpGwG2Wf0LZreY7-QbNgbhOonPe'
# secret key -  Google ReChapta
app.config['RECAPTCHA_SECRET_KEY'] = '6LeUK3cfAAAAACGn_UdvErhV82b8QO2IwMmN4yVh'
mysql.init_app(app)
recaptcha = ReCaptcha(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'ecsaproject@gmail.com'
app.config['MAIL_PASSWORD'] = 'hryriwvwmkopeqkc'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['CRSF_ENABLE'] = True
photos = UploadSet("photos", IMAGES)
app.config["UPLOADED_PHOTOS_DEST"] = "static/images/profile"
configure_uploads(app, photos)
app.config['UPLOADED_PHOTOS_ALLOW'] = set(['png', 'jpg', 'jpeg'])
mail = Mail(app)

paranoid = Paranoid(app)
paranoid.redirect_view = '/'

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=60)


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500


@paranoid.on_invalid_session
def invalid_session():
    render_template('401.html'), 401


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    if 'username' in session:
        return redirect(url_for("dashboard"))
    conn = mysql.connect()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        cursor.execute(
            'SELECT uniqcode FROM users WHERE username = %s', (username))
        uniq = cursor.fetchone()
        if uniq is not None:
            uniqcode = uniq.get('uniqcode')
            passkey = uniqcode.join(reversed(password)) + 'dd'
            ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
            encpass = ruleppass.hexdigest()
            conn.close()
            conn = mysql.connect()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute(
                'SELECT username, password, email,uniqcode, hashcode, verification, activation FROM users WHERE username = %s AND password = %s', (username, encpass))
            account = cursor.fetchone()
            if account and recaptcha.verify():
                verifict = account.get('verification')
                activer = account.get('activation')
                get_mail = account.get('email')
                if verifict == activer:
                    session['username'] = account['username']
                    session['hashcode'] = account['hashcode']
                    session['uniqcode'] = account['uniqcode']
                    print(session['username'])
                    return redirect('/dashboard')
                else:
                    sendmail = get_mail.split()
                    token = s.dumps(get_mail, salt="Abagaboga")
                    msg = Message('Activation account', sender='marmut@vinection.com',
                                  recipients=sendmail)
                    link = url_for('confirm_email',
                                   token=token, _external=True)
                    msg.body = "Please No Reply"
                    msg.body = "click link for activation:{}".format(link)
                    mail.send(msg)
                    conn = mysql.connect()
                    cursor = conn.cursor()
                    cursor.execute('UPDATE users SET activation=%s WHERE email=%s',
                                   (token, sendmail))
                    conn.commit()
                    conn.close()
                    msg = "Your Account not Active, Please Check inbox/spam email for Activation"
            else:
                msg = ' Incorrect username/password! '
                return render_template('login.html', msg=msg)
        else:
            msg = ' Incorrect username/password! '
            return render_template('login.html', msg=msg)
    return render_template('login.html', msg=msg)


@app.route('/signout')
def signout():
    session.pop('username')
    return redirect(url_for('login'))


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        msg = ''
        hashcode = session["hashcode"]
        Getuser = session["username"]
        akses = 'public'
        cursor = mysql.connect().cursor()
        cursor.execute(
            'SELECT * FROM newitem WHERE access = %s', (akses))
        Getshowbank = cursor.fetchall()
        if Getshowbank and 'search' in request.form:
            searchValue = request.form['search']
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT * FROM newitem WHERE source LIKE %s AND access=%s', (searchValue, akses))
            showbank = cursor.fetchall()
            cursor.close()
            if showbank:
                return render_template("dashboard.html", showbank=showbank, name=session["username"])
            else:
                msg = 'Not Found'
                cursor = mysql.connect().cursor()
                cursor.execute(
                    'SELECT * FROM newitem WHERE access = %s ORDER BY created_time DESC LIMIT 10', (akses))
                showbank = cursor.fetchall()
                cursor.close()
                return render_template("dashboard.html", msg=msg, showbank=showbank, name=session["username"])
        else:
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT * FROM newitem WHERE access = %s ORDER BY created_time DESC LIMIT 10', (akses))
            showbank = cursor.fetchall()
            cursor.close()
            return render_template("dashboard.html", msg=msg, showbank=showbank, name=session["username"])


@app.route("/redeem", methods=["GET", "POST"])
def redeem():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        msg = ''
        hashcode = session["hashcode"]
        Getuser = session["username"]
        akses = 'public'
        cursor = mysql.connect().cursor()
        cursor.execute(
            'SELECT access,source,password,deskripsi FROM newitem WHERE access = %s', (akses))
        Getshowbank = cursor.fetchall()
        if Getshowbank and 'search' in request.form:
            searchValue = request.form['search']
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT access,source,password,deskripsi FROM newitem WHERE keycode LIKE %s AND access=%s', (searchValue, akses))
            showbank = cursor.fetchall()
            cursor.close()
            if showbank:
                fixed = 'http://192.168.2.7/'
                aksesKey = fixed + searchValue
                get_qr = str(aksesKey)
                qr_generator = QRcode.qrcode(
                    data=get_qr, error_correction='H', icon_img='static/images/marmutbarcode.jpg')
                return render_template("redeem.html", showbank=showbank, qr=qr_generator, searchValue=searchValue, name=session["username"])
            else:
                msg = 'Data Not Found'
                return render_template("redeem.html", msg=msg, showbank=showbank, name=session["username"])
        else:
            msg = 'Data Not Found'
            return render_template("redeem.html", msg=msg)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        Getuser = session["username"]
        conn = mysql.connect()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT pic_url FROM users WHERE username=%s', (Getuser))
        data = str(cursor.fetchone()[0])
        cursor.close()
        if request.method == 'POST' and 'photo' in request.files:
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT id FROM users WHERE username = %s ', (Getuser))
            member = cursor.fetchone()
            (id, *others) = member
            profilepic_name = str(id)+'.png'
            profilepic_url = '/static/images/profile/' + profilepic_name
            workingdir = os.path.abspath(os.getcwd())
            fullprofilepic_url = workingdir + profilepic_url
            if os.path.isfile(fullprofilepic_url) == True:
                os.remove(fullprofilepic_url)
            photos.save(request.files['photo'],
                        folder=None, name=profilepic_name)

            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET pic_url=%s WHERE username=%s', (profilepic_url, Getuser))
            member = cursor.fetchone()
            conn.commit()
            cursor.close()
            return render_template('profile.html', image=data, Getuser=Getuser)
        return render_template('profile.html', image=data, Getuser=Getuser)


@app.route("/additem", methods=['GET', 'POST'])
def additem():
    msg = ''
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        if request.method == 'POST' and 'source' in request.form and 'deskripsi' in request.form and 'password' in request.form and 'access' in request.form and 'Private_key' in request.form:
            charuniq = session['uniqcode']
            hashcoder = session["hashcode"]
            source = request.form['source']
            deskripsi = request.form['deskripsi']
            password = request.form['password']
            access = request.form['access']
            Private_key = request.form['Private_key']
            waktu = datetime.now()
            hashcode = hashlib.sha256(str(password).encode('utf-8'))
            hash_digit = hashcode.hexdigest()
            keycode = charuniq + hash_digit
            connection = mysql.get_db()
            cursor = connection.cursor()
            cursor.execute('INSERT INTO newitem(source,deskripsi, password,access,Private_key, usercode, keycode, public_access,created_time) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                           (source, deskripsi, password, access, Private_key, hashcoder, keycode, keycode, waktu))
            connection.commit()
            connection.close()
            msg = 'You have successfully add new source !'
            return render_template('additem.html', msg=msg)
    return render_template('additem.html', msg=msg)


@app.route('/detail', methods=['GET', 'POST'])
def detail():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        if 'mypin' not in session:
            return redirect(url_for('show'))
        else:
            page = request.args.get(get_page_parameter(), type=int, default=1)
            limit = 10
            offset = page * limit - limit
            cursor = mysql.connect().cursor()
            hashcode = session["hashcode"]
            cursor.execute(
                'SELECT * FROM newitem')
            result = cursor.fetchall()
            total = len(result)
            next = page+1
            prev = page-1
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT * FROM newitem where usercode=%s ORDER BY created_time DESC limit %s offset %s',  (hashcode, limit, offset))
            showbank = cursor.fetchall()
            pagination = Pagination(
                page=page, per_page=limit, total=total)
            cursor.close()
            return render_template("detail.html", data=showbank, pagination=pagination, next=next, prev=prev, name=session["username"])


@app.route("/detail/<int:id>/delete", methods=['GET', 'POST'])
def delete(id):
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        cursor = mysql.connect().cursor()
        cursor.execute(
            'SELECT * FROM newitem WHERE id = %s', (id))
        get_id = cursor.fetchall()
        if get_id:
            connection = mysql.get_db()
            cursor = connection.cursor()
            cursor.execute('DELETE FROM newitem WHERE id = %s', (id))
            connection.commit()
            connection.close()
            return redirect('/dashboard')
        abort(404)


@app.route("/detail/<int:id>/edit", methods=['GET', 'POST'])
def edit(id):
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        if 'mypin' not in session:
            return redirect(url_for('show'))
        else:
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT * FROM newitem WHERE id = %s', (id))
            get_id = cursor.fetchall()
            msg = ''
            if get_id and 'source' in request.form and 'deskripsi' in request.form and 'password' in request.form and 'access' in request.form and 'Private_key' in request.form:
                source = request.form['source']
                deskripsi = request.form['deskripsi']
                password = request.form['password']
                access = request.form['access']
                Private_key = request.form['Private_key']
                conn = mysql.connect()
                cursor = conn.cursor()
                cursor.execute('UPDATE newitem SET source = %s, deskripsi = %s, password = %s , access = %s ,Private_key = %s WHERE id=%s',
                               (source, deskripsi, password, access, Private_key, id))
                conn.commit()
                conn.close()
                cursor.close()
                keyaccess = 'Private'
                conn = mysql.connect()
                cursor = conn.cursor(pymysql.cursors.DictCursor)
                cursor.execute(
                    'SELECT access, public_access FROM newitem WHERE id = %s AND access =%s', (id, access))
                dataaccess = cursor.fetchone()
                publickey = dataaccess.get('public_access')
                if access == keyaccess:
                    uniqcode = session['uniqcode']
                    passkey = uniqcode.join(reversed(password)) + 'desu'
                    hashcode = hashlib.sha256(str(passkey).encode('utf-8'))
                    hash_digit = hashcode.hexdigest()
                    getkeycode = uniqcode + hash_digit
                    conn = mysql.connect()
                    cursor = conn.cursor()
                    cursor.execute('UPDATE newitem SET keycode = %s WHERE id=%s AND access=%s',
                                   (getkeycode, id, access))
                    conn.commit()
                    conn.close()
                    cursor.close()
                else:
                    conn = mysql.connect()
                    cursor = conn.cursor()
                    cursor.execute('UPDATE newitem SET keycode = %s, access= %s WHERE id=%s',
                                   (publickey, access, id))
                    conn.commit()
                    conn.close()
                    cursor.close()
                msg = 'data has been successfully update'
                return render_template('edit.html', get_id=get_id, msg=msg)
            return render_template('edit.html', get_id=get_id, msg=msg)


@app.route("/detail/<int:id>/QRcode", methods=['GET', 'POST'])
def Qrcode(id):
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        if 'mypin' not in session:
            return redirect(url_for('show'))
        else:
            conn = mysql.connect()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute(
                'SELECT keycode FROM newitem WHERE id = %s', (id))
            uniq = cursor.fetchone()
            get_key = uniq.get("keycode")
            fixed = 'http://192.168.2.7/'
            aksesKey = fixed + get_key
            get_qr = str(aksesKey)
            qr_generator = QRcode.qrcode(
                data=get_qr, error_correction='H', icon_img='static/images/marmutbarcode.jpg')
            return render_template('detailsource.html', qr=qr_generator, get_key=aksesKey)


@app.route("/show", methods=['GET', 'POST'])
def show():
    if "username" and "uniqcode" not in session:
        return redirect(url_for("login"))
    else:
        msg = ''
        if request.method == 'POST' and 'mypin' in request.form:
            mypin = request.form['mypin']
            uniqcode = session['uniqcode']
            passkey = uniqcode.join(reversed(mypin)) + 'dd'
            ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
            encmypin = ruleppass.hexdigest()
            if encmypin:
                conn = mysql.connect()
                cursor = conn.cursor(pymysql.cursors.DictCursor)
                cursor.execute(
                    'SELECT * FROM users WHERE mypin = %s', (encmypin))
                datarow = cursor.fetchone()
                if datarow:
                    session['mypin'] = datarow['mypin']
                    cursor.close()
                    return redirect(url_for('detail'))
                else:
                    msg = 'PIN Not Valid'
                    return render_template('show.html', msg=msg)
            else:
                msg = 'eror'
    return render_template('show.html', msg=msg)


@app.route("/addRequired", methods=['GET', 'POST'])
def addRequired():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        msg = ''
        if request.method == 'POST' and 'mypin' in request.form:
            mypin = request.form['mypin']
            username = session['username']
            mypin = request.form['mypin']
            conn = mysql.connect()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute(
                'SELECT uniqcode FROM users WHERE username = %s', (username))
            uniq = cursor.fetchone()
            uniqcode = uniqcode = session['uniqcode']
            passkey = uniqcode.join(reversed(mypin)) + 'dd'
            ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
            encmypin = ruleppass.hexdigest()
            conn.close()
            if encmypin:
                conn = mysql.connect()
                cursor = conn.cursor(pymysql.cursors.DictCursor)
                cursor.execute(
                    'SELECT * FROM users WHERE mypin = %s', (encmypin))
                datarow = cursor.fetchone()
                if datarow:
                    session['mypin'] = datarow['mypin']
                    cursor.close()
                    return redirect(url_for('additem'))
                else:
                    msg = 'PIN Not Valid'
                    return render_template('show.html', msg=msg)
            else:
                msg = 'eror'
    return render_template('showadd.html', msg=msg)


@app.route("/showmypin", methods=['GET', 'POST'])
def showmypin():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        msg = ''
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and not None:
            username = request.form['username']
            password = request.form['password']
            conn = mysql.connect()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute(
                'SELECT uniqcode FROM users WHERE username = %s', (username))
            uniq = cursor.fetchone()
            uniqcode = uniq.get('uniqcode')
            passkey = uniqcode.join(reversed(password)) + 'dd'
            ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
            encpass = ruleppass.hexdigest()
            conn.close()
            cursor = mysql.connect().cursor()
            cursor.execute(
                'SELECT * FROM users WHERE username = %s AND password = %s', (username, encpass))
            get_id = cursor.fetchone()
            if get_id and 'Private_key' in request.form and recaptcha.verify():
                Private_key = request.form['Private_key']
                conn = mysql.connect()
                cursor = conn.cursor()
                passkey = uniqcode.join(reversed(Private_key)) + 'dd'
                ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
                keypass = ruleppass.hexdigest()
                cursor.execute('UPDATE users SET mypin = %s WHERE username=%s',
                               (keypass, username))
                conn.commit()
                msg = 'data has been successfully changed'
                return render_template('mypin.html', msg=msg)
            else:
                msg = 'Incorrect username/password!'
            cursor.close()
        else:
            msg = ""
    return render_template('mypin.html', msg=msg)


@app.route("/wordbank", methods=['GET', 'POST'])
def wordbank():
    msg = ''
    if request.method == 'POST' and 'search' in request.form:
        conn = mysql.connect()
        cursor = conn.cursor()
        cari = request.form['search']
        cursor.execute(
            'SELECT * FROM bank WHERE hashcode=%s', (cari))
        datahash = cursor.fetchall()
        if datahash:
            return render_template('wordbank.html', datahash=datahash)
        else:
            akses = 'public'
            cursor.execute(
                'SELECT source, password FROM newitem WHERE keycode=%s AND access=%s', (cari, akses))
            datahash2 = cursor.fetchall()
            return render_template('wordbank.html', datahash2=datahash2)
    return render_template('wordbank.html', msg=msg)


@app.route("/group", methods=['GET', 'POST'])
def group():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        return render_template('group.html')


@app.route("/collab", methods=['GET', 'POST'])
def collab():
    if "username" not in session:
        return redirect(url_for("login"))
    else:
        return render_template('collab.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        new_angka = acak(angka)
        new_alfa2 = random.choice(alphabet)
        new_alfa = random.choice(alphabet)
        uniqcoder = new_alfa + new_angka + new_alfa2
        uniqcode = ''.join(random.choice(uniqcoder) for i in range(3))
        tabur = uniqcode

        # hash_prosess
        hashcode = hashlib.sha256(str(username).encode('utf-8'))
        hash_digit = hashcode.hexdigest()
        passkey = uniqcode.join(reversed(password)) + 'dd'
        ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
        encpass = ruleppass.hexdigest()

        uniq_hash = tabur + hash_digit
        conn = mysql.connect()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE username = %s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must contain only characters and numbers !'
        elif not re.fullmatch(r'[A-Za-z0-9@#$!%^&+=]{8,}', password):
            msg = 'Use Strong Password and Min 8 Character'
        else:
            if recaptcha.verify():
                get_email = email.split()
                token = s.dumps(email, salt="Abagaboga")
                msg = Message('Activation account', sender='marmut@vinection.com',
                              recipients=get_email)
                link = url_for('confirm_email', token=token, _external=True)
                msg.body = "Please No Reply"
                msg.body = "click link for activation:{}".format(link)
                mail.send(msg)
                connection = mysql.get_db()
                cursor = connection.cursor()
                cursor.execute(
                    'INSERT INTO users(username,password, email,uniqcode, hashcode, activation) VALUES (%s, %s,%s,%s,%s, %s)', (username, encpass, email, uniqcode, uniq_hash, token))
                connection.commit()
                msg = 'Congraturation You have successfully registered, check your inbox/spam email for Activation Account'
                connection.close()
                cursor.close()
            else:
                msg = 'Invalid ReCaptcha'

    return render_template('register.html', msg=msg)


@ app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='Abagaboga', max_age=360)
    except SignatureExpired:
        return render_template('expired.html')
    get_token = token
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET verification = %s, activation=%s WHERE email= %s',
                   (get_token, get_token, email))
    conn.commit()
    conn.close()
    cursor.close()
    return render_template('activation.html')


@app.route('/tokenactivation',  methods=['GET', 'POST'])
def token():
    msg = ''
    if request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        conn = mysql.connect()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT email FROM users WHERE email = %s', (email, ))
        account = cursor.fetchone()
        if account and recaptcha.verify():
            get_email = email.split()
            token = s.dumps(email, salt="Abagaboga")
            msg = Message('Activation account', sender='ecsaproject@gmail.com',
                          recipients=get_email)
            link = url_for('confirm_email', token=token, _external=True)
            msg.body = "Please No Reply"
            msg.body = "click link for activation:{}".format(link)
            mail.send(msg)
            connection = mysql.get_db()
            cursor = connection.cursor()
            cursor.execute('UPDATE users SET activation = %s WHERE email=%s',
                           (token, email))
            connection.commit()
            msg = 'Activation code has been sent to your email, check inbox/spam'
            connection.close()
            cursor.close()
        else:
            msg = 'Email Not found'
    return render_template('token.html', msg=msg)


@app.route('/forgetpass',  methods=['GET', 'POST'])
def forgetpass():
    msg = ''
    if request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        conn = mysql.connect()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT email FROM users WHERE email = %s', (email, ))
        account = cursor.fetchone()
        if account and recaptcha.verify():
            get_email = email.split()
            token = s.dumps(email, salt="Abagabogapasde")
            msg = Message('Restore Account', sender='ecsaproject@gmail.com',
                          recipients=get_email)
            link = url_for('restoreAccount', token=token, _external=True)
            msg.body = "Please No Reply"
            msg.body = "click link for restore password:{}".format(link)
            mail.send(msg)
            connection = mysql.get_db()
            cursor = connection.cursor()
            cursor.execute('UPDATE users SET restoreToken = %s WHERE email=%s',
                           (token, email))
            connection.commit()
            msg = "Account recovery has been sent to email"
            connection.close()
            cursor.close()
        else:
            msg = 'Email Not found'
    return render_template('forgetpass.html', msg=msg)


@app.route('/restoreaccount/<token>')
def restoreAccount(token):
    try:
        email = s.loads(token, salt='Abagabogapasde', max_age=360)
    except SignatureExpired:
        return render_template('expiredpass.html')
    return render_template('recoverypass.html')


@app.route('/account/delete',  methods=['GET', 'POST'])
def accountDelete():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor.execute(
            'SELECT uniqcode FROM users WHERE username = %s', (username))
        uniq = cursor.fetchone()
        if uniq is not None:
            uniqcode = uniq.get('uniqcode')
            passkey = uniqcode.join(reversed(password)) + 'dd'
            ruleppass = hashlib.sha256(str(passkey).encode('utf-8'))
            encpass = ruleppass.hexdigest()
            conn.close()
            conn = mysql.connect()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            cursor.execute(
                'SELECT * FROM users WHERE username = %s AND password = %s AND email = %s', (username, encpass, email))
            account = cursor.fetchone()
            if account and recaptcha.verify():
                return redirect(url_for("login"))
            else:
                return render_template('accountDelete.html')
        else:
            return render_template('accountDelete.html')
    return render_template('accountDelete.html')


@ app.route('/<uniqcode>')
def uniqcode(uniqcode):
    conn = mysql.connect()
    cursor = conn.cursor()
    akses = 'public'
    cursor.execute(
        'SELECT source, password FROM newitem WHERE access=%s and keycode=%s', (akses, uniqcode))
    get_unik = cursor.fetchall()
    if get_unik:
        cursor.close()
        return render_template('wordbanksearch.html',  get_uniq=get_unik)
    else:
        return render_template('404.html')


@app.route("/smartpass")
def smartpass():
    # current_data
    new_angka = new_angka
    new_simbol = new_simbol
    result1 = getresult(1)
    result2 = getresult(2)
    result3 = getresult(3)
    result4 = getresult(4)
    result5 = getresult(5)
    result6 = getresult(6)
    result7 = getresult(7)
    new_wordbank = ''
    new_result = ''

    if len(new_wordbank) <= 2:
        for char in range(0, 1):
            new_result += random.choice(result1)
            new_result += random.choice(result7)
            new_wordbank = new_result
    elif len(new_wordbank) <= 3:
        for char in range(0, 1):
            new_result += random.choice(result2)
            new_result += random.choice(result6)
            new_wordbank = new_result
    elif len(new_wordbank) <= 4:
        for char in range(0, 1):
            new_result += random.choice(result3)
            new_result += random.choice(result5)
            new_wordbank = new_result
    elif len(new_wordbank) <= 5:
        for char in range(0, 1):
            new_result += random.choice(result4)
            new_result += random.choice(result4)
            new_wordbank = new_result
    elif len(new_wordbank) <= 6:
        for char in range(0, 1):
            new_result += random.choice(result5)
            new_result += random.choice(result3)
            new_wordbank = new_result
    elif len(new_wordbank) <= 7:
        for char in range(0, 1):
            new_result += random.choice(result6)
            new_result += random.choice(result2)
            new_wordbank = new_result
    elif len(new_wordbank) <= 8:
        for char in range(0, 1):
            new_result += random.choice(result7)
            new_result += random.choice(result1)
            new_wordbank = new_result
    else:
        for char in range(0, 1):
            new_wordbank = new_result

    wordlist = new_wordbank
    while wordlist not in gen_pass.values:
        password = wordlist
        wordlist = password.join(secrets.choice(alphabet)
                                 for password in range(2))
        new_wordlist = wordlist.capitalize() + new_angka + new_simbol
        break
    securepass1 = wordlist[0].capitalize()
    securepass2 = wordlist[-1].lower()
    uniq = new_angka + new_simbol
    remember = new_wordbank
    generator = new_wordlist
    tabur = 'dx2'
    hashcode = hashlib.sha256(str(generator).encode('utf-8'))
    hash_digit = hashcode.hexdigest()
    uniq_hash = tabur + hash_digit
    connection = mysql.get_db()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO bank(password,hashcode) VALUES (%s,%s)", (generator, uniq_hash))
    connection.commit()
    connection.close()
    return render_template('smartpass.html', data=generator, data2=remember, data3=uniq, data4=securepass1, data5=securepass2, uniq_hash=uniq_hash)


if __name__ == "__main__":
    app.debug = True
    app.run(host='0.0.0.0', port=80)
