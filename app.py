from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    banned = db.Column(db.Boolean, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    content = db.Column(db.String(500), nullable=False)


class BannedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=False, unique=True)


@app.before_request
def check_ip_ban():
    """접속한 IP가 밴된 IP인지 확인"""
    ip = request.remote_addr
    if BannedIP.query.filter_by(ip_address=ip).first():
        flash('Your IP is banned. Contact the administrator.', 'danger')
        return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    messages = Message.query.all()
    return render_template('index.html', messages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and not user.banned and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        elif user and user.banned:
            flash('This account has been banned.', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/send', methods=['POST'])
@login_required
def send():
    content = request.form['content']
    message = Message(username=current_user.username, content=content)
    db.session.add(message)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/user_list')
@login_required
def user_list():
    """사용자 목록 페이지, 관리자만 접근 가능"""
    if current_user.username != 'admin':
        flash('이 페이지는 관리자만 접속할 수 있습니다.', 'danger')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('user_list.html', users=users)


@app.route('/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    """사용자를 밴하는 기능, 관리자만 사용 가능"""
    if current_user.username != 'admin':
        flash('이 페이지는 관리자만 접속할 수 있습니다.', 'danger')
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user:
        user.banned = True
        db.session.commit()
        flash(f'User {user.username} has been banned.', 'success')
    return redirect(url_for('user_list'))


@app.route('/ban_ip/<int:user_id>', methods=['POST'])
@login_required
def ban_ip(user_id):
    """사용자의 IP를 밴하는 기능, 관리자만 사용 가능"""
    if current_user.username != 'admin':
        flash('이 페이지는 관리자만 접속할 수 있습니다.', 'danger')
        return redirect(url_for('index'))
    user = User.query.get(user_id)
    if user:
        banned_ip = BannedIP(ip_address=request.remote_addr)
        db.session.add(banned_ip)
        db.session.commit()
        flash(f'IP {request.remote_addr} has been banned.', 'success')
    return redirect(url_for('user_list'))


@app.route('/unban_ip/<int:ip_id>', methods=['POST'])
@login_required
def unban_ip(ip_id):
    """밴된 IP를 해제하는 기능, 관리자만 사용 가능"""
    if current_user.username != 'admin':
        flash('이 페이지는 관리자만 접속할 수 있습니다.', 'danger')
        return redirect(url_for('index'))
    banned_ip = BannedIP.query.get(ip_id)
    if banned_ip:
        db.session.delete(banned_ip)
        db.session.commit()
        flash(f'IP {banned_ip.ip_address} has been unbanned.', 'success')
    return redirect(url_for('user_list'))


def create_admin():
    """관리자 계정을 생성하는 함수"""
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('admin'))
        db.session.add(admin_user)
        db.session.commit()
        print('Admin account created: username=admin, password=admin')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()  # 관리자 계정 생성
    app.run(host='0.0.0.0', port=5000)

