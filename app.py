import sqlite3
import html
import uuid
import bcrypt
import re
import time
import random
from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import check_password_hash, generate_password_hash
from flask_socketio import SocketIO, send
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!' 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=100) # 100분 후 자동 로그아웃


# 세션 쿠키 보안 설정
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # 자바스크립트에서 세션 쿠키 접근 차단
    SESSION_COOKIE_SECURE=True,    # HTTPS 환경에서만 세션 쿠키 전송
    SESSION_COOKIE_SAMESITE='Lax'  # CSRF 공격 방어를 위한 SameSite 설정
)


MAX_ATTEMPTS = 5            # 최대 로그인 시도 횟수
BLOCK_TIME = 300             # 차단 시간 (초 단위)
user_last_message_time = {} # 사용자별 마지막 실시간 메시지 시간 저장  


csrf = CSRFProtect(app)  # CSRF 보호 활성화
socketio = SocketIO(app)
DATABASE = 'market.db'
   
# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
# 결과를 dict처럼 사용하기 위함
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  
    return db   
    
# 관리자 ID를 UUID로 설정
def get_admin_id():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM user WHERE username = 'jangheewon'")
    admin_user = cursor.fetchone()
    return admin_user['id'] if admin_user else None

with app.app_context():
    ADMIN_ID = get_admin_id()  # 관리자 UUID 값 저장
    
# 관리자 페이지 접근 차단    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session['user_id'] != ADMIN_ID:
            flash("접근할 수 없는 페이지입니다.")
            return redirect(url_for('index'))  
        return f(*args, **kwargs)
    return decorated_function


# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)                                       
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        # 새로운 채팅 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # 새로운 실시간 채팅 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS realtime_chat (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # user 테이블에 `is_inactive` 필드가 없으면 추가
        cursor.execute("PRAGMA table_info(user);")
        columns = [col[1] for col in cursor.fetchall()]
        if 'is_inactive' not in columns:
            cursor.execute("ALTER TABLE user ADD COLUMN is_inactive INTEGER DEFAULT 0;")
            
        # user 테이블에 'points' 필드가 없으면 추가
        if 'points' not in columns:
            cursor.execute("ALTER TABLE user ADD COLUMN points INTEGER DEFAULT 0;")
                    
        # report 테이블에 'target_type' 필드가 없으면 추가 (user 또는 product 구분용)
        cursor.execute("PRAGMA table_info(report);")
        report_columns = [col[1] for col in cursor.fetchall()]
        if 'target_type' not in report_columns:
            cursor.execute("ALTER TABLE report ADD COLUMN target_type TEXT DEFAULT         'user';") 
          
        # report 테이블에 created_at 필드가 없으면 추가
        cursor.execute("PRAGMA table_info(report);")
        report_columns = [col[1] for col in cursor.fetchall()]
        if 'created_at' not in report_columns:
            cursor.execute("ALTER TABLE report ADD COLUMN created_at TEXT;")
            
        # product 테이블에 'product_code' 칼럼이 없으면 추가 (신고할 때 필요)
        cursor.execute("PRAGMA table_info(product);")
        product_columns = [col[1] for col in cursor.fetchall()]
        if 'product_code' not in product_columns:
            cursor.execute("ALTER TABLE product ADD COLUMN product_code TEXT;")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_product_code ON product(product_code);")

                
        db.commit()
        
        
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 세션 유효 시간 설정 (60분)
@app.before_request
def check_session_timeout():
    last_active = session.get('last_active')

    if last_active:
        last_active = datetime.strptime(last_active, "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() - last_active > timedelta(minutes=60):
            session.clear()
            flash('세션이 만료되었습니다. 다시 로그인하세요.')
            return redirect(url_for('login'))

    # 활동이 있으면, 활동 시간 갱신
    session['last_active'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# 보안 헤더 
@app.after_request
def apply_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdnjs.cloudflare.com https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline'; "
        "object-src 'none';")   
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
          

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')
    
    
# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # XSS 공격 방지 
        username = html.escape(username)
        
        # 사용자명 검증 (영문, 숫자, 밑줄(_)만 허용, 3~20자)
        if not re.match(r"^[a-zA-Z0-9_]{5,15}$", username):
            flash('사용자명은 영문, 숫자, 밑줄(_)만 포함할 수 있으며, 5~15자여야 합니다.')
            return redirect(url_for('register'))

        # 비밀번호 검증 (최소 8자, 영문+숫자+특수문자 포함)
        if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            flash('비밀번호는 최소 8자 이상이어야 하며, 영문, 숫자, 특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))
            
        # 비밀번호 일치 확인
        if password != confirm_password:
            flash('비밀번호가 서로 일치하지 않습니다.')
            return redirect(url_for('register'))
                    
        # 비밀번호 해싱 (bcrypt 사용)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        db = get_db()
        cursor = db.cursor()
        
        # 중복 사용자명 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
            
        # DB에 아이디와 비밀번호 저장
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():

    # 로그인 시도 횟수 추적
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_attempt_time'] = time.time()
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 로그인 시도 횟수 확인
        if session['login_attempts'] >= MAX_ATTEMPTS:
            last_attempt_time = session['last_attempt_time']
            
            # 로그인 차단
            if time.time() - last_attempt_time < BLOCK_TIME:
                wait_time = BLOCK_TIME - (time.time() - last_attempt_time)   
                flash(f"로그인 시도 횟수가 초과되었습니다. {int(wait_time)}초 후에 다시 시도해주세요.", 'danger')
                return render_template('login.html')  

            # 차단 시간 경과 시 로그인 시도 횟수 초기화
            else:
                session['login_attempts'] = 0
                session['flash_shown'] = False  
       
        # XSS 공격 방지 
        username = html.escape(username)
                
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute("SELECT id, password, is_inactive FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        # 휴면 계정인지 확인
        if user and user['is_inactive']:
            flash("휴면 계정입니다. 관리자에게 문의하세요.")
            return redirect(url_for('login'))        
                
        # 비밀번호 일치 여부 확인
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['user_id'] = user['id']
            session['last_active'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            session['login_attempts'] = 0  
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            session['login_attempts'] += 1
            session['last_attempt_time'] = time.time()
            session['flash_shown'] = False
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
            
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))
    

# 대시보드: 상품과 실시간 채팅
@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    # 검색어 받기 (공백 제거 + XSS 방지)
    raw_query = request.args.get('q', '')
    query = html.escape(raw_query.strip())


    if query:
        # 상품명(title)에 검색어가 포함된 상품만 조회
        cursor.execute("SELECT * FROM product WHERE title LIKE ?", (f'%{query}%',))
    else:
        # 검색어 없으면 전체 상품 조회
        cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()    
    
    # 실시간 채팅 메시지 
    cursor.execute("SELECT * FROM realtime_chat ORDER BY timestamp ASC LIMIT 50")
    chat_messages = cursor.fetchall()

    return render_template('dashboard.html', products=products, user=current_user, query=query, chat_messages=chat_messages)


# 프로필 페이지
@app.route('/profile', methods=['GET', 'POST'])
def profile():

    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 로그인한 사용자 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    
    # 사용자가 등록한 상품 목록 가져오기
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    user_products = cursor.fetchall()

    if request.method == 'POST':
    
        # 상품 삭제 처리
        if 'delete_product' in request.form:
            product_id = request.form['product_id']
            
            cursor.execute("SELECT seller_id FROM product WHERE id = ?", (product_id,))
            product = cursor.fetchone()

            # 상품의 소유자 확인
            if not product or product['seller_id'] != session['user_id']:
                flash('상품 삭제 권한이 없습니다.')
                return redirect(url_for('profile'))
            
            cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
            db.commit()
            flash('상품이 삭제되었습니다.')
            return redirect(url_for('profile'))

        # 프로필 소개글 업데이트
        elif 'update_bio' in request.form:
            bio = html.escape(request.form.get('bio', '').strip())
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
            db.commit()
            flash('소개글이 성공적으로 업데이트되었습니다.')

        # 비밀번호 변경 처리
        elif 'update_password' in request.form:
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            if not bcrypt.checkpw(current_password.encode('utf-8'), user['password']):
                flash('현재 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))

            if new_password != confirm_password:
                flash('새 비밀번호와 확인 비밀번호가 일치하지 않습니다.')
                return redirect(url_for('profile'))

            if new_password == current_password:
                flash('새 비밀번호는 기존 비밀번호와 다르게 설정해야 합니다.')
                return redirect(url_for('profile'))

            if len(new_password) < 8 or not re.search(r'[A-Za-z]', new_password) or not re.search(r'\d', new_password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
                flash('비밀번호는 최소 8자 이상, 영문/숫자/특수문자를 포함해야 합니다.')
                return redirect(url_for('profile'))

            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_new_password, user['id']))
            db.commit()
            flash('비밀번호가 성공적으로 업데이트되었습니다.')

        # 포인트 충전 처리
        elif 'charge_points' in request.form:
            try:
                charge_amount = int(request.form['charge_amount'])
                if charge_amount > 0:
                    cursor.execute("UPDATE user SET points = points + ? WHERE id = ?", (charge_amount, session['user_id']))
                    db.commit()
                    flash(f'{charge_amount} 포인트가 충전되었습니다.')
                else:
                    flash('1 이상의 숫자를 입력해주세요.')
            except ValueError:
                flash('유효한 숫자를 입력해주세요.')
       
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()
    
    return render_template('profile.html', user=current_user, user_products=user_products)

# 상품 수정 페이지
@app.route('/product/edit/<product_id>', methods=['GET', 'POST'])
def edit_product(product_id):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 해당 상품 정보 가져오기
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 상품의 소유자 확인
    if not product or product['seller_id'] != session['user_id']:
        flash('상품 수정 권한이 없습니다.')
        return redirect(url_for('profile'))

    if request.method == 'POST':
    
        # XSS 공격방지
        title = html.escape(request.form['title'].strip())
        description = html.escape(request.form['description'].strip())
        price = request.form['price'].strip()
        
        # 필수 항목 검증
        if not title or not description or not price:
            flash('모든 항목을 입력해주세요.', 'danger')
            return render_template('edit_product.html', product=product)
            
        # 가격 형식 및 범위 검증
        try:
            price = int(price)
            if price <= 0 or price > 1000000:
                flash('가격은 1원 이상 100만 원 이하로 입력해주세요.', 'danger')
                return render_template('edit_product.html', product=product)
        except ValueError:
            flash('가격은 숫자 형식으로 입력해주세요.', 'danger')
            return render_template('edit_product.html', product=product)

        cursor.execute("UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
                       (title, description, price, product_id))
        db.commit()

        flash('상품이 수정되었습니다.', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_product.html', product=product) 

# 상품코드 생성
def generate_product_code():
    return "PRD-" + ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=6))

# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():

    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
    
        # XSS 공격방지
        title = html.escape(request.form['title'].strip())
        description = html.escape(request.form['description'].strip())
        price = request.form['price'].strip()
        
        # 필수 항목 검증
        if not title or not description or not price:
            flash('모든 항목을 입력해주세요.')
            return render_template('new_product.html', title=title, description=description, price=price)
            
        # 가격 형식 및 범위 검증
        try:
            price = int(price)
            if price <= 0 or price > 1000000:
                flash('가격은 1원 이상 100만 원 이하로 입력해주세요.', 'danger')
                return render_template('new_product.html', title=title, description=description, price=price)
        except ValueError:
            flash('가격은 숫자 형식으로 입력해야 합니다.', 'danger')
            return render_template('new_product.html', title=title, description=description, price=price)
        
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        
        # 고유 상품 코드 생성 
        while True:
            product_code = generate_product_code()
            cursor.execute("SELECT 1 FROM product WHERE product_code = ?", (product_code,))
            if not cursor.fetchone():
                break
        
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id, product_code) VALUES (?, ?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'], product_code)
        )
        db.commit()
        flash('상품이 등록되었습니다.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>', methods=['GET', 'POST'])
def view_product(product_id):

    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
        
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    
    return render_template('view_product.html', product=product, seller=seller)

# 판매자 프로필
@app.route('/seller/<seller_id>')
def view_seller(seller_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (seller_id,))
    seller = cursor.fetchone()
    if not seller:
        flash('판매자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    return render_template('view_seller.html', seller=seller)
 
# 채팅목록    
@app.route('/chatlist')
def chat_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # 나와 채팅한 상대 목록 가져오기
    cursor.execute("""
        SELECT DISTINCT 
            CASE 
                WHEN sender_id = ? THEN receiver_id
                WHEN receiver_id = ? THEN sender_id
            END AS other_user_id
        FROM chat
        WHERE sender_id = ? OR receiver_id = ?
    """, (user_id, user_id, user_id, user_id))

    chat_users = cursor.fetchall()

    users = []
    for chat_user in chat_users:
        cursor.execute("SELECT id, username FROM user WHERE id = ?", (chat_user['other_user_id'],))
        user = cursor.fetchone()
        if user:
            users.append(user)

    return render_template('chat_list.html', users=users)

# 채팅시작 (판매자 프로필을 통해 채팅 시작하는 부분)    
@app.route('/chat/start/<seller_id>')
def chat_start(seller_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    if user_id == seller_id:
        flash("자신과는 채팅을 시작할 수 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # 기존 채팅 확인
    cursor.execute("""
        SELECT * FROM chat
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
    """, (user_id, seller_id, seller_id, user_id))
    
    existing_chat = cursor.fetchone()

    # 기존 채팅이 없으면 새로운 채팅 기록 생성
    if not existing_chat:
        cursor.execute("""
            INSERT INTO chat (id, sender_id, receiver_id, message)
            VALUES (?, ?, ?, ?)
        """, (str(uuid.uuid4()), user_id, seller_id, "채팅을 시작합니다."))
        db.commit()

    return redirect(url_for('chat_with_user', user_id=seller_id))

# 채팅창
@app.route('/chat/<user_id>', methods=['GET', 'POST'])
def chat_with_user(user_id):

    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # 채팅 내역 조회
    cursor.execute("""
        SELECT * FROM chat
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (current_user_id, user_id, user_id, current_user_id))
    
    chats = cursor.fetchall()

    # 상대방 정보 조회
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (user_id,))
    chat_user = cursor.fetchone()
    
    # 사용자 정보 조회 
    cursor.execute("SELECT * FROM user WHERE id = ?", (current_user_id,))
    current_user = cursor.fetchone()    

    if request.method == 'POST':
        if 'message' in request.form:
            message = request.form['message'].strip()
            
            # 메세지 길이 제한
            if len(message) > 500:
                flash('메시지는 500자 이하로 입력해주세요.')
                return redirect(url_for('chat_with_user', user_id=user_id))            

            # XSS 공격방지
            cleaned_message = html.escape(message)   
            
            cursor.execute("""
                SELECT timestamp FROM chat
                WHERE sender_id = ? AND receiver_id = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (current_user_id, user_id))
            last_msg = cursor.fetchone()

            # 스팸 방지: 1초 이내 반복 전송 제한
            if last_msg:
                try:
                    last_time_str = last_msg['timestamp']                    
                    last_time = datetime.strptime(last_time_str, '%Y-%m-%d %H:%M:%S')
                    now = datetime.utcnow()
                    diff = (now - last_time).total_seconds()

                    if diff < 1:
                        flash(f'메시지를 너무 빠르게 보냈습니다. 잠시 후에 다시 시도하세요')
                        return redirect(url_for('chat_with_user', user_id=user_id))
                except Exception as e:
                    print(f'[스팸 방지 오류] {e}')         
            
            if cleaned_message:
                now_utc = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("""
                    INSERT INTO chat (id, sender_id, receiver_id, message)
                    VALUES (?, ?, ?, ?)
                """, (str(uuid.uuid4()), current_user['id'], user_id, cleaned_message))
                db.commit()
                return redirect(url_for('chat_with_user', user_id=user_id))

        # 포인트 송금 처리
        elif 'transfer_points' in request.form:
            try:
                amount = int(request.form.get('amount', 0))
            except ValueError:
                flash('유효한 숫자를 입력해주세요.', 'danger')
                return redirect(url_for('chat_with_user', user_id=user_id))

            if amount <= 0:
                flash('송금할 포인트는 1 이상이어야 합니다.', 'danger')
            elif current_user['points'] < amount:
                flash('보유 포인트가 부족합니다.', 'danger')
            else:
                # 포인트 차감 및 추가
                cursor.execute("UPDATE user SET points = points - ? WHERE id = ?", (amount, current_user['id']))
                cursor.execute("UPDATE user SET points = points + ? WHERE id = ?", (amount, user_id))
                db.commit()
                flash(f'{chat_user["username"]}님에게 {amount} 포인트를 송금했습니다.', 'success')

            return redirect(url_for('chat_with_user', user_id=user_id))

    return render_template('chat_with_user.html', user=chat_user, chats=chats)

# 연결 시 인증 확인
@socketio.on('connect')
def on_connect():
    if 'user_id' not in session:
        print("인증되지 않은 사용자가 WebSocket 연결 시도")
        disconnect()
    else:
        print(f"사용자 {session['user_id']}가 WebSocket에 연결됨")
        
# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):

    if 'user_id' not in session:
        print("인증 안 된 사용자의 WebSocket 메시지 시도 차단")
        return  

    user_id = session['user_id']
    now = time.time()
    
    # 스팸 방지: 1초 이내 반복 전송 제한
    last_time = user_last_message_time.get(user_id)
    if last_time and now - last_time < 1:
        print(f"스팸 방지: 사용자 {user_id}의 메시지 전송 제한됨")
        return
    user_last_message_time[user_id] = now    

    # 메시지 유효성 검사
    message = data.get('message', '').strip()
    if not message:
        print("빈 메시지 전송 차단됨")
        return
    if len(message) > 500:
        print("500자 초과 메시지 차단됨")
        return              
    cleaned_message = html.escape(message)
    if not cleaned_message.strip():
        print("XSS 필터 후 비어있는 메시지 차단됨")
        return

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()

    if user is None:
        print("유저 정보 없음 - 메시지 차단")
        return
        
    # 메시지 DB에 저장 
    cursor.execute("""
        INSERT INTO realtime_chat (id, user_id, username, message)
        VALUES (?, ?, ?, ?)
    """, (str(uuid.uuid4()), user_id, user['username'], cleaned_message))
    db.commit()
            
    # 메시지 구성 후 브로드캐스트
    send({
        'user_id': user_id,
        'username': user['username'],
        'message': cleaned_message
    }, broadcast=True)
    
# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():

    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        target_type = html.escape(request.form['target_type'].strip())
        target_id = html.escape(request.form['target_id'].strip())
        reason = html.escape(request.form['reason'].strip())        

        # 신고 사유 검증
        if not reason or len(reason) > 500:
            flash('신고 사유를 정확히 입력해주세요. (최대 500자)')
            return render_template('report.html')
        
        db = get_db()
        cursor = db.cursor() 
        
        # 대상 검증
        if target_type == 'user':
            cursor.execute("SELECT id FROM user WHERE username = ?", (target_id,))
            target = cursor.fetchone()
            if not target:
                flash('신고 대상 사용자가 존재하지 않습니다.')
                return render_template('report.html')

        elif target_type == 'product':
            cursor.execute("SELECT id FROM product WHERE product_code = ?", (target_id,))
            target = cursor.fetchone()
            if not target:
                flash('신고 대상 상품이 존재하지 않습니다.')
                return render_template('report.html')
        else:
            flash('잘못된 신고 대상 유형입니다.')
            return render_template('report.html')      
        
        cursor.execute("""
            SELECT COUNT(*) FROM report
            WHERE reporter_id = ? AND DATE(created_at) = DATE('now')
        """, (session['user_id'],))
        daily_count = cursor.fetchone()[0]

        # 하루 신고 건수 제한 (하루 5건 이내)
        if daily_count >= 5:
            flash('하루 신고 가능 횟수를 초과했습니다. 내일 다시 시도해주세요.')
            return render_template('report.html')
            
        cursor.execute("""
            SELECT COUNT(*) FROM report
            WHERE reporter_id = ? AND target_id = ? AND target_type = ? AND DATE(created_at) = DATE('now')
        """, (session['user_id'], target_id, target_type))
        duplicate_count = cursor.fetchone()[0]

        # 중복 신고 방지 (같은 대상에 대해 하루에 한 건만)
        if duplicate_count > 0:
            flash('오늘 이미 해당 대상을 신고하셨습니다.')
            return render_template('report.html')
        
        # 신고 저장
        report_id = str(uuid.uuid4())
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        cursor.execute("""
            INSERT INTO report (id, reporter_id, target_id, reason, target_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (report_id, session['user_id'], target_id, reason, target_type, created_at))
        
        db.commit()
        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))
        
    return render_template('report.html')
    
########################관리자페이지########################## 
    
@app.route('/admin')
@admin_required
def admin():

    db = get_db()
    cursor = db.cursor()
    
    # 신고 목록 가져오기
    cursor.execute("SELECT created_at, id, reporter_id, target_type, target_id, reason FROM report ORDER BY id DESC")
    reports = cursor.fetchall()
    
    # 상품 목록 가져오기
    cursor.execute("SELECT id, product_code, title, description, price, seller_id FROM product ORDER BY id DESC")
    products = cursor.fetchall()

    # 사용자 목록 가져오기
    cursor.execute("SELECT id, username, bio, points, is_inactive FROM user ORDER BY id DESC")
    users = cursor.fetchall()

    return render_template('admin.html', reports=reports, products=products, users=users)
  
# 신고처리    
@app.route('/admin/<report_id>', methods=['POST'])
@admin_required
def process_report(report_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE id = ?", (report_id,))
    db.commit()
    flash("신고가 처리되었습니다.")
    return redirect(url_for('admin'))   
  
# 상품삭제     
@app.route('/admin/<product_id>', methods=['POST'])
@admin_required
def delete_product(product_id):

    db = get_db()
    cursor = db.cursor()
    
    # 해당 상품 삭제
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    
    flash("상품이 삭제되었습니다.")
    return redirect(url_for('admin'))

# 휴먼처리    
@app.route('/admin/users/deactivate/<user_id>', methods=['POST'])
@admin_required
def deactivate_user(user_id):

    db = get_db()
    cursor = db.cursor()
    
    # 해당 사용자가 존재하는지 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("사용자가 존재하지 않습니다.")
        return redirect(url_for('admin'))

    # 휴면 상태로 변경
    cursor.execute("UPDATE user SET is_inactive = 1 WHERE id = ?", (user_id,))
    db.commit()

    flash("사용자가 휴면 처리되었습니다.")
    return redirect(url_for('admin'))

# 활성처리
@app.route('/admin/users/reactivate/<user_id>', methods=['POST'])
@admin_required
def reactivate_user(user_id):

    db = get_db()
    cursor = db.cursor()

    # 해당 사용자가 존재하는지 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("사용자가 존재하지 않습니다.")
        return redirect(url_for('admin'))

    # 활성 상태로 변경
    cursor.execute("UPDATE user SET is_inactive = 0 WHERE id = ?", (user_id,))
    db.commit()

    flash("사용자의 휴면이 해제되었습니다.")
    return redirect(url_for('admin'))
    
# https
if __name__ == '__main__':
    init_db()  
    socketio.run(app, ssl_context=('cert.pem', 'key.pem'), debug=False) 
    # debug=False -> 오류메세지 사용자에게 노출 X
    # ssl_context=('cert.pem', 'key.pem') -> https설정, ngrok 할 때에는 없어야 정상 작동 
