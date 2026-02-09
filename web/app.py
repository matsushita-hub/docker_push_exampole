import os, redis, clamd, datetime, logging
from flask import Flask, render_template, request, redirect, url_for, session, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from flask_caching import Cache
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import timezone


app = Flask(__name__)

app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-key-replace-me'),
        MAX_CONTENT_LENGTH=32 * 1024 * 1024,
        SQLALCHEMY_DATABASE_URI=f"mysql+pymysql://{os.getenv('MYSQL_USER')}:{os.getenv('MYSQL_PASSWORD')}@{os.getenv('MYSQL_HOST')}/{os.getenv('MYSQL_DATABASE')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_TYPE='redis',
        SESSION_REDIS=redis.Redis(host=os.getenv('REDIS_HOST'), port=6379),
        CACHE_TYPE='RedisCache',
        CACHE_REDIS_HOST=os.getenv('REDIS_HOST')
)



db = SQLAlchemy(app)
csrf = CSRFProtect(app)
cache = Cache(app)
Session(app)



file_tags = db.Table('file_tags',
                     db.Column('file_id', db.Integer, db.ForeignKey('file_metadata.id')),
                     db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)




class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)



class FileMetadata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    tags = db.relationship('Tag', secondary=file_tags, backref='files')



class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)



class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    status = db.Column(db.String(50))
    virus_name = db.Column(db.String(255))
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))


with app.app_context():
    try:
        db.create_all()
        admin_user = db.session.execute(db.select(User).filter_by(username='admin')).scalar_one_or_none()
        if not admin_user:
            admin = User(username='admin', password_hash=generate_password_hash('admin123'), is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print("Database initialized and Admin user created.")
    except Exception as e:
        print(f"Database initialization failed: {e}")




UPLOAD_FOLDER = '/app/shared_uploads'



def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated



@app.route('/')
@login_required
def index():
    q = request.args.get('q', '')
    stmt = db.select(FileMetadata).where(FileMetadata.original_name.contains(q)).order_by(FileMetadata.upload_date.desc())
    files = db.session.execute(stmt).scalars().all()
    return render_template('index.html', files=files, query=q)




@app.route('/upload', methods=["GET", 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '': return "No file selected", 400

        try:
            cd = clamd.ClamdNetworkSocket(host=os.getenv('CLAMAV_HOST'), port=3310)
            scan = cd.instream(file.stream)
            file.stream.seek(0)

            res = scan.get('stream')
            res_status, res_msg = res if res else (None, None)
            is_clean = (res_status == 'OK')

            status_str = 'CLEAN' if is_clean else 'INFECTED'
            log = ScanLog(filename=file.filename, status=status_str, virus_name=None if is_clean else res_msg)
            db.session.add(log)

            if is_clean:
                fname = secure_filename(file.filename)
                savename = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{fname}"

                file.stream.seek(0)
                file.save(os.path.join(UPLOAD_FOLDER, savename))


                new_file = FileMetadata(filename=savename, original_name=fname)
                db.session.add(new_file)
                db.session.commit()
                return redirect(url_for('index'))


            db.session.commit()
            return "Virus Detected!", 400
        except Exception as e:
            db.session.rollback()
            logging.error(f"Upload error: {e}")
            return "Internal Server Error", 500
    return render_template('upload.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db.session.execute(db.select(User).filter_by(username=request.form.get('username'))).scalar_one_or_none()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('index'))
        return "Invalid username or password", 401
    return render_template('login.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin_user = db.session.execute(db.select(User).filter_by(username='admin')).scalar_one_or_none()
        if not admin_user:
            admin = User(username='admin', password_hash=generate_password_hash('admin123'), is_admin=True)
            db.session.add(admin)
            db.session.commit()
    app.run()
