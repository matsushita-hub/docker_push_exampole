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
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from celery import Celery
from flask_migrate import Migrate


app = Flask(__name__)

app.config.update(
        SECRET_KEY=os.getenv('SECRET_KEY', 'dev-key-replace-me'),
        PREFERRED_URL_SCHEME='http',
        OIDC_REDIRECT_URI='http://localhost:8081/redirect_uri',
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


def metadata_filter(object, name, type_, reflected, compare_to):
    my_tables = ['file_metadata', 'tag', 'file_tags', 'scan_log', 'alembic_version']
    if type_ == "table":
        return name in my_tables
    return True

migrate = Migrate(app, db, include_object=metadata_filter)

celery_app = Celery('tasks', broker=f"redis://{os.getenv('REDIS_HOST')}:6379/0")
celery_app.conf.update(app.config)


provider_config = ProviderConfiguration(
        issuer=os.getenv('OIDC_ISSUER'),
        client_metadata=ClientMetadata(
            client_id=os.getenv('OIDC_CLIENT_ID'),
            client_secret=os.getenv('OIDC_CLIENT_SECRET')
        )
)

auth_endpoint='http://localhost:8080/realms/myrealm/protocol/openid-connect/auth',
end_session_endpoint='http://localhost:8080/realms/myrealm/protocol/openid-connect/logout'

auth = OIDCAuthentication({'default': provider_config}, app)


file_tags = db.Table('file_tags',
                     db.Column('file_id', db.Integer, db.ForeignKey('file_metadata.id')),
                     db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)





class FileMetadata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))
    tags = db.relationship('Tag', secondary=file_tags, backref='files')
    status = db.Column(db.String(20), default="PENDING")



class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)



class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    status = db.Column(db.String(50))
    virus_name = db.Column(db.String(255))
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(timezone.utc))


UPLOAD_FOLDER = '/app/shared_uploads'


@celery_app.task
def scan_file_task(file_path, original_name, file_id):
    with app.app_context():
        try:
            cd = clamd.ClamdNetworkSocket(host=os.getenv('CLAMAV_HOST'), port=3310)

            with open(file_path, 'rb') as f:
                scan = cd.instream(f)

            res = scan.get('stream')
            res_status, res_msg = res if res else (None, None)
            is_clean = (res_status == 'OK')

            status_str = 'CLEAN' if is_clean else 'INFECTED'

            file_record = db.session.get(FileMetadata, file_id)
            if file_record:
                file_record.status = status_str

            log = ScanLog(filename=original_name, status=status_str, virus_name=None if is_clean else res_msg)

            db.session.add(log)
            db.session.commit()

            logging.info(f"Scan complete fot {original_name}: {status_str}")

            if not is_clean and os.path.exists(file_path):
                os.remove(file_path)

        except Exception as e:
            logging.error(f"Async Scan Error: {e}")


@app.route('/')
@auth.oidc_auth('default')
def index():
    user_info = session.get('userinfo')
    
    if user_info is None:
        return redirect(url_for('index'))

    q = request.args.get('q', '')
    stmt = db.select(FileMetadata).where(FileMetadata.original_name.contains(q)).order_by(FileMetadata.upload_date.desc())
    files = db.session.execute(stmt).scalars().all()
    return render_template('index.html', files=files, query=q, user=user_info)




@app.route('/upload', methods=['GET', 'POST'])
@auth.oidc_auth('default')
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '': return "No file selected", 400

        fname = secure_filename(file.filename)
        savename = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{fname}"
        file_path = os.path.join(UPLOAD_FOLDER, savename)

        file.save(file_path)
        new_file = FileMetadata(filename=savename, original_name=fname, status='PENDING')
        db.session.add(new_file)
        db.session.commit()

        scan_file_task.delay(file_path, fname, new_file.id)

        return redirect(url_for('index'))

    return render_template('upload.html')


@app.route('/logout')
def logout():
    return redirect(url_for('oidc_logout', provider_name='default'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
