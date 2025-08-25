from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, abort
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor
import paramiko
import scp
import os
import datetime
import psycopg2
from psycopg2 import pool
import shutil
import logging
import smtplib
from email.mime.text import MIMEText
from functools import wraps
from datetime import timedelta
import pytz
import pyotp
from pyrad.client import Client
from pyrad.dictionary import Dictionary
from pyrad.packet import AuthPacket
import csv
import io
import socket
import threading
import random
import time
try:
    import pkg_resources
except ImportError:
    pkg_resources = None

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)  # For session management
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1-hour session timeout
app.config['PREFERRED_URL_SCHEME'] = 'https'  # Support reverse proxy with HTTPS

# Global database lock
db_lock = threading.Lock()

# Configure scheduler with PostgreSQL job store
DB_CONFIG = {
    'database': os.getenv('PG_DATABASE', 'firewall_backups'),
    'user': os.getenv('PG_USER', 'your_user'),
    'password': os.getenv('PG_PASSWORD', 'your_password'),
    'host': os.getenv('PG_HOST', 'localhost'),
    'port': os.getenv('PG_PORT', '5432')
}
jobstores = {
    'default': SQLAlchemyJobStore(url=f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
}
executors = {
    'default': ThreadPoolExecutor(max_workers=2000)
}
scheduler = BackgroundScheduler(jobstores=jobstores, executors=executors, job_defaults={'coalesce': True, 'max_instances': 1})
scheduler.start()

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

db_pool = psycopg2.pool.ThreadedConnectionPool(minconn=1, maxconn=2000, **DB_CONFIG)

BACKUP_DIR = 'backups'
REMOTE_CONFIG_PATH = os.getenv('FORTIGATE_CONFIG_PATH', 'sys_config')
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USER = os.getenv('MAIL_USER', 'user@example.com')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'password')
MAIL_RECIPIENT = os.getenv('MAIL_RECIPIENT', MAIL_USER)
TOTP_ENABLED = os.getenv('TOTP_ENABLED', 'false').lower() == 'true'
TOTP_SECRET = os.getenv('TOTP_SECRET', pyotp.random_base32())
RADIUS_ENABLED = os.getenv('RADIUS_ENABLED', 'false').lower() == 'true'
RADIUS_SERVER = os.getenv('RADIUS_SERVER', 'localhost')
RADIUS_PORT = int(os.getenv('RADIUS_PORT', 1812))
RADIUS_SECRET = os.getenv('RADIUS_SECRET', 'secret')
SCP_TIMEOUT = int(os.getenv('SCP_TIMEOUT', 60))
DICTIONARY_PATH = '/app/dictionary'

# Log environment variables and library version
logger.info(f"TOTP_ENABLED set to: {TOTP_ENABLED}")
logger.info(f"SCP_TIMEOUT set to: {SCP_TIMEOUT} seconds")
logger.info(f"RADIUS_ENABLED set to: {RADIUS_ENABLED}")
logger.info(f"RADIUS_SERVER set to: {RADIUS_SERVER}")
logger.info(f"RADIUS_PORT set to: {RADIUS_PORT}")
logger.info(f"RADIUS_SECRET set to: {RADIUS_SECRET}")
logger.info(f"DICTIONARY_PATH set to: {DICTIONARY_PATH}")
if os.path.exists(DICTIONARY_PATH):
    try:
        with open(DICTIONARY_PATH, 'r') as f:
            dictionary_content = f.read()
        logger.debug(f"RADIUS dictionary file content: {dictionary_content}")
    except Exception as e:
        logger.error(f"Failed to read RADIUS dictionary file at {DICTIONARY_PATH}: {str(e)}")
else:
    logger.error(f"RADIUS dictionary file not found at {DICTIONARY_PATH}")
if pkg_resources:
    try:
        pyrad_version = pkg_resources.get_distribution("pyrad").version
        logger.info(f"Using pyrad version: {pyrad_version}")
    except pkg_resources.DistributionNotFound:
        logger.error("pyrad library not found")
else:
    logger.warning("pkg_resources not available, cannot log pyrad version")

# Set timezone to Europe/Vienna
tz = pytz.timezone('Europe/Vienna')

def send_email(subject, body, to_addr):
    """Thread-safe function to send email notifications."""
    if not (MAIL_SERVER and MAIL_USER and MAIL_PASSWORD):
        logger.error("Email configuration missing: MAIL_SERVER, MAIL_USER, or MAIL_PASSWORD not set")
        return
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = MAIL_USER
        msg['To'] = to_addr
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=30) as server:
            server.starttls()
            server.login(MAIL_USER, MAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"Email notification sent to {to_addr}: {subject}")
    except Exception as email_error:
        logger.error(f"Failed to send email notification: {str(email_error)}")

def execute_with_retry(cursor, query, params, retries=3, delay=1):
    """Execute a database query with retry logic for transient errors."""
    for attempt in range(retries):
        try:
            cursor.execute(query, params)
            return
        except psycopg2.OperationalError as e:
            if attempt < retries - 1:
                logger.warning(f"Database error, retrying {attempt + 1}/{retries}: {str(e)}")
                time.sleep(delay)
                continue
            raise

def init_db():
    """Initialize PostgreSQL database schema."""
    try:
        with db_lock:
            logger.info("Acquiring database connection...")
            conn = db_pool.getconn()
            c = conn.cursor()
            logger.info("Creating tables...")
            c.execute('''CREATE TABLE IF NOT EXISTS firewalls (
                id SERIAL PRIMARY KEY,
                fqdn TEXT,
                username TEXT,
                password TEXT,
                interval_minutes INTEGER CHECK (interval_minutes > 0),
                retention_count INTEGER,
                last_backup TEXT,
                status TEXT,
                ssh_port INTEGER DEFAULT 9422
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS backups (
                id SERIAL PRIMARY KEY,
                fw_id INTEGER REFERENCES firewalls(id),
                timestamp TEXT,
                filename TEXT,
                UNIQUE(fw_id, filename)
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                first_login INTEGER DEFAULT 1,
                totp_secret TEXT,
                is_radius_user BOOLEAN DEFAULT FALSE
            )''')
            c.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                username TEXT,
                action TEXT,
                details TEXT,
                timestamp TEXT
            )''')
            logger.info("Tables created or verified.")
            c.execute("INSERT INTO users (username, password, first_login, is_radius_user) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                      ("admin", "changeme", 1, False))
            logger.info("Admin user inserted or exists.")
            if TOTP_ENABLED:
                c.execute("UPDATE users SET totp_secret = %s WHERE username = %s", (TOTP_SECRET, "admin"))
                logger.info(f"Updated TOTP secret for admin user to: {TOTP_SECRET}")
            else:
                c.execute("UPDATE users SET totp_secret = NULL WHERE username = %s", ("admin",))
                logger.info("TOTP disabled, set admin TOTP secret to NULL")
            logger.info("Checking ssh_port column...")
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'firewalls' AND column_name = 'ssh_port'")
            if not c.fetchone():
                c.execute("ALTER TABLE firewalls ADD COLUMN ssh_port INTEGER DEFAULT 9422")
                logger.info("Added ssh_port column to firewalls table.")
            c.execute("UPDATE firewalls SET interval_minutes = 180 WHERE interval_minutes IS NULL OR interval_minutes <= 0")
            logger.info("Updated interval_minutes in firewalls table.")
            c.execute('''DELETE FROM backups WHERE id NOT IN (
                SELECT MIN(id) FROM backups GROUP BY fw_id, filename
            )''')
            logger.info("Removed duplicate backup entries to enforce unique constraint.")
            conn.commit()
            logger.info("Committed changes to PostgreSQL database in init_db")
            logger.info("Skipping clean_nonexistent_backups for testing...")
            logger.info("Closing database connection...")
            conn.close()
            db_pool.putconn(conn)
            logger.info("Database connection closed.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}", exc_info=True)
        if 'conn' in locals():
            conn.close()
            db_pool.putconn(conn)
        raise

def clean_nonexistent_backups(conn):
    """Remove backup entries for non-existent files."""
    try:
        c = conn.cursor()
        logger.info("Querying backups table...")
        c.execute("SELECT id, filename FROM backups LIMIT 100")  # Limit to prevent large table issues
        backups = c.fetchall()
        logger.info(f"Retrieved {len(backups)} backup entries.")
        for backup_id, filename in backups:
            file_path = os.path.join(BACKUP_DIR, filename)
            logger.debug(f"Checking file: {file_path}")
            if not os.path.exists(file_path):
                logger.warning(f"Removing non-existent backup entry: {filename}")
                execute_with_retry(c, "DELETE FROM backups WHERE id = %s", (backup_id,))
        conn.commit()
        logger.info("Committed changes to PostgreSQL in clean_nonexistent_backups")
    except Exception as e:
        logger.error(f"Failed to clean non-existent backups: {str(e)}", exc_info=True)

def log_activity(username, action, details):
    """Log user activity to activity_logs table."""
    try:
        logger.info("Acquiring database connection for activity log...")
        conn = db_pool.getconn()
        c = conn.cursor()
        timestamp = datetime.datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"Inserting activity log for {username}: {action}")
        execute_with_retry(c, "INSERT INTO activity_logs (username, action, details, timestamp) VALUES (%s, %s, %s, %s)",
                          (username, action, details, timestamp))
        logger.info("Committing activity log to PostgreSQL...")
        conn.commit()
        logger.info(f"Logged activity and committed to PostgreSQL: {username} - {action} - {details}")
        logger.info("Closing activity log connection...")
        conn.close()
        db_pool.putconn(conn)
        logger.info("Activity log connection closed.")
    except Exception as e:
        logger.error(f"Failed to log activity: {str(e)}", exc_info=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        if 'last_activity' in session:
            last_activity = tz.localize(session['last_activity']) if not session['last_activity'].tzinfo else session['last_activity']
            if datetime.datetime.now(tz) - last_activity > timedelta(hours=1):
                session.pop('logged_in', None)
                return redirect(url_for('login'))
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if 'x_forwarded_for' in session and session['x_forwarded_for'] != x_forwarded_for:
            session.pop('logged_in', None)
            return redirect(url_for('login'))
        session['last_activity'] = datetime.datetime.now(tz)
        session['x_forwarded_for'] = x_forwarded_for
        return f(*args, **kwargs)
    return decorated_function

def verify_radius(username, password):
    if not RADIUS_ENABLED:
        return False
    try:
        dictionary = Dictionary(DICTIONARY_PATH)
        logger.debug(f"RADIUS dictionary initialized from {DICTIONARY_PATH}")
        client = Client(server=RADIUS_SERVER, authport=RADIUS_PORT, secret=RADIUS_SECRET.encode('utf-8'))
        client.dictionary = dictionary
        logger.debug(f"RADIUS client initialized for server {RADIUS_SERVER}:{RADIUS_PORT}")
        pkt_id = random.randint(0, 255)
        pkt = AuthPacket(code=1, id=pkt_id, secret=RADIUS_SECRET.encode('utf-8'), dict=dictionary)
        pkt["User-Name"] = username
        pkt["User-Password"] = pkt.PwCrypt(password)
        logger.debug(f"RADIUS authentication packet created for {username} with ID {pkt_id}")
        reply = client.SendPacket(pkt)
        if reply.code == 2:  # Access-Accept
            logger.debug(f"RADIUS authentication successful for {username}")
            return True
        else:
            logger.debug(f"RADIUS authentication rejected for {username}, reply code: {reply.code}")
            return False
    except Exception as e:
        logger.error(f"RADIUS authentication failed for {username}: {str(e)}")
        return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form.get('totp_code', '')
        logger.debug(f"Login attempt for username: {username}, TOTP_ENABLED: {TOTP_ENABLED}")

        with db_lock:
            conn = db_pool.getconn()
            c = conn.cursor()
            c.execute("SELECT password, first_login, totp_secret, is_radius_user FROM users WHERE username = %s", (username,))
            user = c.fetchone()
            conn.close()
            db_pool.putconn(conn)

        authenticated = False
        is_radius_user = False
        if user and user[0] == password:
            authenticated = True
            logger.debug(f"Local authentication successful for {username}")
        elif verify_radius(username, password):
            authenticated = True
            is_radius_user = True
            with db_lock:
                conn = db_pool.getconn()
                c = conn.cursor()
                c.execute("SELECT id FROM users WHERE username = %s", (username,))
                if not c.fetchone():
                    execute_with_retry(c, "INSERT INTO users (username, password, first_login, is_radius_user) VALUES (%s, %s, %s, %s)",
                                      (username, '', 0, True))  # Set first_login to 0 for RADIUS users
                    conn.commit()
                    logger.info(f"Created user entry for RADIUS user: {username}")
                else:
                    execute_with_retry(c, "UPDATE users SET is_radius_user = %s, first_login = %s WHERE username = %s", 
                                      (True, 0, username))  # Set first_login to 0 for existing RADIUS users
                    conn.commit()
                    logger.info(f"Updated user entry to mark {username} as RADIUS user")
                conn.close()
                db_pool.putconn(conn)
                
        if authenticated and TOTP_ENABLED and not is_radius_user:
            if user and user[2]:
                totp = pyotp.TOTP(user[2])
                if not totp.verify(totp_code):
                    log_activity(username, "Login Failed", "Invalid TOTP code")
                    return render_template('login.html', error="Invalid TOTP code", totp_enabled=TOTP_ENABLED)
            else:
                log_activity(username, "Login Failed", "TOTP required but no secret found")
                return render_template('login.html', error="TOTP required but no secret found", totp_enabled=TOTP_ENABLED)

        if authenticated:
            session['logged_in'] = True
            session['username'] = username
            session['is_radius_user'] = is_radius_user  # Store RADIUS status in session
            session['last_activity'] = datetime.datetime.now(tz)
            session['x_forwarded_for'] = request.headers.get('X-Forwarded-For')
            log_activity(username, "Login Success", "User logged in")
            if user and user[1] == 1 and not is_radius_user:  # Only redirect non-RADIUS users on first login
                return redirect(url_for('change_password'))
            return redirect(url_for('index'))
        else:
            log_activity(username, "Login Failed", "Invalid credentials")
            return render_template('login.html', error="Invalid credentials", totp_enabled=TOTP_ENABLED)
    return render_template('login.html', totp_enabled=TOTP_ENABLED)

@app.route('/logout')
@login_required
def logout():
    username = session.get('username', 'unknown')
    session.clear()
    log_activity(username, "Logout", "User logged out")
    return redirect(url_for('login'))

@app.route('/activity_log')
@login_required
def activity_log():
    try:
        with db_lock:
            conn = db_pool.getconn()
            c = conn.cursor()
            c.execute("SELECT username, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC")
            logs = c.fetchall()
            conn.close()
            db_pool.putconn(conn)
        return render_template('activity_log.html', logs=logs)
    except Exception as e:
        logger.error(f"Failed to retrieve activity logs: {str(e)}")
        return render_template('activity_log.html', logs=[], error="Failed to load activity logs")

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        if 'csv_file' in request.files:
            csv_file = request.files['csv_file']
            if csv_file.filename == '':
                return render_template('index.html', error="No file selected", firewalls=[])
            if not csv_file.filename.endswith('.csv'):
                return render_template('index.html', error="File must be a CSV", firewalls=[])

            with db_lock:
                conn = db_pool.getconn()
                c = conn.cursor()
                errors = []
                added_firewalls = []
                try:
                    stream = io.StringIO(csv_file.stream.read().decode("UTF-8"), newline=None)
                    csv_reader = csv.DictReader(stream)
                    required_headers = {'fqdn', 'interval_minutes', 'retention_count'}
                    if not required_headers.issubset(csv_reader.fieldnames):
                        return render_template('index.html', error="CSV must contain fqdn, interval_minutes, retention_count headers", firewalls=[])

                    for row in csv_reader:
                        try:
                            fqdn = row['fqdn'].strip()
                            username = row.get('username', '').strip() or os.getenv('DEFAULT_SCP_USER', 'admin')
                            password = row.get('password', '').strip() or os.getenv('DEFAULT_SCP_PASSWORD', '')
                            interval_minutes = int(row['interval_minutes'])
                            retention_count = int(row['retention_count'])
                            ssh_port = int(row.get('ssh_port', '9422') or '9422')

                            if not fqdn:
                                errors.append(f"Missing FQDN in row: {row}")
                                continue

                            execute_with_retry(c, '''INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port)
                                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id''',
                                              (fqdn, username, password, interval_minutes, retention_count, None, 'New', ssh_port))
                            fw_id = c.fetchone()[0]
                            added_firewalls.append(fw_id)

                            log_activity(session['username'], "Create Firewall", f"Created firewall with ID {fw_id} and FQDN {fqdn} via bulk upload")

                            job_id = f"backup_firewall_{fw_id}"
                            if not scheduler.get_job(job_id):
                                initial_delay = len(added_firewalls) * 10  # Stagger by 10 seconds
                                scheduler.add_job(id=job_id, func=backup_firewall, args=[fw_id],
                                                 trigger='interval', minutes=interval_minutes, start_date=datetime.datetime.now(tz) + datetime.timedelta(seconds=initial_delay),
                                                 coalesce=True, max_instances=1)
                                logger.debug(f"Scheduled job {job_id} for fw_id {fw_id} with interval {interval_minutes} minutes, initial delay {initial_delay} seconds")
                            else:
                                logger.warning(f"Job {job_id} already exists for fw_id {fw_id}, skipping scheduling")

                        except (ValueError, KeyError) as e:
                            errors.append(f"Invalid data in row {row}: {str(e)}")
                            continue

                    conn.commit()
                    logger.info(f"Committed {len(added_firewalls)} new firewalls to PostgreSQL via bulk upload")
                    conn.close()
                    db_pool.putconn(conn)

                    if errors:
                        error_msg = "Some firewalls were not added due to errors: " + "; ".join(errors)
                        with db_lock:
                            conn = db_pool.getconn()
                            c = conn.cursor()
                            c.execute("SELECT * FROM firewalls")
                            firewalls = c.fetchall()
                            conn.close()
                            db_pool.putconn(conn)
                        return render_template('index.html', error=error_msg, firewalls=firewalls, first_login=False)
                    
                    return redirect(url_for('index'))

                except Exception as e:
                    conn.close()
                    db_pool.putconn(conn)
                    return render_template('index.html', error=f"Failed to process CSV: {str(e)}", firewalls=[])

        elif 'username' in request.form and 'password' in request.form and 'new_password' in request.form and 'confirm_password' in request.form:
            old_password = request.form['password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if new_password != confirm_password:
                return "New passwords do not match", 400
            with db_lock:
                conn = db_pool.getconn()
                c = conn.cursor()
                c.execute("SELECT first_login FROM users WHERE username = %s AND password = %s", 
                         (session['username'], old_password if not session['first_login'] else session['password']))
                result = c.fetchone()
                if result:
                    execute_with_retry(c, "UPDATE users SET password = %s, first_login = 0 WHERE username = %s AND password = %s",
                                      (new_password, session['username'], old_password if not result[0] else session['password']))
                    if c.rowcount > 0:
                        session['password'] = new_password
                        conn.commit()
                        logger.info("Committed password change to PostgreSQL")
                        log_activity(session['username'], "Change Password", "Password changed successfully")
                        return redirect(url_for('index'))
                conn.close()
                db_pool.putconn(conn)
                return "Old password incorrect or update failed", 400
        else:
            fqdn = request.form['fqdn']
            username = request.form['username'] or os.getenv('DEFAULT_SCP_USER', 'admin')
            password = request.form['password'] or os.getenv('DEFAULT_SCP_PASSWORD', '')
            try:
                interval_minutes = int(request.form['interval_minutes'])
                retention_count = int(request.form['retention_count'])
                ssh_port = int(request.form.get('ssh_port', '9422'))
            except ValueError as e:
                return render_template('index.html', error=f"Invalid input: {str(e)}", firewalls=[])

            with db_lock:
                conn = db_pool.getconn()
                c = conn.cursor()
                execute_with_retry(c, '''INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port)
                                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id''',
                                  (fqdn, username, password, interval_minutes, retention_count, None, 'New', ssh_port))
                fw_id = c.fetchone()[0]
                conn.commit()
                logger.info(f"Committed new firewall (ID: {fw_id}) to PostgreSQL")
                conn.close()
                db_pool.putconn(conn)

            log_activity(session['username'], "Create Firewall", f"Created firewall with ID {fw_id} and FQDN {fqdn}")

            job_id = f"backup_firewall_{fw_id}"
            if not scheduler.get_job(job_id):
                scheduler.add_job(id=job_id, func=backup_firewall, args=[fw_id],
                                 trigger='interval', minutes=interval_minutes, start_date=datetime.datetime.now(tz) + datetime.timedelta(seconds=10),
                                 coalesce=True, max_instances=1)
                logger.debug(f"Scheduled job {job_id} for fw_id {fw_id} with interval {interval_minutes} minutes, initial delay 10 seconds")
            else:
                logger.warning(f"Job {job_id} already exists for fw_id {fw_id}, skipping scheduling")

    with db_lock:
        conn = db_pool.getconn()
        c = conn.cursor()
        c.execute("SELECT * FROM firewalls")
        firewalls = c.fetchall()
        conn.close()
        db_pool.putconn(conn)

    with db_lock:
        conn = db_pool.getconn()
        c = conn.cursor()
        c.execute("SELECT first_login FROM users WHERE username = %s", (session['username'],))
        result = c.fetchone()
        if result is None:
            logger.warning(f"User {session['username']} not found in users table, setting first_login to False")
            first_login = False
        else:
            first_login = result[0]
        conn.close()
        db_pool.putconn(conn)

    if first_login and not session.get('is_radius_user', False):
        return redirect(url_for('change_password'))
    return render_template('index.html', firewalls=firewalls, first_login=first_login)

@app.route('/backups/<int:fw_id>')
@login_required
def list_backups(fw_id):
    try:
        with db_lock:
            conn = db_pool.getconn()
            c = conn.cursor()
            c.execute("SELECT DISTINCT * FROM backups WHERE fw_id = %s ORDER BY timestamp DESC", (fw_id,))
            backups = c.fetchall()
            conn.close()
            db_pool.putconn(conn)
        return render_template('backups.html', backups=backups, fw_id=fw_id)
    except Exception as e:
        logger.error(f"Failed to retrieve backups for fw_id {fw_id}: {str(e)}")
        return render_template('backups.html', backups=[], fw_id=fw_id, error="Failed to load backups")

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    try:
        log_activity(session['username'], "Download Config", f"Downloaded configuration file: {filename}")
        return send_from_directory(BACKUP_DIR, filename)
    except Exception as e:
        logger.error(f"Failed to download file {filename}: {str(e)}")
        return render_template('index.html', error=f"Failed to download file: {str(e)}", firewalls=[])

@app.route('/delete/<int:fw_id>')
@login_required
def delete_firewall(fw_id):
    try:
        with db_lock:
            conn = db_pool.getconn()
            c = conn.cursor()
            c.execute("SELECT fqdn FROM firewalls WHERE id = %s", (fw_id,))
            fw = c.fetchone()
            if not fw:
                conn.close()
                db_pool.putconn(conn)
                log_activity(session['username'], "Delete Firewall Failed", f"Firewall not found: fw_id {fw_id}")
                return redirect(url_for('index', error="Firewall not found"))
            fqdn = fw[0]
            execute_with_retry(c, "DELETE FROM backups WHERE fw_id = %s", (fw_id,))
            execute_with_retry(c, "DELETE FROM firewalls WHERE id = %s", (fw_id,))
            conn.commit()
            logger.info(f"Deleted firewall: {fqdn} with ID {fw_id}")
            conn.close()
            db_pool.putconn(conn)

        fw_dir = os.path.join(BACKUP_DIR, str(fw_id))
        if os.path.exists(fw_dir):
            shutil.rmtree(fw_dir)
            logger.info(f"Deleted backup directory for fw_id {fw_id}")

        job_id = f"backup_firewall_{fw_id}"
        if job_id in [job.id for job in scheduler.get_jobs()]:
            scheduler.remove_job(job_id)
            logger.debug(f"Removed scheduled job {job_id}")
        log_activity(session['username'], "Delete Firewall", f"Deleted firewall {fqdn} with ID {fw_id}")
    except Exception as e:
        logger.error(f"Failed to delete firewall fw_id {fw_id}: {str(e)}")
        log_activity(session['username'], "Delete Firewall Failed", f"Failed to delete firewall fw_id {fw_id}: {str(e)}")
        return redirect(url_for('index', error=str(e)))
    return redirect(url_for('index'))

@app.route('/errors')
@login_required
def view_errors():
    try:
        with db_lock:
            conn = db_pool.getconn()
            c = conn.cursor()
            c.execute("SELECT id, fqdn, last_backup, status FROM firewalls WHERE status LIKE 'Failed:%'")
            errors = c.fetchall()
            conn.close()
            db_pool.putconn(conn)
        return render_template('errors.html', errors=errors)
    except Exception as e:
        logger.error(f"Failed to retrieve errors: {str(e)}")
        return render_template('errors.html', errors=[], error="Failed to load errors")

@app.route('/backup_now/<int:fw_id>')
@login_required
def backup_now(fw_id):
    logger.info(f"Manual backup triggered for fw_id {fw_id}")
    backup_firewall(fw_id)
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Disable password change for RADIUS users
    if session.get('is_radius_user', False):
        log_activity(session['username'], "Password Change Attempt", "Password change denied for RADIUS user")
        return redirect(url_for('index', error="Password change is not allowed for RADIUS users"))

    #
    if request.method == 'POST':
        old_password = request.form['old_password'] if not session.get('first_login') else session['password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match", first_login=session.get('first_login', False))
        try:
            with db_lock:
                conn = db_pool.getconn()
                c = conn.cursor()
                c.execute("SELECT password FROM users WHERE username = %s AND password = %s", 
                         (session['username'], old_password))
                result = c.fetchone()
                if result:
                    execute_with_retry(c, "UPDATE users SET password = %s, first_login = 0 WHERE username = %s AND password = %s",
                                      (new_password, session['username'], old_password))
                    if c.rowcount > 0:
                        session['password'] = new_password
                        conn.commit()
                        logger.info("Committed password change to PostgreSQL")
                        log_activity(session['username'], "Change Password", "Password changed successfully")
                        logger.info("Redirecting to index...")
                        return redirect(url_for('index'))
                conn.close()
                db_pool.putconn(conn)
                return render_template('change_password.html', error="Old password incorrect", first_login=session.get('first_login', False))
        except Exception as e:
            logger.error(f"Failed to change password: {str(e)}", exc_info=True)
            return render_template('change_password.html', error=f"Failed to change password: {str(e)}", first_login=session.get('first_login', False))
    return render_template('change_password.html', first_login=session.get('first_login', False))

def get_latest_backup_write_time(fw_id):
    """Retrieve the last write time of the most recent .conf file for the given fw_id."""
    try:
        fw_dir = os.path.join(BACKUP_DIR, str(fw_id))
        if not os.path.exists(fw_dir):
            logger.info(f"No backup directory found for fw_id {fw_id}")
            return None
        conf_files = [f for f in os.listdir(fw_dir) if f.endswith('.conf')]
        if not conf_files:
            logger.info(f"No .conf files found in {fw_dir}")
            return None
        latest_file = max(conf_files, key=lambda f: os.path.getmtime(os.path.join(fw_dir, f)))
        write_time = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(fw_dir, latest_file)), tz=tz)
        logger.info(f"Latest .conf file for fw_id {fw_id}: {latest_file}, last write time: {write_time}")
        return write_time
    except Exception as e:
        logger.error(f"Failed to get latest backup write time for fw_id {fw_id}: {str(e)}", exc_info=True)
        return None

def clean_nonexistent_backups(conn, fw_id):
    """Remove backup entries for non-existent files and orphaned files for the specified fw_id in BACKUP_DIR."""
    try:
        c = conn.cursor()
        logger.info(f"Querying backups table for fw_id {fw_id}...")
        c.execute("SELECT id, filename FROM backups WHERE fw_id = %s LIMIT 100", (fw_id,))
        backups = c.fetchall()
        logger.info(f"Retrieved {len(backups)} backup entries for fw_id {fw_id}.")
        backup_filenames = {b[1] for b in backups}  # Set of filenames in database
        for backup_id, filename in backups:
            file_path = os.path.join(BACKUP_DIR, filename)
            logger.debug(f"Checking file: {file_path}")
            if not os.path.exists(file_path):
                logger.warning(f"Removing non-existent backup entry: {filename}")
                execute_with_retry(c, "DELETE FROM backups WHERE id = %s", (backup_id,))
        # Check for orphaned files in BACKUP_DIR for this fw_id
        fw_dir = os.path.join(BACKUP_DIR, str(fw_id))
        logger.info(f"Checking for orphaned files in {fw_dir}...")
        if os.path.exists(fw_dir):
            for file in os.listdir(fw_dir):
                rel_path = os.path.join(str(fw_id), file)
                if rel_path not in backup_filenames:
                    file_path = os.path.join(fw_dir, file)
                    logger.warning(f"Removing orphaned file: {file_path}")
                    os.remove(file_path)
        conn.commit()
        logger.info(f"Committed changes to PostgreSQL in clean_nonexistent_backups for fw_id {fw_id}")
    except Exception as e:
        logger.error(f"Failed to clean non-existent backups for fw_id {fw_id}: {str(e)}", exc_info=True)

def backup_firewall(fw_id, retries=3, timeout=SCP_TIMEOUT):
    try:
        logger.info(f"Starting backup job for fw_id {fw_id}, active workers: {threading.active_count()}")
        conn = db_pool.getconn()
        c = conn.cursor()
        c.execute("SELECT fqdn, username, password, retention_count, ssh_port FROM firewalls WHERE id = %s", (fw_id,))
        fw = c.fetchone()
        conn.close()
        db_pool.putconn(conn)

        if not fw:
            logger.warning(f"No firewall found for fw_id {fw_id}")
            return

        fqdn, username, password, retention_count, ssh_port = fw
        timestamp = datetime.datetime.now(tz).strftime('%Y%m%d_%H%M%S')
        fw_dir = os.path.join(BACKUP_DIR, str(fw_id))
        os.makedirs(fw_dir, exist_ok=True)
        filename = f"{timestamp}.conf"
        local_path = os.path.join(fw_dir, filename)
        status = 'Success'

        # Check for successful backups in the last 24 hours
        should_notify = True
        conn = db_pool.getconn()
        c = conn.cursor()
        c.execute("SELECT timestamp FROM backups WHERE fw_id = %s ORDER BY timestamp DESC LIMIT 1", (fw_id,))
        last_backup = c.fetchone()
        conn.close()
        db_pool.putconn(conn)
        if last_backup:
            try:
                last_backup_time = datetime.datetime.strptime(last_backup[0], '%Y%m%d_%H%M%S').replace(tzinfo=tz)
                time_diff = datetime.datetime.now(tz) - last_backup_time
                should_notify = time_diff.total_seconds() > 24 * 3600  # 24 hours in seconds
                logger.debug(f"Last successful backup for fw_id {fw_id} was at {last_backup[0]}, notifying: {should_notify}")
            except ValueError:
                logger.warning(f"Invalid timestamp format for fw_id {fw_id}: {last_backup[0]}, will notify")
                should_notify = True
        else:
            logger.debug(f"No successful backups found for fw_id {fw_id}, will notify")

        try:
            perms = oct(os.stat(BACKUP_DIR).st_mode & 0o777)
            logger.debug(f"Backup directory permissions: {perms}")
        except Exception as e:
            logger.error(f"Failed to check backup directory permissions: {str(e)}")

        for attempt in range(1, retries + 1):
            ssh = None
            scp_client = None
            try:
                logger.debug(f"Starting backup for fw_id {fw_id} on {fqdn}:{ssh_port} with username {username}, attempt {attempt}/{retries}")
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(fqdn, username=username, password=password, port=ssh_port, timeout=timeout, look_for_keys=False, allow_agent=False)
                transport = ssh.get_transport()
                transport.set_keepalive(60)
                logger.debug(f"SSH connection established to {fqdn} with keep-alive")

                try:
                    stdin, stdout, stderr = ssh.exec_command(f"ls {REMOTE_CONFIG_PATH}")
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0:
                        error = stderr.read().decode().strip()
                        logger.warning(f"Remote file check failed for {REMOTE_CONFIG_PATH} on {fqdn}: {error}. Proceeding with SCP transfer.")
                    else:
                        logger.debug(f"Remote file {REMOTE_CONFIG_PATH} exists on {fqdn}")
                except Exception as e:
                    logger.warning(f"Failed to check remote file {REMOTE_CONFIG_PATH} on {fqdn}: {str(e)}. Proceeding with SCP transfer.")

                scp_client = scp.SCPClient(ssh.get_transport(), socket_timeout=timeout)
                logger.debug(f"Attempting SCP transfer of {REMOTE_CONFIG_PATH} to {local_path}")
                scp_client.get(REMOTE_CONFIG_PATH, local_path)
                scp_client.close()
                logger.debug(f"SCP transfer completed for {fqdn}")
                if not os.path.exists(local_path):
                    raise Exception("Backup file was not created")
                if os.path.getsize(local_path) == 0:
                    os.remove(local_path)
                    raise Exception("Backup file is empty")
                logger.debug(f"Backup successful for {fqdn}, saved to {local_path}")

                logger.info(f"Acquiring database connection for backup update (fw_id {fw_id})...")
                conn = db_pool.getconn()
                c = conn.cursor()
                logger.info(f"Inserting backup entry for fw_id {fw_id}...")
                execute_with_retry(c, "INSERT INTO backups (fw_id, timestamp, filename) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                                  (fw_id, timestamp, os.path.join(str(fw_id), filename)))
                logger.info(f"Querying existing backups for fw_id {fw_id}...")
                c.execute("SELECT filename FROM backups WHERE fw_id = %s ORDER BY timestamp DESC", (fw_id,))
                all_backups = c.fetchall()
                logger.info(f"Retrieved {len(all_backups)} backups for fw_id {fw_id}")
                if len(all_backups) > retention_count:
                    to_delete = all_backups[retention_count:]
                    for del_file in to_delete:
                        file_path = os.path.join(BACKUP_DIR, del_file[0])
                        logger.debug(f"Checking file for deletion: {file_path}")
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            logger.debug(f"Deleted file: {file_path}")
                        execute_with_retry(c, "DELETE FROM backups WHERE filename = %s", (del_file[0],))
                logger.info(f"Cleaning non-existent backups for fw_id {fw_id}...")
                clean_nonexistent_backups(conn, fw_id)
                logger.info(f"Non-existent backups cleaned for fw_id {fw_id}")
                logger.info(f"Updating firewall status for fw_id {fw_id}...")
                execute_with_retry(c, "UPDATE firewalls SET last_backup = %s, status = %s WHERE id = %s",
                                  (timestamp, status, fw_id))
                logger.info(f"Committing backup changes for fw_id {fw_id}...")
                conn.commit()
                logger.info(f"Committed backup and status update for fw_id {fw_id} to PostgreSQL")
                logger.info(f"Closing database connection for fw_id {fw_id}...")
                conn.close()
                db_pool.putconn(conn)
                logger.info(f"Database connection closed for fw_id {fw_id}")
                break
            except (socket.timeout, paramiko.SSHException, scp.SCPException) as e:
                logger.error(f"Backup attempt {attempt}/{retries} failed for {fqdn}: {str(e)}")
                if attempt == retries:
                    status = f'Failed: {str(e)}'
                    if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                        os.remove(local_path)
                    if should_notify:
                        send_email(f"Backup Failure Notification - {fqdn}", f"Backup failed for {fqdn} at {timestamp}: {str(e)}", MAIL_RECIPIENT)
                    else:
                        logger.info(f"Skipping email notification for fw_id {fw_id} as last successful backup is recent")
                else:
                    continue
            except Exception as e:
                logger.error(f"Unexpected error during backup attempt {attempt}/{retries} for {fqdn}: {str(e)}")
                status = f'Failed: {str(e)}'
                if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                    os.remove(local_path)
                if should_notify:
                    send_email(f"Backup Failure Notification - {fqdn}", f"Backup failed for {fqdn} at {timestamp}: {str(e)}", MAIL_RECIPIENT)
                else:
                    logger.info(f"Skipping email notification for fw_id {fw_id} as last successful backup is recent")
                break
            finally:
                if 'scp_client' in locals() and scp_client:
                    scp_client.close()
                if ssh:
                    ssh.close()
        if status != 'Success':
            logger.info(f"Acquiring database connection for failure update (fw_id {fw_id})...")
            conn = db_pool.getconn()
            c = conn.cursor()
            execute_with_retry(c, "UPDATE firewalls SET status = %s WHERE id = %s",
                              (status, fw_id))
            conn.commit()
            logger.info(f"Committed firewall status update for fw_id {fw_id} to PostgreSQL")
            conn.close()
            db_pool.putconn(conn)
    except Exception as e:
        logger.error(f"Backup job for fw_id {fw_id} failed: {str(e)}")
        if should_notify:
            send_email(f"Backup Failure Notification - fw_id {fw_id}", f"Backup job failed for fw_id {fw_id}: {str(e)}", MAIL_RECIPIENT)
        else:
            logger.info(f"Skipping email notification for fw_id {fw_id} as last successful backup is recent")

if __name__ == '__main__':
    try:
        logger.info("Starting application initialization...")

        # Step 1: Initialize database
        logger.info("Initializing database...")
        init_db()
        logger.info("Database initialization complete.")

        # Step 2: Create backup directory
        logger.info("Creating backup directory...")
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            logger.info(f"Backup directory {BACKUP_DIR} created or exists.")
            perms = oct(os.stat(BACKUP_DIR).st_mode & 0o777)
            logger.info(f"Backup directory permissions: {perms}")
        except Exception as e:
            logger.error(f"Failed to create backup directory {BACKUP_DIR}: {str(e)}", exc_info=True)
            raise

        # Step 3: Query firewalls table and schedule missing jobs
        logger.info("Querying firewalls table...")
        with db_lock:
            conn = db_pool.getconn()
            try:
                c = conn.cursor()
                c.execute("SELECT id, interval_minutes FROM firewalls")
                firewalls = c.fetchall()
                logger.info(f"Retrieved {len(firewalls)} firewalls from database: {firewalls}")
            except Exception as e:
                logger.error(f"Failed to query firewalls table: {str(e)}", exc_info=True)
                raise
            finally:
                conn.close()
                db_pool.putconn(conn)

        # Step 4: Schedule backup jobs if not already scheduled
        logger.info("Scheduling backup jobs...")
        existing_jobs = {job.id for job in scheduler.get_jobs()}
        for index, (fw_id, interval_minutes) in enumerate(firewalls):
            if interval_minutes is None or interval_minutes <= 0:
                logger.warning(f"Invalid interval_minutes for fw_id {fw_id}: {interval_minutes}, skipping job.")
                continue
            job_id = f"backup_firewall_{fw_id}"
            if job_id not in existing_jobs:
                initial_delay = index * 10
                try:
                    scheduler.add_job(id=job_id, func=backup_firewall, args=[fw_id],
                                     trigger='interval', minutes=interval_minutes,
                                     start_date=datetime.datetime.now(tz) + datetime.timedelta(seconds=initial_delay),
                                     coalesce=True, max_instances=1)
                    logger.debug(f"Scheduled job {job_id} for fw_id {fw_id} with interval {interval_minutes} minutes, initial_delay {initial_delay} seconds")
                except Exception as e:
                    logger.error(f"Failed to schedule job for fw_id {fw_id}: {str(e)}", exc_info=True)
                    raise
            else:
                logger.info(f"Job {job_id} for fw_id {fw_id} already exists, skipping.")

        logger.info("Current scheduled jobs:")
        for job in scheduler.get_jobs():
            logger.info(f"Job ID: {job.id}, Next run: {job.next_run_time}")

        # Step 5: Start Flask server
        logger.info("Starting Flask server on 0.0.0.0:8521...")
        app.run(host='0.0.0.0', port=8521, debug=True, use_reloader=False)
    except Exception as e:
        logger.error(f"Application startup failed: {str(e)}", exc_info=True)
        raise
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, shutting down...")
        scheduler.shutdown()
    except SystemExit:
        logger.info("Received SystemExit, shutting down...")
        scheduler.shutdown()
    finally:
        logger.info("Application shutdown complete.")