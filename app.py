from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, abort
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
import paramiko
import scp
import os
import datetime
import sqlite3
import shutil
import logging
import smtplib
from email.mime.text import MIMEText
from functools import wraps
from datetime import timedelta
import pytz
import pyotp
import radius
import csv
import io
import socket
import threading

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)  # For session management
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1-hour session timeout
app.config['PREFERRED_URL_SCHEME'] = 'https'  # Support reverse proxy with HTTPS

# Configure scheduler with ThreadPoolExecutor to limit parallel tasks
executors = {
    'default': ThreadPoolExecutor(max_workers=2000)  # Limit to 2 concurrent backup tasks
}
scheduler = BackgroundScheduler(job_defaults={'coalesce': True, 'max_instances': 1}, executors=executors)
scheduler.start()

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB = '/app/data/firewalls.db'
ACTIVITY_DB = '/app/data/activity_log.db'
BACKUP_DIR = 'backups'
REMOTE_CONFIG_PATH = os.getenv('FORTIGATE_CONFIG_PATH', 'sys_config')
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')
MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
MAIL_USER = os.getenv('MAIL_USER', 'user@example.com')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'password')
MAIL_RECIPIENT = os.getenv('MAIL_RECIPIENT', MAIL_USER)  # Default to MAIL_USER if not set
TOTP_ENABLED = os.getenv('TOTP_ENABLED', 'false').lower() == 'true'
TOTP_SECRET = os.getenv('TOTP_SECRET', pyotp.random_base32())  # Generate random secret if not provided
RADIUS_ENABLED = os.getenv('RADIUS_ENABLED', 'false').lower() == 'true'
RADIUS_SERVER = os.getenv('RADIUS_SERVER', 'localhost')
RADIUS_PORT = int(os.getenv('RADIUS_PORT', 1812))
RADIUS_SECRET = os.getenv('RADIUS_SECRET', 'secret')
SCP_TIMEOUT = int(os.getenv('SCP_TIMEOUT', 120))  # Default to 120 seconds for SCP transfers

# Log environment variables for debugging
logger.info(f"TOTP_ENABLED set to: {TOTP_ENABLED}")
logger.info(f"SCP_TIMEOUT set to: {SCP_TIMEOUT} seconds")

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

def init_db():
    # Initialize firewalls.db
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS firewalls
                 (id INTEGER PRIMARY KEY, fqdn TEXT, username TEXT, password TEXT,
                  interval_minutes INTEGER, retention_count INTEGER,
                  last_backup TEXT, status TEXT, ssh_port INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS backups
                 (id INTEGER PRIMARY KEY, fw_id INTEGER, timestamp TEXT, filename TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, first_login INTEGER DEFAULT 1)''')
    # Check if totp_secret column exists and add it if not
    c.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in c.fetchall()]
    if 'totp_secret' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    # Insert or update admin user
    c.execute("INSERT OR IGNORE INTO users (username, password, first_login) VALUES (?, ?, ?)", 
              ("admin", "changeme", 1))
    # Update TOTP secret for admin user if TOTP is enabled
    if TOTP_ENABLED:
        c.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (TOTP_SECRET, "admin"))
        logger.info(f"Updated TOTP secret for admin user to: {TOTP_SECRET}")
    else:
        c.execute("UPDATE users SET totp_secret = NULL WHERE username = ?", ("admin",))
        logger.info("TOTP disabled, set admin TOTP secret to NULL")
    conn.commit()
    logger.info("Committed changes to firewalls.db in init_db")
    c.execute("PRAGMA table_info(firewalls)")
    columns = [col[1] for col in c.fetchall()]
    if 'ssh_port' not in columns:
        c.execute("ALTER TABLE firewalls ADD COLUMN ssh_port INTEGER DEFAULT 9422")
    c.execute("UPDATE firewalls SET interval_minutes = 180 WHERE interval_minutes IS NULL")
    c.execute('''DELETE FROM backups WHERE id NOT IN (
        SELECT MIN(id) FROM backups GROUP BY fw_id, filename
    )''')
    logger.info("Removed duplicate backup entries to enforce unique constraint")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_backups_unique ON backups (fw_id, filename)")
    conn.commit()
    logger.info("Committed changes to firewalls.db after backups cleanup")
    clean_nonexistent_backups(conn)
    conn.close()

    # Initialize activity_log.db
    conn = sqlite3.connect(ACTIVITY_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY, username TEXT, action TEXT, details TEXT, timestamp TEXT)''')
    conn.commit()
    logger.info("Committed changes to activity_log.db in init_db")
    conn.close()

def clean_nonexistent_backups(conn):
    c = conn.cursor()
    c.execute("SELECT id, filename FROM backups")
    backups = c.fetchall()
    for backup_id, filename in backups:
        file_path = os.path.join(BACKUP_DIR, filename)
        if not os.path.exists(file_path):
            logger.warning(f"Removing non-existent backup entry: {filename}")
            c.execute("DELETE FROM backups WHERE id = ?", (backup_id,))
    conn.commit()
    logger.info("Committed changes to firewalls.db in clean_nonexistent_backups")

def log_activity(username, action, details):
    try:
        conn = sqlite3.connect(ACTIVITY_DB)
        c = conn.cursor()
        timestamp = datetime.datetime.now(tz).strftime('%Y-%m-%d %H:%M:%S')
        c.execute("INSERT INTO activity_logs (username, action, details, timestamp) VALUES (?, ?, ?, ?)",
                  (username, action, details, timestamp))
        conn.commit()
        logger.info(f"Logged activity and committed to activity_log.db: {username} - {action} - {details}")
    except Exception as e:
        logger.error(f"Failed to log activity: {str(e)}")
    finally:
        conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        # Check session timeout or X-Forwarded-For change
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
        r = radius.Radius(RADIUS_SECRET.encode('utf-8'), host=RADIUS_SERVER, port=RADIUS_PORT)
        return r.authenticate(username, password)
    except Exception as e:
        logger.error(f"RADIUS authentication failed: {str(e)}")
        return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form.get('totp_code', '')
        logger.debug(f"Login attempt for username: {username}, TOTP_ENABLED: {TOTP_ENABLED}")

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT password, first_login, totp_secret FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        authenticated = False
        if user and user[0] == password:
            authenticated = True
            logger.debug(f"Local authentication successful for {username}")
        elif verify_radius(username, password):
            authenticated = True
            logger.debug(f"RADIUS authentication successful for {username}")

        if authenticated:
            if TOTP_ENABLED and user and user[2]:
                totp = pyotp.TOTP(user[2])
                if not totp.verify(totp_code):
                    logger.debug(f"Invalid TOTP code for {username}")
                    return render_template('login.html', error="Invalid TOTP code", totp_enabled=TOTP_ENABLED)
                logger.debug(f"TOTP verification successful for {username}")
            session['logged_in'] = True
            session['username'] = username
            session['password'] = password
            session['last_activity'] = datetime.datetime.now(tz)
            session['x_forwarded_for'] = request.headers.get('X-Forwarded-For')
            session['first_login'] = user[1] if user else False
            log_activity(username, "Login", "Successful login")
            if session['first_login']:
                logger.debug(f"Redirecting {username} to change_password due to first login")
                return redirect(url_for('change_password'))
            logger.debug(f"Login successful for {username}, redirecting to index")
            return redirect(url_for('index'))
        logger.debug(f"Login failed for {username}: Invalid username or password")
        return render_template('login.html', error="Invalid username or password", totp_enabled=TOTP_ENABLED)
    logger.debug(f"Rendering login page, TOTP_ENABLED: {TOTP_ENABLED}")
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
        conn = sqlite3.connect(ACTIVITY_DB)
        c = conn.cursor()
        c.execute("SELECT username, action, details, timestamp FROM activity_logs ORDER BY timestamp DESC")
        logs = c.fetchall()
        conn.close()
        return render_template('activity_log.html', logs=logs)
    except Exception as e:
        logger.error(f"Failed to retrieve activity logs: {str(e)}")
        return render_template('activity_log.html', logs=[], error="Failed to load activity logs")

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        if 'csv_file' in request.files:
            # Handle bulk firewall addition via CSV
            csv_file = request.files['csv_file']
            if csv_file.filename == '':
                return render_template('index.html', error="No file selected", firewalls=[])
            if not csv_file.filename.endswith('.csv'):
                return render_template('index.html', error="File must be a CSV", firewalls=[])

            conn = sqlite3.connect(DB)
            c = conn.cursor()
            errors = []
            added_firewalls = []

            try:
                # Read CSV file
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

                        c.execute('''INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port)
                                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                                  (fqdn, username, password, interval_minutes, retention_count, None, 'New', ssh_port))
                        fw_id = c.lastrowid
                        added_firewalls.append(fw_id)

                        log_activity(session['username'], "Create Firewall", f"Created firewall with ID {fw_id} and FQDN {fqdn} via bulk upload")

                        job_id = f"backup_firewall_{fw_id}"
                        if not scheduler.get_job(job_id):
                            scheduler.add_job(id=job_id, func=backup_firewall, args=[fw_id],
                                             trigger='interval', minutes=interval_minutes,
                                             coalesce=True, max_instances=1)
                            logger.debug(f"Scheduled job {job_id} for fw_id {fw_id} with interval {interval_minutes} minutes")
                        else:
                            logger.warning(f"Job {job_id} already exists for fw_id {fw_id}, skipping scheduling")

                    except (ValueError, KeyError) as e:
                        errors.append(f"Invalid data in row {row}: {str(e)}")
                        continue

                conn.commit()
                logger.info(f"Committed {len(added_firewalls)} new firewalls to firewalls.db via bulk upload")
                conn.close()

                if errors:
                    error_msg = "Some firewalls were not added due to errors: " + "; ".join(errors)
                    conn = sqlite3.connect(DB)
                    c = conn.cursor()
                    c.execute("SELECT * FROM firewalls")
                    firewalls = c.fetchall()
                    conn.close()
                    return render_template('index.html', error=error_msg, firewalls=firewalls, first_login=False)
                
                return redirect(url_for('index'))

            except Exception as e:
                conn.close()
                return render_template('index.html', error=f"Failed to process CSV: {str(e)}", firewalls=[])

        elif 'username' in request.form and 'password' in request.form and 'new_password' in request.form and 'confirm_password' in request.form:
            # Handle password change
            old_password = request.form['password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if new_password != confirm_password:
                return "New passwords do not match", 400
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("SELECT first_login FROM users WHERE username = ? AND password = ?", 
                     (session['username'], old_password if not session['first_login'] else session['password']))
            result = c.fetchone()
            if result:
                c.execute("UPDATE users SET password = ?, first_login = 0 WHERE username = ? AND password = ?",
                          (new_password, session['username'], old_password if not result[0] else session['password']))
                if c.rowcount > 0:
                    session['password'] = new_password
                    conn.commit()
                    logger.info("Committed password change to firewalls.db")
                    log_activity(session['username'], "Change Password", "Password changed successfully")
                    return redirect(url_for('index'))
            conn.close()
            return "Old password incorrect or update failed", 400
        else:
            # Handle single firewall addition
            fqdn = request.form['fqdn']
            username = request.form['username'] or os.getenv('DEFAULT_SCP_USER', 'admin')
            password = request.form['password'] or os.getenv('DEFAULT_SCP_PASSWORD', '')
            try:
                interval_minutes = int(request.form['interval_minutes'])
                retention_count = int(request.form['retention_count'])
                ssh_port = int(request.form.get('ssh_port', '9422'))
            except ValueError as e:
                return render_template('index.html', error=f"Invalid input: {str(e)}", firewalls=[])

            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute('''INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (fqdn, username, password, interval_minutes, retention_count, None, 'New', ssh_port))
            fw_id = c.lastrowid
            conn.commit()
            logger.info(f"Committed new firewall (ID: {fw_id}) to firewalls.db")
            conn.close()

            log_activity(session['username'], "Create Firewall", f"Created firewall with ID {fw_id} and FQDN {fqdn}")

            job_id = f"backup_firewall_{fw_id}"
            if not scheduler.get_job(job_id):
                scheduler.add_job(id=job_id, func=backup_firewall, args=[fw_id],
                                 trigger='interval', minutes=interval_minutes,
                                 coalesce=True, max_instances=1)
                logger.debug(f"Scheduled job {job_id} for fw_id {fw_id} with interval {interval_minutes} minutes")
            else:
                logger.warning(f"Job {job_id} already exists for fw_id {fw_id}, skipping scheduling")

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT * FROM firewalls")
    firewalls = c.fetchall()
    conn.close()

    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT first_login FROM users WHERE username = ?", (session['username'],))
    first_login = c.fetchone()[0]
    conn.close()

    if first_login:
        return redirect(url_for('change_password'))
    return render_template('index.html', firewalls=firewalls, first_login=first_login)

@app.route('/backups/<int:fw_id>')
@login_required
def list_backups(fw_id):
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT DISTINCT * FROM backups WHERE fw_id = ? ORDER BY timestamp DESC", (fw_id,))
        backups = c.fetchall()
        conn.close()
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
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT fqdn FROM firewalls WHERE id = ?", (fw_id,))
        fw = c.fetchone()
        fqdn = fw[0] if fw else "unknown"
        c.execute("DELETE FROM firewalls WHERE id = ?", (fw_id,))
        c.execute("SELECT filename FROM backups WHERE fw_id = ?", (fw_id,))
        backup_files = c.fetchall()
        c.execute("DELETE FROM backups WHERE fw_id = ?", (fw_id,))
        c.execute("SELECT * FROM firewalls")
        firewalls = c.fetchall()
        conn.commit()
        logger.info(f"Committed firewall deletion (ID: {fw_id}) to firewalls.db")
        conn.close()

        log_activity(session['username'], "Delete Firewall", f"Deleted firewall with ID {fw_id} and FQDN {fqdn}")

        job_id = f"backup_firewall_{fw_id}"
        try:
            scheduler.remove_job(job_id)
            logger.debug(f"Removed job {job_id} for fw_id {fw_id}")
        except Exception as e:
            logger.warning(f"Failed to remove scheduler job {job_id} for fw_id {fw_id}: {str(e)}")

        fw_dir = os.path.join(BACKUP_DIR, str(fw_id))
        if os.path.exists(fw_dir):
            shutil.rmtree(fw_dir)

        return render_template('index.html', firewalls=firewalls, first_login=False)
    except Exception as e:
        logger.error(f"Failed to delete firewall {fw_id}: {str(e)}")
        return render_template('index.html', error=f"Failed to delete firewall: {str(e)}", firewalls=[])

@app.route('/errors')
@login_required
def view_errors():
    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT id, fqdn, last_backup, status FROM firewalls WHERE status LIKE 'Failed:%'")
        errors = c.fetchall()
        conn.close()
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
    if request.method == 'POST':
        old_password = request.form['old_password'] if not session.get('first_login') else session['password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            return render_template('change_password.html', error="New passwords do not match", first_login=session.get('first_login', False))
        try:
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username = ? AND password = ?", 
                     (session['username'], old_password))
            result = c.fetchone()
            if result:
                c.execute("UPDATE users SET password = ?, first_login = 0 WHERE username = ? AND password = ?",
                          (new_password, session['username'], old_password))
                if c.rowcount > 0:
                    session['password'] = new_password
                    conn.commit()
                    logger.info("Committed password change to firewalls.db")
                    log_activity(session['username'], "Change Password", "Password changed successfully")
                    return redirect(url_for('index'))
            conn.close()
            return render_template('change_password.html', error="Old password incorrect", first_login=session.get('first_login', False))
        except Exception as e:
            logger.error(f"Failed to change password: {str(e)}")
            return render_template('change_password.html', error=f"Failed to change password: {str(e)}", first_login=session.get('first_login', False))
    return render_template('change_password.html', first_login=session.get('first_login', False))

def backup_firewall(fw_id, retries=3, timeout=SCP_TIMEOUT):
    try:
        logger.info(f"Starting backup job for fw_id {fw_id}")
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT fqdn, username, password, retention_count, ssh_port FROM firewalls WHERE id = ?", (fw_id,))
        fw = c.fetchone()
        conn.close()

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

        # Check directory permissions
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

                # Check if remote file exists and is readable
                stdin, stdout, stderr = ssh.exec_command(f"ls {REMOTE_CONFIG_PATH}")
                exit_status = stdout.channel.recv_exit_status()
                if exit_status != 0:
                    error = stderr.read().decode().strip()
                    raise Exception(f"Remote file {REMOTE_CONFIG_PATH} does not exist: {error}")
                logger.debug(f"Remote file {REMOTE_CONFIG_PATH} exists on {fqdn}")

                # Use SCP for file transfer
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

                conn = sqlite3.connect(DB)
                c = conn.cursor()
                c.execute("INSERT OR IGNORE INTO backups (fw_id, timestamp, filename) VALUES (?, ?, ?)",
                          (fw_id, timestamp, os.path.join(str(fw_id), filename)))
                conn.commit()
                logger.info(f"Committed backup entry for fw_id {fw_id} to firewalls.db")

                c.execute("SELECT filename FROM backups WHERE fw_id = ? ORDER BY timestamp DESC", (fw_id,))
                all_backups = c.fetchall()
                if len(all_backups) > retention_count:
                    to_delete = all_backups[retention_count:]
                    for del_file in to_delete:
                        file_path = os.path.join(BACKUP_DIR, del_file[0])
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        c.execute("DELETE FROM backups WHERE filename = ?", (del_file[0],))
                clean_nonexistent_backups(conn)
                conn.commit()
                logger.info(f"Committed backup cleanup for fw_id {fw_id} to firewalls.db")
                conn.close()
                break  # Exit retry loop on success

            except (socket.timeout, paramiko.SSHException, scp.SCPException) as e:
                logger.error(f"Backup attempt {attempt}/{retries} failed for {fqdn}: {str(e)}")
                if attempt == retries:
                    status = f'Failed: {str(e)}'
                    if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                        os.remove(local_path)
                    send_email(f"Backup Failure Notification - {fqdn}", f"Backup failed for {fqdn} at {timestamp}: {str(e)}", MAIL_RECIPIENT)
                else:
                    continue  # Retry on failure
            except Exception as e:
                logger.error(f"Unexpected error during backup attempt {attempt}/{retries} for {fqdn}: {str(e)}")
                status = f'Failed: {str(e)}'
                if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                    os.remove(local_path)
                send_email(f"Backup Failure Notification - {fqdn}", f"Backup failed for {fqdn} at {timestamp}: {str(e)}", MAIL_RECIPIENT)
                break  # Do not retry on unexpected errors
            finally:
                if 'scp_client' in locals() and scp_client:
                    scp_client.close()
                if ssh:
                    ssh.close()

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("UPDATE firewalls SET last_backup = ?, status = ? WHERE id = ?",
                  (timestamp, status, fw_id))
        conn.commit()
        logger.info(f"Committed firewall status update for fw_id {fw_id} to firewalls.db")
        conn.close()
    except Exception as e:
        logger.error(f"Backup job for fw_id {fw_id} failed: {str(e)}")
        send_email(f"Backup Failure Notification - fw_id {fw_id}", f"Backup job failed for fw_id {fw_id}: {str(e)}", MAIL_RECIPIENT)

if __name__ == '__main__':
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)
        logger.debug(f"Cleared existing job {job.id}")

    init_db()
    os.makedirs(BACKUP_DIR, exist_ok=True)

    try:
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT id, interval_minutes FROM firewalls")
        for row in c.fetchall():
            fw_id, interval_minutes = row
            job_id = f"backup_firewall_{fw_id}"
            scheduler.add_job(id=job_id, func=backup_firewall, args=[fw_id],
                             trigger='interval', minutes=interval_minutes,
                             coalesce=True, max_instances=1)
            logger.debug(f"Scheduled job {job_id} for fw_id {fw_id} with interval {interval_minutes} minutes")
        conn.close()
    except Exception as e:
        logger.error(f"Failed to schedule backup jobs: {str(e)}")

    logger.info("Current scheduled jobs:")
    for job in scheduler.get_jobs():
        logger.info(f"Job ID: {job.id}, Next run: {job.next_run_time}")

    app.run(host='0.0.0.0', port=8521, debug=True, use_reloader=False)