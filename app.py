from flask import Flask, request, render_template, send_from_directory, redirect, url_for, session, abort
from apscheduler.schedulers.background import BackgroundScheduler
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

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)  # For session management
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1-hour session timeout
app.config['PREFERRED_URL_SCHEME'] = 'https'  # Support reverse proxy with HTTPS
scheduler = BackgroundScheduler(job_defaults={'coalesce': True, 'max_instances': 1})
scheduler.start()

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB = '/app/data/firewalls.db'
BACKUP_DIR = 'backups'
REMOTE_CONFIG_PATH = os.getenv('FORTIGATE_CONFIG_PATH', 'sys_config')
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')
MAIL_PORT = os.getenv('MAIL_PORT', 587)
MAIL_USER = os.getenv('MAIL_USER', 'user@example.com')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'password')
MAIL_RECIPIENT = os.getenv('MAIL_RECIPIENT', MAIL_USER)  # Default to MAIL_USER if not set

# Set timezone to Europe/Vienna
tz = pytz.timezone('Europe/Vienna')

def init_db():
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
    c.execute("INSERT OR IGNORE INTO users (username, password, first_login) VALUES (?, ?, ?)", ("admin", "changeme", 1))
    conn.commit()
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
    clean_nonexistent_backups(conn)
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

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        if 'username' in request.form and 'password' in request.form and 'new_password' in request.form and 'confirm_password' in request.form:
            # Handle password change
            old_password = request.form['password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if new_password != confirm_password:
                return "New passwords do not match", 400
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("SELECT first_login FROM users WHERE username = ? AND password = ?", (session['username'], old_password if not first_login else session['password']))
            result = c.fetchone()
            if result:
                c.execute("UPDATE users SET password = ?, first_login = 0 WHERE username = ? AND password = ?",
                          (new_password, session['username'], old_password if not result[0] else session['password']))
                if c.rowcount > 0:
                    session['password'] = new_password
                    conn.commit()
                    return redirect(url_for('index'))
            conn.close()
            return "Old password incorrect or update failed", 400
        else:
            fqdn = request.form['fqdn']
            username = request.form['username'] or os.getenv('DEFAULT_SCP_USER', 'admin')
            password = request.form['password'] or os.getenv('DEFAULT_SCP_PASSWORD', '')
            interval_minutes = int(request.form['interval_minutes'])
            retention_count = int(request.form['retention_count'])
            ssh_port = int(request.form.get('ssh_port', 9422))

            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute('''INSERT INTO firewalls (fqdn, username, password, interval_minutes, retention_count, last_backup, status, ssh_port)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (fqdn, username, password, interval_minutes, retention_count, None, 'New', ssh_port))
            fw_id = c.lastrowid
            conn.commit()
            conn.close()

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT password, first_login FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result and result[0] == password:
            session['logged_in'] = True
            session['username'] = username
            session['password'] = password
            session['last_activity'] = datetime.datetime.now(tz)
            session['x_forwarded_for'] = request.headers.get('X-Forwarded-For')
            if result[1]:  # First login
                return redirect(url_for('change_password'))
            return redirect(url_for('index'))
        return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password != confirm_password:
            return "New passwords do not match", 400
        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT first_login FROM users WHERE username = ? AND password = ?", (session['username'], old_password if not first_login else session['password']))
        result = c.fetchone()
        if result:
            c.execute("UPDATE users SET password = ?, first_login = 0 WHERE username = ? AND password = ?",
                      (new_password, session['username'], old_password if not result[0] else session['password']))
            if c.rowcount > 0:
                session['password'] = new_password
                conn.commit()
                return redirect(url_for('index'))
        conn.close()
        return "Old password incorrect or update failed", 400
    return render_template('change_password.html', first_login=session.get('first_login', False))

@app.route('/backups/<int:fw_id>')
@login_required
def list_backups(fw_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT DISTINCT * FROM backups WHERE fw_id = ? ORDER BY timestamp DESC", (fw_id,))
    backups = c.fetchall()
    conn.close()
    return render_template('backups.html', backups=backups, fw_id=fw_id)

@app.route('/download/<path:filename>')
@login_required
def download(filename):
    return send_from_directory(BACKUP_DIR, filename)

@app.route('/delete/<int:fw_id>')
@login_required
def delete_firewall(fw_id):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("DELETE FROM firewalls WHERE id = ?", (fw_id,))
    c.execute("SELECT filename FROM backups WHERE fw_id = ?", (fw_id,))
    backup_files = c.fetchall()
    c.execute("DELETE FROM backups WHERE fw_id = ?", (fw_id,))
    c.execute("SELECT * FROM firewalls")
    firewalls = c.fetchall()
    conn.commit()
    conn.close()

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

@app.route('/errors')
@login_required
def view_errors():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("SELECT id, fqdn, last_backup, status FROM firewalls WHERE status LIKE 'Failed:%'")
    errors = c.fetchall()
    conn.close()
    return render_template('errors.html', errors=errors)

@app.route('/backup_now/<int:fw_id>')
@login_required
def backup_now(fw_id):
    logger.info(f"Manual backup triggered for fw_id {fw_id}")
    backup_firewall(fw_id)
    return redirect(url_for('index'))

def backup_firewall(fw_id):
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

    try:
        logger.debug(f"Starting backup for fw_id {fw_id} on {fqdn}:{ssh_port} with username {username}")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(fqdn, username=username, password=password, port=ssh_port, timeout=30)  # Increased timeout
        transport = ssh.get_transport()
        transport.set_keepalive(60)  # Increase keep-alive to 60 seconds
        logger.debug(f"SSH connection established to {fqdn} with keep-alive")

        # Note: No settimeout on Transport; rely on connect timeout and keep-alive
        stdin, stdout, stderr = ssh.exec_command(f"ls {REMOTE_CONFIG_PATH}")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error = stderr.read().decode().strip()
            raise Exception(f"Remote file {REMOTE_CONFIG_PATH} does not exist: {error}")
        logger.debug(f"Remote file {REMOTE_CONFIG_PATH} exists on {fqdn}")

        scp_client = scp.SCPClient(ssh.get_transport())  # No timeout parameter
        logger.debug(f"Attempting SCP transfer of {REMOTE_CONFIG_PATH} to {local_path}")
        scp_client.get(REMOTE_CONFIG_PATH, local_path)
        scp_client.close()
        ssh.close()

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
        conn.close()

    except Exception as e:
        status = f'Failed: {str(e)}'
        logger.error(f"Backup failed for {fqdn}: {str(e)}")
        if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
            os.remove(local_path)

        # Send email notification for failed backup
        if MAIL_SERVER and MAIL_USER and MAIL_PASSWORD:
            msg = MIMEText(f"Backup failed for {fqdn} at {timestamp}: {str(e)}")
            msg['Subject'] = f"Backup Failure Notification - {fqdn}"
            msg['From'] = MAIL_USER
            msg['To'] = MAIL_RECIPIENT  # Use MAIL_RECIPIENT from env
            try:
                with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
                    server.starttls()
                    server.login(MAIL_USER, MAIL_PASSWORD)
                    server.send_message(msg)
                logger.info(f"Email notification sent for failed backup of {fqdn}")
            except Exception as email_error:
                logger.error(f"Failed to send email notification: {str(email_error)}")

    # Update firewall status
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("UPDATE firewalls SET last_backup = ?, status = ? WHERE id = ?",
              (timestamp, status, fw_id))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Clear all existing jobs to prevent duplicates
    for job in scheduler.get_jobs():
        scheduler.remove_job(job.id)
        logger.debug(f"Cleared existing job {job.id}")

    init_db()
    os.makedirs(BACKUP_DIR, exist_ok=True)

    # Load existing firewalls and schedule their jobs
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

    # Log all scheduled jobs
    logger.info("Current scheduled jobs:")
    for job in scheduler.get_jobs():
        logger.info(f"Job ID: {job.id}, Next run: {job.next_run_time}")

    app.run(host='0.0.0.0', port=8521, debug=True, use_reloader=False)