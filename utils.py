from functools import wraps
from flask import redirect, url_for, session, request
from datetime import datetime, timedelta
import pytz

# Set timezone to Europe/Vienna - moved from app.py
tz = pytz.timezone('Europe/Vienna')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        if 'last_activity' in session:
            last_activity = tz.localize(session['last_activity']) if not session['last_activity'].tzinfo else session['last_activity']
            if datetime.now(tz) - last_activity > timedelta(hours=1):
                session.pop('logged_in', None)
                return redirect(url_for('login'))
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if 'x_forwarded_for' in session and session['x_forwarded_for'] != x_forwarded_for:
            session.pop('logged_in', None)
            return redirect(url_for('login'))
        session['last_activity'] = datetime.now(tz)
        session['x_forwarded_for'] = x_forwarded_for
        return f(*args, **kwargs)
    return decorated_function
