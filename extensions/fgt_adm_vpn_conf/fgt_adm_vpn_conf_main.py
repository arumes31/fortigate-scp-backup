import os
from flask import Blueprint, render_template, request, redirect, url_for, send_file, make_response, current_app, session
from flask_sqlalchemy import SQLAlchemy
from utils import login_required # Import login_required from the main app
import csv
import io
import random
import string
import zipfile
import ipaddress
import urllib.request
import urllib.parse
import base64
import json
import time

fgt_adm_vpn_conf_bp = Blueprint('fgt_adm_vpn_conf', __name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'), static_folder='static')
# This db instance is for the blueprint, it will be initialized by the main app
db = SQLAlchemy()

def get_graylog_status(hostname):
    graylog_url = os.getenv('GRAYLOG_URL', '').rstrip('/')
    graylog_token = os.getenv('GRAYLOG_TOKEN', '')
    timeframe = os.getenv('GRAYLOG_SEARCH_TIMEFRAME', '86400')
    base_query = os.getenv('GRAYLOG_SEARCH_QUERY', 'fw_inventory_status:online')

    if not graylog_url or not graylog_token:
        return "config_missing"

    query = f'source:"{hostname}" AND {base_query}'
    params = urllib.parse.urlencode({
        'query': query,
        'range': timeframe,
        'limit': 1
    })
    
    api_url = f"{graylog_url}/api/search/universal/relative?{params}"
    
    try:
        auth_str = f"{graylog_token}:token"
        auth_bytes = auth_str.encode('ascii')
        auth_header = base64.b64encode(auth_bytes).decode('ascii')
        
        req = urllib.request.Request(api_url)
        req.add_header('Authorization', f'Basic {auth_header}')
        req.add_header('Accept', 'application/json')
        
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            return "online" if data.get('total_results', 0) > 0 else "offline"
    except Exception as e:
        return "error"

def graylog_status_worker(app):
    with app.app_context():
        # Sleep initially to let the app start up completely
        time.sleep(10)
        while True:
            try:
                configs = VpnConfig.query.filter_by(graylog_enabled=True).all()
                if not configs:
                    time.sleep(60)
                    continue
                
                # Check over a 15-minute (900s) window.
                # Delay between each firewall check so they don't overlap or burst
                delay_between_checks = 900.0 / len(configs)
                
                for config in configs:
                    if config.cluster_hostnames:
                        hostnames = [h.strip() for h in config.cluster_hostnames.split(',') if h.strip()]
                        statuses = [get_graylog_status(h) for h in hostnames]
                        if "config_missing" in statuses:
                            config.last_graylog_status = "config_missing"
                        elif "error" in statuses or "offline" in statuses:
                            config.last_graylog_status = "offline"
                        else:
                            config.last_graylog_status = "online"
                    else:
                        config.last_graylog_status = get_graylog_status(config.firewallname)
                    
                    db.session.commit()
                    time.sleep(delay_between_checks)
            except Exception as e:
                app.logger.error(f"Error in graylog_status_worker loop: {e}")
                time.sleep(60)

import threading
worker_started = False
worker_lock = threading.Lock()

@fgt_adm_vpn_conf_bp.before_app_request
def start_worker():
    global worker_started
    if not worker_started:
        with worker_lock:
            if not worker_started:
                worker_started = True
                app = current_app._get_current_object()
                t = threading.Thread(target=graylog_status_worker, args=(app,), daemon=True)
                t.start()

def log_action(action, details):
    username = session.get('username', 'Unknown')
    if hasattr(current_app, 'log_activity'):
        current_app.log_activity(username, action, details)

class VpnConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kundenname = db.Column(db.String(100))
    standort = db.Column(db.String(100))
    remoteip_full = db.Column(db.String(100), unique=True)
    remoteip_full_1st = db.Column(db.String(100))
    ike2_username = db.Column(db.String(100))
    wan_interface = db.Column(db.String(100))
    lan_interface = db.Column(db.String(100))
    dns_name = db.Column(db.String(100))
    firewallname = db.Column(db.String(100), unique=True)
    ipsec_psk_ro = db.Column(db.String(100))
    ipsec_psk_hci = db.Column(db.String(100))
    radiusmgt = db.Column(db.String(10))
    dns_name_full = db.Column(db.String(100))
    graylog_enabled = db.Column(db.Boolean, default=True)
    cluster_hostnames = db.Column(db.String(255))
    last_graylog_status = db.Column(db.String(20), default="unknown")

    def __repr__(self):
        return f'<VpnConfig {self.kundenname}>'

def get_random_password(length=20, upper=4, lower=4, numeric=2, special=2):
    if upper + lower + numeric + special > length:
        raise ValueError("number of upper/lower/numeric/special char must be lower or equal to length")

    u_char_set = string.ascii_uppercase
    l_char_set = string.ascii_lowercase
    n_char_set = string.digits
    s_char_set = "!#"
    
    password = []
    password.extend(random.choice(u_char_set) for _ in range(upper))
    password.extend(random.choice(l_char_set) for _ in range(lower))
    password.extend(random.choice(n_char_set) for _ in range(numeric))
    password.extend(random.choice(s_char_set) for _ in range(special))

    remaining_length = length - (upper + lower + numeric + special)
    
    char_set = u_char_set + l_char_set + n_char_set + s_char_set
    password.extend(random.choice(char_set) for _ in range(remaining_length))
    
    random.shuffle(password)
    
    return "".join(password)

def get_next_available_ip():
    ip_network = ipaddress.ip_network('10.105.1.0/24')
    used_ips = [ipaddress.ip_address(config.remoteip_full) for config in VpnConfig.query.all()]
    
    for ip in ip_network.hosts():
        if ip not in used_ips:
            return str(ip)
    return None

def get_all_available_ips():
    ip_network = ipaddress.ip_network('10.105.1.0/24')
    used_ips = {ipaddress.ip_address(config.remoteip_full) for config in VpnConfig.query.all()}
    
    available_ips = [str(ip) for ip in ip_network.hosts() if ip not in used_ips]
    return available_ips, ip_network.num_addresses - 2 # Subtract network and broadcast addresses

@fgt_adm_vpn_conf_bp.route('/')
@login_required
def index():
    try:
        # Simple auto-migration for graylog_enabled column
        try:
            db.session.execute(db.text("SELECT graylog_enabled FROM vpn_config LIMIT 1"))
        except Exception:
            db.session.rollback()
            db.session.execute(db.text("ALTER TABLE vpn_config ADD COLUMN graylog_enabled BOOLEAN DEFAULT 1"))
            db.session.commit()
            log_action("Database Migration", "Added graylog_enabled column to vpn_config table")

        # Simple auto-migration for cluster_hostnames column
        try:
            db.session.execute(db.text("SELECT cluster_hostnames FROM vpn_config LIMIT 1"))
        except Exception:
            db.session.rollback()
            db.session.execute(db.text("ALTER TABLE vpn_config ADD COLUMN cluster_hostnames VARCHAR(255)"))
            db.session.commit()
            log_action("Database Migration", "Added cluster_hostnames column to vpn_config table")

        # Simple auto-migration for last_graylog_status column
        try:
            db.session.execute(db.text("SELECT last_graylog_status FROM vpn_config LIMIT 1"))
        except Exception:
            db.session.rollback()
            db.session.execute(db.text("ALTER TABLE vpn_config ADD COLUMN last_graylog_status VARCHAR(20) DEFAULT 'unknown'"))
            db.session.commit()
            log_action("Database Migration", "Added last_graylog_status column to vpn_config table")

        configs = VpnConfig.query.all()
        
        available_ips, total_ips_in_pool = get_all_available_ips()
        
        available_ips_count = len(available_ips)
        available_ips_percentage = (available_ips_count / total_ips_in_pool) * 100 if total_ips_in_pool > 0 else 0

        return render_template('fgt_adm_vpn_conf_index.html', 
                               configs=configs, 
                               available_ips_count=available_ips_count,
                               available_ips_percentage=available_ips_percentage)
    except Exception as e:
        if hasattr(current_app, 'logger'):
            current_app.logger.error(f"Error in fgt_adm_vpn_conf blueprint index() function: {str(e)}", exc_info=True)
        return "An error occurred in the FGT ADM VPN Config page. Check logs for details.", 500

@fgt_adm_vpn_conf_bp.route('/add', methods=['POST'])
@login_required
def add():
    kundenname = request.form['kundenname']
    standort = request.form['standort']
    
    remoteip_full = get_next_available_ip()
    if not remoteip_full:
        return "No available IP in the pool."
        
    last_octet = remoteip_full.split('.')[-1]
    remoteip_full_1st = f"10.150.11.{last_octet}"
    
    dns_name = f"fgt-{kundenname}-{standort}"
    dns_name_full = f"{dns_name}.adm.eworx.at"
    
    # Allow firewallname to be provided, otherwise derive it
    firewallname = request.form.get('firewallname')
    if not firewallname:
        firewallname = f"{kundenname}-{standort}"
    
    new_config = VpnConfig(
        kundenname=kundenname,
        standort=standort,
        remoteip_full=remoteip_full,
        remoteip_full_1st=remoteip_full_1st,
        ike2_username=f"vpn-adm-{kundenname}-{standort}",
        wan_interface=request.form.get('wan_interface', 'wan1'),
        lan_interface=request.form.get('lan_interface', 'loopback'),
        dns_name=dns_name,
        firewallname=firewallname,
        ipsec_psk_ro=request.form.get('ipsec_psk_ro', 'psauto'),
        ipsec_psk_hci=request.form.get('ipsec_psk_hci', 'psauto'),
        radiusmgt=request.form.get('radiusmgt', 'YES'),
        dns_name_full=dns_name_full,
        graylog_enabled='graylog_enabled' in request.form,
        cluster_hostnames=request.form.get('cluster_hostnames', '')
    )
    db.session.add(new_config)
    db.session.commit()
    log_action("FGT ADM VPN - Add", f"Added config for {kundenname} - {standort} ({remoteip_full})")
    return redirect(url_for('fgt_adm_vpn_conf.index'))

@fgt_adm_vpn_conf_bp.route('/import', methods=['POST'])
@login_required
def import_csv():
    file = request.files['file']
    if not file:
        return "No file uploaded."

    stream = io.StringIO(file.stream.read().decode("utf-8-sig"), newline=None)
    csv_input = csv.reader(stream)
    
    header = [h.strip() for h in next(csv_input)]
    
    # Create a normalized map (lowercase) for easier matching
    header_lower = [h.lower() for h in header]
    col_map = {h.lower(): i for i, h in enumerate(header)}

    expected_cols = {
        'kundenname', 'standort', 'remoteip-full', 'remoteip-full-1st',
        'ipsec-psk-ro', 'ipsec-psk-hci', 'radiusmgt', 'wan-interface', 'lan-interface', 'firewallname'
    }

    if not expected_cols.issubset(set(header_lower)):
        missing_cols = expected_cols - set(header_lower)
        return f"Missing required CSV columns: {', '.join(missing_cols)}"

    errors = []
    for i, row in enumerate(csv_input):
        if not row or row[col_map['kundenname']].strip() == 'xxxx':
            continue

        try:
            kundenname = row[col_map['kundenname']].strip()
            standort = row[col_map['standort']].strip()

            firewallname = row[col_map['firewallname']].strip() if 'firewallname' in col_map and row[col_map['firewallname']].strip() else None
            if not firewallname:
                firewallname = f"{kundenname}-{standort}"
            
            dns_name = f"fgt-{kundenname}-{standort}"
            dns_name_full = f"{dns_name}.adm.eworx.at"
            ike2_username = f"vpn-adm-{kundenname}-{standort}"
            
            remoteip_full = row[col_map['remoteip-full']].strip() if 'remoteip-full' in col_map and row[col_map['remoteip-full']].strip() else None
            if not remoteip_full:
                remoteip_full = get_next_available_ip()
                if not remoteip_full:
                    errors.append(f"Row {i+2}: No available IP in the pool during import.")
                    continue
            
            remoteip_full_1st = row[col_map['remoteip-full-1st']].strip() if 'remoteip-full-1st' in col_map and row[col_map['remoteip-full-1st']].strip() else None
            if not remoteip_full_1st:
                last_octet = remoteip_full.split('.')[-1]
                remoteip_full_1st = f"10.150.11.{last_octet}"

            ipsec_psk_ro = row[col_map['ipsec-psk-ro']].strip() if 'ipsec-psk-ro' in col_map and row[col_map['ipsec-psk-ro']].strip() else 'psauto'
            ipsec_psk_hci = row[col_map['ipsec-psk-hci']].strip() if 'ipsec-psk-hci' in col_map and row[col_map['ipsec-psk-hci']].strip() else 'psauto'
            radiusmgt = row[col_map['radiusmgt']].strip() if 'radiusmgt' in col_map and row[col_map['radiusmgt']].strip() else 'YES'
            wan_interface = row[col_map['wan-interface']].strip() if 'wan-interface' in col_map and row[col_map['wan-interface']].strip() else 'wan1'
            lan_interface = row[col_map['lan-interface']].strip() if 'lan-interface' in col_map and row[col_map['lan-interface']].strip() else 'loopback'
            graylog_enabled = row[col_map['graylog_enabled']].strip().upper() == 'YES' if 'graylog_enabled' in col_map else True
            cluster_hostnames = row[col_map['cluster_hostnames']].strip() if 'cluster_hostnames' in col_map else ''

            existing_config_by_firewallname = VpnConfig.query.filter_by(firewallname=firewallname).first()
            existing_config_by_remoteip = VpnConfig.query.filter_by(remoteip_full=remoteip_full).first()

            if existing_config_by_firewallname:
                if existing_config_by_remoteip and existing_config_by_remoteip.id != existing_config_by_firewallname.id:
                    errors.append(f"Row {i+2}: Skipping row for firewallname '{firewallname}': remoteip_full '{remoteip_full}' is already in use by another entry (ID: {existing_config_by_remoteip.id}).")
                    continue

                existing_config_by_firewallname.kundenname = kundenname
                existing_config_by_firewallname.standort = standort
                existing_config_by_firewallname.remoteip_full = remoteip_full
                existing_config_by_firewallname.remoteip_full_1st = remoteip_full_1st
                existing_config_by_firewallname.ike2_username = ike2_username
                existing_config_by_firewallname.wan_interface = wan_interface
                existing_config_by_firewallname.lan_interface = lan_interface
                existing_config_by_firewallname.dns_name = dns_name
                existing_config_by_firewallname.ipsec_psk_ro = ipsec_psk_ro
                existing_config_by_firewallname.ipsec_psk_hci = ipsec_psk_hci
                existing_config_by_firewallname.radiusmgt = radiusmgt
                existing_config_by_firewallname.dns_name_full = dns_name_full
                existing_config_by_firewallname.graylog_enabled = graylog_enabled
                existing_config_by_firewallname.cluster_hostnames = cluster_hostnames
            else:
                if existing_config_by_remoteip:
                    errors.append(f"Row {i+2}: Skipping insert for firewallname '{firewallname}': remoteip_full '{remoteip_full}' is already in use by an existing entry (ID: {existing_config_by_remoteip.id}).")
                    continue

                new_config = VpnConfig(
                    kundenname=kundenname,
                    standort=standort,
                    remoteip_full=remoteip_full,
                    remoteip_full_1st=remoteip_full_1st,
                    ike2_username=ike2_username,
                    wan_interface=wan_interface,
                    lan_interface=lan_interface,
                    dns_name=dns_name,
                    firewallname=firewallname,
                    ipsec_psk_ro=ipsec_psk_ro,
                    ipsec_psk_hci=ipsec_psk_hci,
                    radiusmgt=radiusmgt,
                    dns_name_full=dns_name_full,
                    graylog_enabled=graylog_enabled,
                    cluster_hostnames=cluster_hostnames
                )
                db.session.add(new_config)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            errors.append(f"Row {i+2}: An unexpected error occurred: {e}")

    if errors:
        log_action("FGT ADM VPN - Import Failed", f"Import finished with errors: {len(errors)} errors")
        return "<br>".join(errors)
    else:
        log_action("FGT ADM VPN - Import Success", "Imported configs from CSV")
        return redirect(url_for('fgt_adm_vpn_conf.index'))

@fgt_adm_vpn_conf_bp.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    config = VpnConfig.query.get_or_404(id)
    if request.method == 'POST':
        config.kundenname = request.form['kundenname']
        config.standort = request.form['standort']
        config.wan_interface = request.form['wan_interface']
        config.lan_interface = request.form['lan_interface']
        config.graylog_enabled = 'graylog_enabled' in request.form
        config.cluster_hostnames = request.form.get('cluster_hostnames', '')
        
        new_remoteip_full = request.form['remoteip_full']
        # Validate if new_remoteip_full is unique (excluding current config)
        if new_remoteip_full != config.remoteip_full:
            if VpnConfig.query.filter_by(remoteip_full=new_remoteip_full).first():
                # Handle error: IP already in use. For a modal, this would be a message in the modal.
                # For now, we'll return a simple string error.
                return f"Error: IP address {new_remoteip_full} is already in use by another entry.", 400
        config.remoteip_full = new_remoteip_full
        
        # Re-derive remoteip_full_1st based on the new remoteip_full
        last_octet = config.remoteip_full.split('.')[-1]
        config.remoteip_full_1st = f"10.150.11.{last_octet}"

        config.ipsec_psk_ro = request.form['ipsec_psk_ro']
        config.ipsec_psk_hci = request.form['ipsec_psk_hci']
        config.radiusmgt = request.form['radiusmgt']
        
        # Allow firewallname to be provided, otherwise derive it
        firewallname = request.form.get('firewallname')
        if firewallname:
            config.firewallname = firewallname
        else:
            config.firewallname = f"{config.kundenname}-{config.standort}"
        
        #Re-generate derived fields
        config.dns_name = f"fgt-{config.kundenname}-{config.standort}"
        config.dns_name_full = f"{config.dns_name}.adm.eworx.at"
        config.ike2_username=f"vpn-adm-{config.kundenname}-{config.standort}"

        db.session.commit()
        log_action("FGT ADM VPN - Edit", f"Edited config for {config.kundenname} - {config.standort} (ID: {config.id})")
        return redirect(url_for('fgt_adm_vpn_conf.index'))
    return render_template('fgt_adm_vpn_conf_edit_form.html', config=config)



@fgt_adm_vpn_conf_bp.route('/delete/<int:id>')
@login_required
def delete(id):
    config = VpnConfig.query.get_or_404(id)
    kname = config.kundenname
    sname = config.standort
    db.session.delete(config)
    db.session.commit()
    log_action("FGT ADM VPN - Delete", f"Deleted config for {kname} - {sname} (ID: {id})")
    return redirect(url_for('fgt_adm_vpn_conf.index'))

@fgt_adm_vpn_conf_bp.route('/generate_single/<int:id>')
@login_required
def generate_single(id):
    e = VpnConfig.query.get(id)
    if not e:
        return "Entry not found."

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        GWro = "80.122.63.44"
        GWhci = "83.164.150.12"

        psk_ro = e.ipsec_psk_ro
        psk_hci = e.ipsec_psk_hci
        if e.ipsec_psk_ro.lower() == "psauto":
            psk_ro = get_random_password(34, 4, 4, 2, 2)
        if e.ipsec_psk_hci.lower() == "psauto":
            psk_hci = get_random_password(34, 4, 4, 2, 2)

        radiusro1 = get_random_password(20, 4, 4, 2, 2)
        radiusro2 = get_random_password(20, 4, 4, 2, 2)
        radiushci1 = get_random_password(20, 4, 4, 2, 2)
        radiushci2 = get_random_password(20, 4, 4, 2, 2)

        # Create config files as strings
        config_ex = ""
        if e.radiusmgt.upper() == "YES":
            config_ex += f"""config vpn ipsec phase2-interface
edit VPN_ADM_{e.kundenname}-{e.standort}_2nd
set phase1name "VPN_ADM_RO"
set proposal aes256-sha512
set dhgrp 18
set src-subnet 10.12.34.0 255.255.255.0
set dst-subnet {e.remoteip_full} 255.255.255.255
next
end

config vpn ipsec phase2-interface
edit VPN_ADM_{e.kundenname}-{e.standort}_1st
set phase1name "VPN_ADM_RO"
set proposal aes256-sha512
set dhgrp 18
set src-subnet 10.12.34.0 255.255.255.0
set dst-subnet {e.remoteip_full_1st} 255.255.255.255
next
end
"""
        config_ex += f"""
config user local
edit {e.ike2_username}
set type password
set passwd {psk_ro}
next
end

##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_RO HINZUGEFÜGT WERDEN
##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_RO HINZUGEFÜGT WERDEN
"""
        zf.writestr(f"{e.kundenname}.{e.standort}.FW_EX.txt", config_ex)

        confighci = ""
        if e.radiusmgt.upper() == "YES":
            confighci += f"""config vpn ipsec phase2-interface
edit VPN_ADM_{e.kundenname}-{e.standort}_2nd
set phase1name "VPN_ADM-RZP"
set proposal aes256-sha512
set dhgrp 21
set src-subnet 10.250.11.192 255.255.255.192
set dst-subnet {e.remoteip_full} 255.255.255.255
next
end

config vpn ipsec phase2-interface
edit VPN_ADM_{e.kundenname}-{e.standort}_1st
set phase1name "VPN_ADM-RZP"
set proposal aes256-sha512
set dhgrp 21
set src-subnet 10.250.11.192 255.255.255.192
set dst-subnet {e.remoteip_full_1st} 255.255.255.255
next
end

config user local
edit {e.ike2_username}
set type password
set passwd {psk_hci}
next
end

##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_HC HINZUGEFÜGT WERDEN
##ACHTUNG USER MUSS MANUELL ZUR FIREWALL GROUP IPSEC_VPN_ADM_HC HINZUGEFÜGT WERDEN
"""
        else:
            confighci = "MGT DISABLED IN XLSX - NO HCI CONFIG"
        zf.writestr(f"{e.kundenname}.{e.standort}.FW_rzp.txt", confighci)

        configcu = f"""config system global
set remoteauthtimeout 180
end

config vpn ipsec phase1-interface
edit "VPN_EX-ADMRO"
set interface {e.wan_interface}
set ike-version 2
set peertype any
set net-device disable
set proposal aes256-sha512
set localid {e.ike2_username}
set dpd on-idle
set dhgrp 18
set remote-gw {GWro}
set psksecret {psk_ro}
set dpd-retrycount 10
set dpd-retryinterval 900
next
end
"""
        if e.radiusmgt.upper() == "YES":
            configcu += f"""
config vpn ipsec phase2-interface
edit "VPN_EX-ADMRO-2nd"
set phase1name "VPN_EX-ADMRO"
set proposal aes256-sha512
set dhgrp 18
set keepalive enable
set auto-negotiate enable
set src-subnet {e.remoteip_full} 255.255.255.255
set dst-subnet 10.12.34.0 255.255.255.0
next
end

config vpn ipsec phase2-interface
edit "VPN_EX-ADMRO-1st"
set phase1name "VPN_EX-ADMRO"
set proposal aes256-sha512
set dhgrp 18
set keepalive enable
set auto-negotiate enable
set src-subnet {e.remoteip_full_1st} 255.255.255.255
set dst-subnet 10.12.34.0 255.255.255.0
next
end
"""
        configcu += f"""
config system interface
edit "LB-EXADM"
set vdom "root"
set ip {e.remoteip_full} 255.255.255.255
set allowaccess ping https ssh http
set role dmz
set type loopback
set secondary-IP enable
config secondaryip
edit 1
set ip {e.remoteip_full_1st} 255.255.255.255
next
end
next
end

config firewall service custom
edit "TCP9443"
set tcp-portrange 9443
next
end
config firewall service custom
edit "TCP9422"
set tcp-portrange 9422
next
end
config firewall service custom
edit "RADIUS"
set category "Authentication"
set udp-portrange 1812 1813
next
end
config firewall service custom
edit "PING"
set category "Network Services"
set protocol ICMP
set icmptype 8
unset icmptype
next
end
"""
        if e.radiusmgt.upper() == "YES":
            configcu += f"""
config firewall policy
edit 0
set name "EX-adm https/ssh ro"
set srcintf "VPN_EX-ADMRO"
set dstintf "LB-EXADM"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "TCP9443" "TCP9422" "PING"
next
end

config firewall policy
edit 0
set name "EX-adm radius ro"
set srcintf "LB-EXADM"
set dstintf "VPN_EX-ADMRO"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "RADIUS"
next
end

config router static
edit 0
set dst 10.12.34.0 255.255.255.0
set device "VPN_EX-ADMRO"
next
end
"""
        configcu += """
############################################################################################
################################COPYBREAK###################################################
############################################################################################
"""
        if e.radiusmgt.upper() == "YES":
            configcu += f"""
config system global
set remoteauthtimeout 180
end

config vpn ipsec phase1-interface
edit "VPN_EX-ADMHCI"
set interface {e.wan_interface}
set ike-version 2
set peertype any
set net-device disable
set proposal aes256-sha512
set localid {e.ike2_username}
set dpd on-idle
set dhgrp 21
set remote-gw {GWhci}
set psksecret {psk_hci}
set dpd-retrycount 10
set dpd-retryinterval 900
next
end

config vpn ipsec phase2-interface
edit "VPN_EX-ADMHCI-2nd"
set phase1name "VPN_EX-ADMHCI"
set proposal aes256-sha512
set dhgrp 21
set keepalive enable
set auto-negotiate enable
set src-subnet {e.remoteip_full} 255.255.255.255
set dst-subnet 10.250.11.192 255.255.255.192
next
end

config vpn ipsec phase2-interface
edit "VPN_EX-ADMHCI-1st"
set phase1name "VPN_EX-ADMHCI"
set proposal aes256-sha512
set dhgrp 21
set keepalive enable
set auto-negotiate enable
set src-subnet {e.remoteip_full_1st} 255.255.255.255
set dst-subnet 10.250.11.192 255.255.255.192
next
end

config system interface
edit "LB-EXADM"
set vdom "root"
set ip {e.remoteip_full} 255.255.255.255
set allowaccess ping https ssh http
set role dmz
set type loopback
set secondary-IP enable
config secondaryip
edit 1
set ip {e.remoteip_full_1st} 255.255.255.255
next
end
next
end

config firewall service custom
edit "TCP9443"
set tcp-portrange 9443
next
end
config firewall service custom
edit "TCP9422"
set tcp-portrange 9422
next
end
config firewall service custom
edit "RADIUS"
set category "Authentication"
set udp-portrange 1812 1813
next
end
config firewall service custom
edit "PING"
set category "Network Services"
set protocol ICMP
set icmptype 8
unset icmptype
next
end

config firewall policy
edit 0
set name "EX-adm https/ssh hc"
set srcintf "VPN_EX-ADMHCI"
set dstintf "LB-EXADM"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "TCP9443" "TCP9422" "PING"
next
end

config firewall policy
edit 0
set name "EX-adm radius hc"
set srcintf "LB-EXADM"
set dstintf "VPN_EX-ADMHCI"
set srcaddr "all"
set dstaddr "all"
set action accept
set schedule "always"
set service "RADIUS"
next
end

config router static
edit 0
set dst 10.250.11.192 255.255.255.192
set device "VPN_EX-ADMHCI"
next
end
"""
        configcu += """
############################################################################################
################################COPYBREAK-2#################################################
############################################################################################
"""
        if e.radiusmgt.upper() == "YES":
            configcu += f"""
config system accprofile
edit "Readonly"
set secfabgrp read
set ftviewgrp read
set authgrp read
set sysgrp read
set netgrp read
set loggrp read
set fwgrp read
set vpngrp read
set utmgrp read
set wifi read
next
end

config user radius
edit "RAD-EXADM-1stlvl_1"
set server "10.250.11.201"
set secret {radiushci1}
set nas-ip {e.remoteip_full_1st}
set auth-type ms_chap_v2
set source-ip "{e.remoteip_full_1st}"
next
end

config user radius
edit "RAD-EXADM-1stlvl_2"
set server "10.12.34.201"
set secret {radiusro1}
set nas-ip {e.remoteip_full_1st}
set auth-type ms_chap_v2
set source-ip "{e.remoteip_full_1st}"
next
end

config user group
edit "sg-ADM_FGT_Auth_1st-Level"
set member "RAD-EXADM-1stlvl_1" "RAD-EXADM-1stlvl_2"
next
end

config system admin
edit "sg-ADM_FGT_Auth_1st-Level"
set vdom "root"
set trusthost1 10.12.34.0 255.255.255.0
set trusthost2 10.250.11.192 255.255.255.192
set remote-auth enable
set accprofile "Readonly"
set wildcard enable
set remote-group "sg-ADM_FGT_Auth_1st-Level"
next
end

config user radius
edit "RAD-EXADM-2ndlvl_1"
set server "10.250.11.201"
set secret {radiushci2}
set nas-ip {e.remoteip_full}
set auth-type ms_chap_v2
set source-ip "{e.remoteip_full}"
next
end

config user radius
edit "RAD-EXADM-2ndlvl_2"
set server "10.12.34.201"
set secret {radiusro2}
set nas-ip {e.remoteip_full}
set auth-type ms_chap_v2
set source-ip "{e.remoteip_full}"
next
end

config user group
edit "sg-ADM_FGT_Auth_2nd-Level"
set member "RAD-EXADM-2ndlvl_1" "RAD-EXADM-2ndlvl_2"
next
end

config system admin
edit "sg-ADM_FGT_Auth_2nd-Level"
set vdom "root"
set trusthost1 10.12.34.0 255.255.255.0
set trusthost2 10.250.11.192 255.255.255.192
set remote-auth enable
set accprofile "super_admin"
set wildcard enable
set remote-group "sg-ADM_FGT_Auth_2nd-Level"
next
end
"""
        zf.writestr(f"{e.kundenname}.{e.standort}.FW_kunde.txt", configcu)

        radiuscfg = ""
        if e.radiusmgt.upper() == "YES":
            radiuscfg += f"""$CustomCred = Get-Credential

#~~~~~~~~~~~~~~~~~~~~~~~~~~#
#RUN ON ADM-NPS02 RO
Invoke-Command -ComputerName ADM-NPS02.adm.eworx.at -ScriptBlock {{
New-NpsRadiusClient -Address "{e.remoteip_full}" -Name "{e.kundenname}-{e.standort}_2nd" -SharedSecret "{radiusro2}" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "{e.remoteip_full}" -Name "{e.kundenname}-{e.standort}_2nd" -SharedSecret "{radiusro2}" -AuthAttributeRequired $False
New-NpsRadiusClient -Address "{e.remoteip_full_1st}" -Name "{e.kundenname}-{e.standort}_1st" -SharedSecret "{radiusro1}" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "{e.remoteip_full_1st}" -Name "{e.kundenname}-{e.standort}_1st" -SharedSecret "{radiusro1}" -AuthAttributeRequired $False
Restart-Service IAS
}} -Credential $CustomCred

#~~~~~~~~~~~~~~~~~~~~~~~~~~#
#RUN ON ADM-NPS01 HCI
Invoke-Command -ComputerName ADM-NPS01.adm.eworx.at -ScriptBlock {{
New-NpsRadiusClient -Address "{e.remoteip_full}" -Name "{e.kundenname}-{e.standort}_2nd" -SharedSecret "{radiushci2}" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "{e.remoteip_full}" -Name "{e.kundenname}-{e.standort}_2nd" -SharedSecret "{radiushci2}" -AuthAttributeRequired $False
New-NpsRadiusClient -Address "{e.remoteip_full_1st}" -Name "{e.kundenname}-{e.standort}_1st" -SharedSecret "{radiushci1}" -AuthAttributeRequired $False
Set-NpsRadiusClient -Address "{e.remoteip_full_1st}" -Name "{e.kundenname}-{e.standort}_1st" -SharedSecret "{radiushci1}" -AuthAttributeRequired $False
Restart-Service IAS
}} -Credential $CustomCred

#~~~~~~~~~~~~~~~~~~~~~~~~~~#
#RUN ON ANY DC
Invoke-Command -ComputerName ADM-DC01.adm.eworx.at -ScriptBlock {{
Add-DnsServerResourceRecordA -Name "{e.dns_name_full}" -ZoneName "adm.eworx.at" -IPv4Address "{e.remoteip_full}"
}} -Credential $CustomCred
Invoke-Command -ComputerName ADM-DC02.adm.eworx.at -ScriptBlock {{
Add-DnsServerResourceRecordA -Name "{e.dns_name_full}" -ZoneName "adm.eworx.at" -IPv4Address "{e.remoteip_full}"
}} -Credential $CustomCred

#~~~~~~~~~ACCESS-URLs~~~~~~#
https://{e.remoteip_full}:9443
https://{e.dns_name_full}:9443
"""
        else:
            radiuscfg = "RADIUS CONFIG DISABLED"
        zf.writestr(f"{e.kundenname}.{e.standort}.radiuscfg.txt", radiuscfg)
        
        configfinal = ""
        if e.radiusmgt.upper() == "YES":
            configfinal = """ADMIN USER KONTROLLIEREN / TRUSTED HOSTS ANPASSEN
Es darf keine Admins ohne Trusted Hosts geben, externe IP darf nur unser Jumphost 193.104.82.251/32 erlaubt werden

VORHER ADM LOGIN TESTEN

config system admin
edit "admin"
set trusthost1 193.104.82.251 255.255.255.255
next
end
"""
        else:
            configfinal = "NO RADIUS CONFIG - NO FINAL CONFIG"
        zf.writestr(f"{e.kundenname}.{e.standort}.finalconfig.txt", configfinal)


    log_action("FGT ADM VPN - Download", f"Generated and downloaded config for {e.kundenname} - {e.standort} (ID: {id})")
    memory_file.seek(0)
    return send_file(memory_file,
                     download_name=f'fgt_adm_config_{e.kundenname}-{e.standort}.zip',
                     as_attachment=True)

@fgt_adm_vpn_conf_bp.route('/export')
@login_required
def export_csv():
    si = io.StringIO()
    cw = csv.writer(si)

    # Write header
    header = [
        "Kundenname", "Standort", "REMOTEIP-FULL", "REMOTEIP-FULL-1st",
        "ike2_username", "WAN-Interface", "LAN-Interface", "DNS-Name",
        "IPSEC-PSK-RO", "IPSEC-PSK-HCI", "RADIUSMGT", "DNS-Name-Full", "Firewallname", "graylog_enabled", "cluster_hostnames"
    ]
    cw.writerow(header)

    # Write data rows
    for config in VpnConfig.query.all():
        cw.writerow([
            config.kundenname,
            config.standort,
            config.remoteip_full,
            config.remoteip_full_1st,
            config.ike2_username,
            config.wan_interface,
            config.lan_interface,
            config.dns_name,
            config.ipsec_psk_ro,
            config.ipsec_psk_hci,
            config.radiusmgt,
            config.dns_name_full,
            config.firewallname,
            "YES" if config.graylog_enabled else "NO",
            config.cluster_hostnames
        ])
    
    log_action("FGT ADM VPN - Export", "Exported all configs to CSV")
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=vpn_configs_backup.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@fgt_adm_vpn_conf_bp.route('/export_bookmarks')
@login_required
def export_bookmarks():
    import time
    timestamp = int(time.time())
    
    bookmarks_html = f"""<!DOCTYPE NETSCAPE-Bookmark-file-1>
<!-- This is an automatically generated file.
     It will be read and overwritten.
     DO NOT EDIT! -->
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>
    <DT><H3 ADD_DATE="{timestamp}" LAST_MODIFIED="{timestamp}">FGT ADM VPN</H3>
    <DL><p>
"""
    for config in VpnConfig.query.all():
        url = f"https://{config.dns_name_full}:9443"
        name = f"FGT ADM - {config.kundenname} - {config.standort}"
        bookmarks_html += f'        <DT><A HREF="{url}" ADD_DATE="{timestamp}">{name}</A>\n'
    
    bookmarks_html += """    </DL><p>
</DL><p>
"""
    
    log_action("FGT ADM VPN - Export Bookmarks", "Exported all DNS names to browser bookmarks")
    
    response = make_response(bookmarks_html)
    response.headers["Content-Disposition"] = "attachment; filename=fgt_adm_bookmarks.html"
    response.headers["Content-type"] = "text/html"
    return response

@fgt_adm_vpn_conf_bp.route('/graylog_dsv')
def graylog_dsv():
    configs = VpnConfig.query.filter_by(graylog_enabled=True).all()
    output = ["Firewallname;Remote_IP;Status"]
    for config in configs:
        if config.remoteip_full:
            if config.cluster_hostnames:
                # Split comma-separated hostnames and add a row for each
                hostnames = [h.strip() for h in config.cluster_hostnames.split(',') if h.strip()]
                for hostname in hostnames:
                    output.append(f"{hostname};{config.remoteip_full};active")
            elif config.firewallname:
                output.append(f"{config.firewallname};{config.remoteip_full};active")
    
    log_action("FGT ADM VPN - Graylog DSV Access", f"Served {len(output)-1} records")
    response = make_response("\n".join(output))
    response.headers["Content-Type"] = "text/plain"
    return response
