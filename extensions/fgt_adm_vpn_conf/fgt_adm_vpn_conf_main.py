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

fgt_adm_vpn_conf_bp = Blueprint('fgt_adm_vpn_conf', __name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'), static_folder='static')
# This db instance is for the blueprint, it will be initialized by the main app
db = SQLAlchemy()

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
        configs = VpnConfig.query.all()
        available_ips, total_ips_in_pool = get_all_available_ips()
        
        available_ips_count = len(available_ips)
        available_ips_percentage = (available_ips_count / total_ips_in_pool) * 100 if total_ips_in_pool > 0 else 0

        return render_template('fgt_adm_vpn_conf_index.html', 
                               configs=configs, 
                               available_ips_count=available_ips_count,
                               available_ips_percentage=available_ips_percentage)
    except Exception as e:
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
    
    dns_name = f"{kundenname}-{standort}"
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
        dns_name_full=dns_name_full
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
            
            dns_name = f"{kundenname}-{standort}"
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
                    dns_name_full=dns_name_full
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
        config.dns_name = f"{config.kundenname}-{config.standort}"
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
Add-DnsServerResourceRecordA -Name "{e.dns_name}" -ZoneName "adm.eworx.at" -IPv4Address "{e.remoteip_full}"
}} -Credential $CustomCred
Invoke-Command -ComputerName ADM-DC02.adm.eworx.at -ScriptBlock {{
Add-DnsServerResourceRecordA -Name "{e.dns_name}" -ZoneName "adm.eworx.at" -IPv4Address "{e.remoteip_full}"
}} -Credential $CustomCred

#~~~~~~~~~ACCESS-URLs~~~~~~#
https://{e.remoteip_full}:9443
https://{e.dns_name_full}
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
        "IPSEC-PSK-RO", "IPSEC-PSK-HCI", "RADIUSMGT", "DNS-Name-Full", "Firewallname"
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
            config.firewallname
        ])
    
    log_action("FGT ADM VPN - Export", "Exported all configs to CSV")
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=vpn_configs_backup.csv"
    output.headers["Content-type"] = "text/csv"
    return output
