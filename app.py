# czesc komentarzy pisane prez llm
import os
import json
import logging
import time
import iptc
import subprocess
import ipaddress
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.urandom(24)

RULES_FILE = "firewall_rules.json"
USERS_FILE = "users.json"
BACKUP_DIR = "backups"

# czy istnieja backupy
os.makedirs(BACKUP_DIR, exist_ok=True)

# ============================================================================
# AUTHENTICATION SETUP
# ============================================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username

@login_manager.user_loader
def load_user(username):
    users = get_users()
    if username in users:
        return User(username)
    return None

def get_users():
    """Load users from file"""
    if not os.path.exists(USERS_FILE):
        default_users = {
            "admin": generate_password_hash("admin123")
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(default_users, f, indent=4)
        logging.warning("Created default admin user. Password: admin123 - CHANGE THIS IMMEDIATELY!")
        return default_users
    
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Could not read users file: {e}")
        return {}

def save_users(users):
    """Save users to file"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=4)
    except IOError as e:
        logging.error(f"Could not save users file: {e}")

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def validate_ip_or_cidr(ip_str):
    """Validates IP address or CIDR notation"""
    if not ip_str:
        return True, None  # Empty is OK
    
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True, None
    except ValueError as e:
        return False, f"Invalid IP/CIDR format: {str(e)}"

def validate_port(port_str):
    """Validates port number or range"""
    # Handle None or empty string
    if port_str is None or port_str == '':
        return True, None  # Empty is OK
    
    # Convert to string and strip whitespace
    port_str = str(port_str).strip()
    
    # Empty after strip
    if not port_str:
        return True, None
    
    # Single port
    if ':' not in port_str:
        # Check if it's a valid number
        if not port_str.isdigit():
            return False, f"Port '{port_str}' must be a number"
        
        try:
            port = int(port_str)
        except ValueError:
            return False, f"Port '{port_str}' is not a valid number"
        
        if port < 1 or port > 65535:
            return False, f"Port {port} must be between 1 and 65535"
        
        return True, None
    
    # Port range (1024:2048)
    try:
        parts = port_str.split(':')
        if len(parts) != 2:
            return False, "Port range must be in format START:END (e.g., 1024:2048)"
        
        # Check if both parts are numeric
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        
        if not start_str.isdigit():
            return False, f"Port range start '{start_str}' must be a number"
        if not end_str.isdigit():
            return False, f"Port range end '{end_str}' must be a number"
        
        start = int(start_str)
        end = int(end_str)
        
        # Validate range
        if start < 1 or start > 65535:
            return False, f"Port range start {start} must be between 1 and 65535"
        if end < 1 or end > 65535:
            return False, f"Port range end {end} must be between 1 and 65535"
        if start > end:
            return False, f"Port range start ({start}) must be less than or equal to end ({end})"
        
        return True, None
    except ValueError as e:
        return False, f"Invalid port range format: {str(e)}"

def validate_protocol(proto):
    """Validates protocol"""
    if not proto:
        return True, None  # Empty is OK
    
    valid_protocols = ['tcp', 'udp', 'icmp', 'all']
    if proto.lower() in valid_protocols:
        return True, None
    return False, f"Protocol must be one of: {', '.join(valid_protocols)}"

def validate_target(target):
    """Validates target action"""
    if not target:
        return False, "Target is required"
    
    valid_targets = ['ACCEPT', 'DROP', 'REJECT', 'LOG']
    if target.upper() in valid_targets:
        return True, None
    return False, f"Target must be one of: {', '.join(valid_targets)}"

def validate_chain(chain):
    """Validates chain name"""
    if not chain:
        return False, "Chain is required"
    
    # Allow built-in chains and custom chains
    if not chain.replace('_', '').replace('-', '').isalnum():
        return False, "Chain name can only contain letters, numbers, hyphens and underscores"
    
    if len(chain) > 30:
        return False, "Chain name must be 30 characters or less"
    
    return True, None

def validate_rule(rule_data):
    """Validates entire rule data"""
    errors = []
    
    # Validate chain
    valid, error = validate_chain(rule_data.get('chain'))
    if not valid:
        errors.append(error)
    
    # Validate source IP
    valid, error = validate_ip_or_cidr(rule_data.get('source'))
    if not valid:
        errors.append(f"Source: {error}")
    
    # Validate destination IP
    valid, error = validate_ip_or_cidr(rule_data.get('destination'))
    if not valid:
        errors.append(f"Destination: {error}")
    
    # Validate protocol
    valid, error = validate_protocol(rule_data.get('protocol'))
    if not valid:
        errors.append(f"Protocol: {error}")
    
    # ALWAYS validate ports if they are provided
    # (ports only make sense with tcp/udp, but we need to catch invalid input)
    sport = rule_data.get('sport')
    dport = rule_data.get('dport')
    proto = rule_data.get('protocol')
    
    # If ports are specified, protocol must be tcp or udp
    if (sport or dport) and proto and proto.lower() not in ['tcp', 'udp']:
        errors.append(f"Ports can only be specified for TCP or UDP protocols, not '{proto}'")
    
    # If ports are specified without protocol, that's an error
    if (sport or dport) and not proto:
        errors.append("Ports require protocol to be specified (tcp or udp)")
    
    # Validate port format regardless
    valid, error = validate_port(sport)
    if not valid:
        errors.append(f"Source port: {error}")
    
    valid, error = validate_port(dport)
    if not valid:
        errors.append(f"Destination port: {error}")
    
    # Validate target
    valid, error = validate_target(rule_data.get('target'))
    if not valid:
        errors.append(error)
    
    if errors:
        return False, "; ".join(errors)
    return True, None

# ============================================================================
# BACKUP FUNCTIONS
# ============================================================================

def create_backup():
    """Creates a backup of current configuration"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(BACKUP_DIR, f'firewall_backup_{timestamp}.json')
        
        if os.path.exists(RULES_FILE):
            import shutil
            shutil.copy(RULES_FILE, backup_file)
            logging.info(f"Created backup: {backup_file}")
            return True, backup_file
        return False, "No rules file to backup"
    except Exception as e:
        logging.error(f"Backup failed: {e}")
        return False, str(e)

# ============================================================================
# CORE FIREWALL FUNCTIONS
# ============================================================================

def get_rules_from_file():
    if not os.path.exists(RULES_FILE):
        return {"chains": [], "rules": [], "policies": {}}
    try:
        with open(RULES_FILE, 'r') as f:
            content = f.read()
            data = json.loads(content) if content.strip() else {}
            # Ensure policies key exists
            if "policies" not in data:
                data["policies"] = {}
            return data
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Could not read/parse rules file: {e}")
        return {"chains": [], "rules": [], "policies": {}}

def save_rules_to_file(data):
    """Saves firewall rules to the JSON file."""
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        logging.error(f"Could not save rules to file: {e}")

def setup_stateful_rules(table):
    """Setup stateful firewall rules for connection tracking"""
    logging.info("Setting up stateful firewall rules...")
    
    for chain_name in ['INPUT', 'OUTPUT', 'FORWARD']:
        chain = iptc.Chain(table, chain_name)
        
        # Rule 1: Allow ESTABLISHED and RELATED connections
        rule = iptc.Rule()
        match = rule.create_match('conntrack')
        match.ctstate = 'ESTABLISHED,RELATED'
        rule.target = rule.create_target('ACCEPT')
        chain.insert_rule(rule)
        logging.info(f"Added ESTABLISHED,RELATED rule to {chain_name}")
        
        # Rule 2: Drop INVALID packets
        rule = iptc.Rule()
        match = rule.create_match('conntrack')
        match.ctstate = 'INVALID'
        rule.target = rule.create_target('DROP')
        chain.insert_rule(rule)
        logging.info(f"Added INVALID drop rule to {chain_name}")

def set_default_policies(table, config):
    """Sets default chain policies"""
    logging.info("Setting default chain policies...")
    
    policies = config.get("policies", {})
    default_policies = {
        'INPUT': policies.get('INPUT', 'DROP'),
        'OUTPUT': policies.get('OUTPUT', 'ACCEPT'),
        'FORWARD': policies.get('FORWARD', 'DROP')
    }
    
    for chain_name, policy in default_policies.items():
        chain = iptc.Chain(table, chain_name)
        chain.set_policy(policy)
        logging.info(f"Set {chain_name} default policy to {policy}")

def build_and_insert_rule(chain, rule_def):
    rule = iptc.Rule()

    if rule_def.get("source"):
        rule.src = rule_def["source"]
    if rule_def.get("destination"):
        rule.dst = rule_def["destination"]
    if rule_def.get("protocol"):
        rule.protocol = rule_def["protocol"]
        
        proto = rule.protocol.lower()
        if proto in ("tcp", "udp"):
            match = rule.create_match(proto)
            if rule_def.get("sport"):
                match.sport = str(rule_def["sport"])
            if rule_def.get("dport"):
                match.dport = str(rule_def["dport"])

    target_name = rule_def.get("target")
    if not target_name:
        logging.warning(f"Skipping rule with no target: {rule_def}")
        return

    rule.target = rule.create_target(target_name)
    
    chain.insert_rule(rule)
    logging.info(f"Inserted rule into chain '{chain.name}': {rule_def}")

def apply_rules_to_iptables():
    logging.info("Applying iptables rules from configuration file...")
    
    max_retries = 5
    retry_delay = 0.5
    
    for attempt in range(max_retries):
        try:
            config = get_rules_from_file()
            table = iptc.Table(iptc.Table.FILTER)
            table.autocommit = False

            existing_chains = {chain.name for chain in table.chains}
            custom_chains_in_config = set(config.get("chains", []))
            
            # Flush built-in chains
            for chain_name in existing_chains:
                if chain_name in ("INPUT", "OUTPUT", "FORWARD"):
                    chain = iptc.Chain(table, chain_name)
                    chain.flush()
                    logging.info(f"Flushed chain: {chain_name}")
                elif chain_name not in custom_chains_in_config:
                    chain = iptc.Chain(table, chain_name)
                    try:
                        chain.flush()
                        table.delete_chain(chain_name)
                        logging.info(f"Deleted old custom chain: {chain_name}")
                    except Exception as e:
                        logging.warning(f"Could not delete chain {chain_name} (might be in use): {e}")

            # Create custom chains
            for chain_name in custom_chains_in_config:
                if chain_name not in existing_chains:
                    table.create_chain(chain_name)
                    logging.info(f"Created custom chain: {chain_name}")

            # Setup stateful firewall rules FIRST
            setup_stateful_rules(table)

            # Add user-defined rules
            for rule_def in config.get("rules", []):
                chain_name = rule_def.get("chain")
                if not chain_name:
                    logging.warning(f"Skipping rule with no chain specified: {rule_def}")
                    continue
                
                chain = iptc.Chain(table, chain_name)
                build_and_insert_rule(chain, rule_def)

            # Set default policies LAST
            set_default_policies(table, config)

            table.commit()
            table.autocommit = True
            logging.info("Successfully applied iptables rules.")
            return True, "Success"

        except iptc.ip4tc.IPTCError as e:
            error_msg = str(e)
            if "Resource temporarily unavailable" in error_msg and attempt < max_retries - 1:
                if 'table' in locals() and not table.autocommit:
                    table.refresh()
                    table.autocommit = True
                logging.warning(f"iptables locked, retrying in {retry_delay}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(retry_delay)
                retry_delay *= 2 
                continue
            else:
                if 'table' in locals() and not table.autocommit:
                    table.refresh()
                    table.autocommit = True
                error_message = f"ERROR applying iptables rules after {attempt + 1} attempts: {e}"
                logging.error(error_message, exc_info=True)
                return False, str(e)
        except Exception as e:
            if 'table' in locals() and not table.autocommit:
                table.refresh()
                table.autocommit = True
            error_message = f"ERROR applying iptables rules: {e}"
            logging.error(error_message, exc_info=True)
            return False, str(e)
    
    return False, "Failed after maximum retries due to iptables lock"

# ============================================================================
# CONNECTION MONITORING FUNCTIONS
# ============================================================================

def get_active_connections():
    connections = []
    
    commands_to_try = [
        (['ss', '-tuna'], 'ss'),
        (['netstat', '-tuna'], 'netstat'),
        (['netstat', '-an'], 'netstat-simple')
    ]
    
    for cmd, cmd_type in commands_to_try:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                logging.info(f"{cmd[0]} command returned {len(lines)} lines")
                
                if cmd_type == 'ss':
                    connections = parse_ss_output(lines)
                elif cmd_type.startswith('netstat'):
                    connections = parse_netstat_output(lines)
                
                if connections:
                    logging.info(f"Successfully parsed {len(connections)} connections using {cmd[0]}")
                    return connections
            else:
                logging.debug(f"{cmd[0]} command failed with return code {result.returncode}")
                
        except FileNotFoundError:
            logging.debug(f"{cmd[0]} command not found, trying next option")
            continue
        except subprocess.TimeoutExpired:
            logging.warning(f"Timeout while executing {cmd[0]}")
            continue
        except Exception as e:
            logging.debug(f"Error with {cmd[0]}: {e}")
            continue
    
    logging.error("No suitable command found to fetch connections (tried ss and netstat)")
    return connections

def parse_ss_output(lines):
    """Parse ss command output"""
    connections = []
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            continue
            
        parts = line.split()
        if len(parts) >= 5:
            try:
                conn = {
                    'protocol': parts[0].upper(),
                    'state': parts[1] if len(parts) > 1 else '-',
                    'recv_q': parts[2] if len(parts) > 2 else '0',
                    'send_q': parts[3] if len(parts) > 3 else '0',
                    'local': parts[4] if len(parts) > 4 else '-',
                    'remote': parts[5] if len(parts) > 5 else '-',
                    'process': ' '.join(parts[6:]) if len(parts) > 6 else '-'
                }
                connections.append(conn)
            except Exception as e:
                logging.debug(f"Error parsing ss line {i}: {e}")
    return connections

def parse_netstat_output(lines):
    connections = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('Active') or line.startswith('Proto'):
            continue
            
        parts = line.split()
        if len(parts) >= 5:
            try:
                protocol = parts[0].upper()
                
                if not protocol.startswith('TCP') and not protocol.startswith('UDP'):
                    continue
                
                conn = {
                    'protocol': protocol,
                    'recv_q': parts[1] if len(parts) > 1 else '0',
                    'send_q': parts[2] if len(parts) > 2 else '0',
                    'local': parts[3] if len(parts) > 3 else '-',
                    'remote': parts[4] if len(parts) > 4 else '-',
                    'state': parts[5] if len(parts) > 5 else 'UNKNOWN',
                    'process': parts[6] if len(parts) > 6 else '-'
                }
                connections.append(conn)
            except Exception as e:
                logging.debug(f"Error parsing netstat line {i}: {e}")
    return connections

def get_connection_stats():
    commands_to_try = [
        (['ss', '-s'], 'ss'),
        (['netstat', '-s'], 'netstat')
    ]
    
    for cmd, cmd_type in commands_to_try:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            continue
        except Exception as e:
            logging.debug(f"Error fetching stats with {cmd[0]}: {e}")
            continue
    
    return "Statistics unavailable (neither ss nor netstat found)"

# ============================================================================
# ROUTES - AUTHENTICATION
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = get_users()
        
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        users = get_users()
        
        if not check_password_hash(users[current_user.username], old_password):
            flash('Current password is incorrect', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'error')
        elif len(new_password) < 8:
            flash('New password must be at least 8 characters', 'error')
        else:
            users[current_user.username] = generate_password_hash(new_password)
            save_users(users)
            flash('Password changed successfully!', 'success')
            return redirect(url_for('index'))
    
    return render_template('change_password.html')

# ============================================================================
# ROUTES - MAIN APPLICATION
# ============================================================================

@app.route('/')
@login_required
def index():
    config = get_rules_from_file()
    return render_template('index.html', 
                         rules=config.get('rules', []), 
                         chains=config.get('chains', []),
                         policies=config.get('policies', {}))

@app.route('/connections')
@login_required
def connections():
    return render_template('connections.html')

@app.route('/api/connections')
@login_required
def api_connections():
    connections = get_active_connections()
    stats = get_connection_stats()
    return jsonify({
        'connections': connections,
        'stats': stats,
        'count': len(connections)
    })

@app.route('/add_rule', methods=['GET', 'POST'])
@login_required
def add_rule():
    if request.method == 'POST':
        # Create backup before making changes
        create_backup()
        
        new_rule = {
            "chain": request.form.get('chain', '').strip() or None,
            "source": request.form.get('source', '').strip() or None,
            "destination": request.form.get('destination', '').strip() or None,
            "protocol": request.form.get('protocol', '').strip() or None,
            "dport": request.form.get('dport', '').strip() or None,
            "sport": request.form.get('sport', '').strip() or None,
            "target": request.form.get('target', '').strip().upper() or None
        }
        
        # Log what we received
        logging.info(f"Attempting to add rule: {new_rule}")
        
        # Validate the rule
        valid, error_msg = validate_rule(new_rule)
        if not valid:
            logging.warning(f"Rule validation failed: {error_msg}")
            flash(f'Validation error: {error_msg}', 'error')
            return redirect(url_for('index'))
        
        # Remove None values
        new_rule = {k: v for k, v in new_rule.items() if v}
        
        config = get_rules_from_file()
        config.setdefault('rules', []).append(new_rule)
        save_rules_to_file(config)

        success, message = apply_rules_to_iptables()
        if success:
            flash('Rule added and firewall updated successfully!', 'success')
        else:
            flash(f'Failed to apply rules: {message}', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete_rule', methods=['POST'])
@login_required
def delete_rule():
    # Create backup before making changes
    create_backup()
    
    rule_index_str = request.form.get('rule_index')

    try:
        rule_index = int(rule_index_str)
        config = get_rules_from_file()
        rules_list = config.get('rules', [])

        if 0 <= rule_index < len(rules_list):
            rules_list.pop(rule_index)
            save_rules_to_file(config)
            
            success, message = apply_rules_to_iptables()
            if success:
                flash('Rule deleted and firewall updated successfully!', 'success')
            else:
                flash(f'Failed to apply rules: {message}', 'error')
        else:
            flash('Invalid rule index provided.', 'warning')
            
    except (ValueError, KeyError, TypeError) as e:
        flash(f'Invalid request to delete rule: {e}', 'error')
        
    return redirect(url_for('index'))

@app.route('/set_policy', methods=['POST'])
@login_required
def set_policy():
    # Create backup before making changes
    create_backup()
    
    chain = request.form.get('chain')
    policy = request.form.get('policy')
    
    if chain not in ['INPUT', 'OUTPUT', 'FORWARD']:
        flash('Invalid chain name', 'error')
        return redirect(url_for('index'))
    
    if policy not in ['ACCEPT', 'DROP']:
        flash('Invalid policy', 'error')
        return redirect(url_for('index'))
    
    config = get_rules_from_file()
    config.setdefault('policies', {})[chain] = policy
    save_rules_to_file(config)
    
    success, message = apply_rules_to_iptables()
    if success:
        flash(f'Policy for {chain} set to {policy}!', 'success')
    else:
        flash(f'Failed to apply policy: {message}', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Create default users if needed
    get_users()
    
    try:
        ok, msg = apply_rules_to_iptables()
        if not ok:
            logging.warning(f"Initial apply_rules_to_iptables() failed: {msg}")
    except Exception as e:
        logging.exception("Exception while applying rules at startup")

    app.run(host='0.0.0.0', port=5000, debug=False)
