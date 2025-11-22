import os
import json
import logging
import time
import iptc
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.urandom(24)

RULES_FILE = "firewall_rules.json"

def get_rules_from_file():
    if not os.path.exists(RULES_FILE):
        return {"chains": [], "rules": []}
    try:
        with open(RULES_FILE, 'r') as f:
            content = f.read()
            return json.loads(content) if content.strip() else {"chains": [], "rules": []}
    except (json.JSONDecodeError, IOError) as e:
        logging.error(f"Could not read/parse rules file: {e}")
        return {"chains": [], "rules": []}

def save_rules_to_file(data):
    """Saves firewall rules to the JSON file."""
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(data, f, indent=4)
    except IOError as e:
        logging.error(f"Could not save rules to file: {e}")

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
    retry_delay = 0.5  # seconds
    
    for attempt in range(max_retries):
        try:
            config = get_rules_from_file()
            table = iptc.Table(iptc.Table.FILTER)
            table.autocommit = False

            existing_chains = {chain.name for chain in table.chains}
            custom_chains_in_config = set(config.get("chains", []))
            
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

            for chain_name in custom_chains_in_config:
                if chain_name not in existing_chains:
                    table.create_chain(chain_name)
                    logging.info(f"Created custom chain: {chain_name}")

            for rule_def in config.get("rules", []):
                chain_name = rule_def.get("chain")
                if not chain_name:
                    logging.warning(f"Skipping rule with no chain specified: {rule_def}")
                    continue
                
                chain = iptc.Chain(table, chain_name)
                build_and_insert_rule(chain, rule_def)

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

@app.route('/')
def index():
    config = get_rules_from_file()
    return render_template('index.html', 
                         rules=config.get('rules', []), 
                         chains=config.get('chains', []))

@app.route('/connections')
def connections():
    return render_template('connections.html')

@app.route('/api/connections')
def api_connections():
    connections = get_active_connections()
    stats = get_connection_stats()
    return jsonify({
        'connections': connections,
        'stats': stats,
        'count': len(connections)
    })

@app.route('/add_rule', methods=['GET', 'POST'])
def add_rule():
    config = get_rules_from_file()
    
    new_rule = {
        "chain": request.form.get('chain'),
        "source": request.form.get('source', '').strip() or None,
        "destination": request.form.get('destination', '').strip() or None,
        "protocol": request.form.get('protocol', '').strip() or None,
        "dport": request.form.get('dport', '').strip() or None,
        "sport": request.form.get('sport', '').strip() or None,
        "target": request.form.get('target', '').strip().upper() or None
    }
    
    new_rule = {k: v for k, v in new_rule.items() if v}
    config.setdefault('rules', []).append(new_rule)
    save_rules_to_file(config)

    success, message = apply_rules_to_iptables()
    if success:
        flash('Rule added and firewall updated successfully!', 'success')
    else:
        flash(f'Failed to apply rules: {message}', 'error')
    return redirect(url_for('index'))

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
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

if __name__ == '__main__':
    try:
        ok, msg = apply_rules_to_iptables()
        if not ok:
            logging.warning(f"Initial apply_rules_to_iptables() failed: {msg}")
    except Exception as e:
        logging.exception("Exception while applying rules at startup")

    app.run(host='0.0.0.0', port=5000, debug=True)
