import os
import json
import logging
import iptc
from flask import Flask, render_template, request, redirect, url_for, flash

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.urandom(24)

RULES_FILE = "firewall_rules.json"

def get_rules_from_file():
    """Reads firewall rules from the JSON file."""
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

def apply_rules_to_iptables():
    """
    Reads configuration from RULES_FILE and applies it to the filter table.
    This function attempts to be robust: turns off autocommit while making
    many changes, uses Chain objects for deletion/creation, and validates
    chains exist before inserting rules.
    Returns (success: bool, message: str)
    """
    logging.info("Applying firewall rules from configuration file...")
    table = iptc.Table(iptc.Table.FILTER)
    try:
        # disable autocommit to stage changes, commit at the end
        table.autocommit = False
        # make sure we have the freshest view
        table.refresh()

        config = get_rules_from_file()
        chains_to_create = config.get("chains", [])
        rules_to_apply = config.get("rules", [])

        # --- Teardown Phase ---
        # 1) For builtin chains set policy to ACCEPT and flush them
        # 2) For non-builtin chains flush then delete them
        # iterate over a copy because we'll delete chains
        current_chains = list(table.chains)
        for chain in current_chains:
            try:
                if chain.is_builtin():
                    # set policy and flush
                    try:
                        chain.set_policy('ACCEPT')
                    except Exception:
                        # fallback if set_policy is not present
                        chain.policy = 'ACCEPT'
                    chain.flush()
                else:
                    # flush then delete
                    chain.flush()
                    # delete_chain expects a Chain object
                    table.delete_chain(chain)
            except Exception as e:
                logging.warning(f"Could not teardown chain {chain.name}: {e}")

        # commit teardown before rebuild (safer)
        table.commit()

        # --- Rebuild Phase ---
        table.refresh()

        # create chains from config (skip builtin names)
        for name in chains_to_create:
            if not table.is_chain(name):
                try:
                    table.create_chain(name)
                except Exception as e:
                    logging.error(f"Failed to create chain '{name}': {e}")
                    # continue trying to create other chains

        # Insert rules
        for rule_def in rules_to_apply:
            # validate required keys
            chain_name = rule_def.get("chain")
            target_name = rule_def.get("target")
            if not chain_name or not target_name:
                logging.warning(f"Skipping incomplete rule definition: {rule_def}")
                continue

            # ensure chain exists (create if missing)
            if not table.is_chain(chain_name):
                try:
                    table.create_chain(chain_name)
                except Exception as e:
                    logging.error(f"Failed to create chain '{chain_name}' for rule {rule_def}: {e}")
                    continue

            rule = iptc.Rule()
            if rule_def.get("source"):
                rule.src = rule_def["source"]
            if rule_def.get("destination"):
                rule.dst = rule_def["destination"]

            proto = (rule_def.get("protocol") or "").lower()
            # Only attach protocol and port matches for protocols that support ports
            if proto:
                rule.protocol = proto
                # tcp/udp support dport/sport via a Match('tcp') or Match('udp')
                try:
                    if proto in ("tcp", "udp"):
                        match = iptc.Match(rule, proto)
                        if rule_def.get("dport"):
                            match.dport = str(rule_def["dport"])
                        if rule_def.get("sport"):
                            match.sport = str(rule_def["sport"])
                        rule.add_match(match)
                    else:
                        # add a generic match for other protocols if needed
                        # Note: most other protocols don't have dport/sport attributes
                        match = iptc.Match(rule, proto)
                        rule.add_match(match)
                except Exception as e:
                    logging.warning(f"Could not add match for protocol '{proto}' on rule {rule_def}: {e}")

            # create and set target
            try:
                target = iptc.Target(rule, target_name.upper())
                rule.target = target
            except Exception as e:
                logging.error(f"Failed to create/set target '{target_name}' for rule {rule_def}: {e}")
                continue

            # finally insert into chain
            try:
                chain = iptc.Chain(table, chain_name)
                chain.insert_rule(rule)
            except Exception as e:
                logging.error(f"Failed to insert rule into chain {chain_name}: {e}")

        # commit all changes
        table.commit()
        logging.info("Successfully applied firewall rules.")
        return True, "Success"

    except Exception as e:
        # If we hit an exception before commit(), changes are not applied
        error_message = f"ERROR applying iptables rules: {e}. Changes were NOT committed."
        logging.error(error_message)
        # When running as main for debugging, re-raise for visibility
        if __name__ == '__main__':
            raise
        return False, str(e)
    finally:
        try:
            table.autocommit = True
            table.refresh()
        except Exception:
            # ignore any finalization errors
            pass

# --- Flask Routes ---
@app.route('/')
def index():
    config = get_rules_from_file()
    return render_template('index.html', rules=config.get('rules', []), chains=config.get('chains', []))

@app.route('/add_rule', methods=['POST'])
def add_rule():
    config = get_rules_from_file()
    new_rule = {
        "chain": request.form.get('chain'),
        "source": request.form.get('source', '').strip() or None,
        "destination": request.form.get('destination', '').strip() or None,
        "protocol": request.form.get('protocol', '').strip() or None,
        "dport": request.form.get('dport', '').strip() or None,
        "sport": request.form.get('sport', '').strip() or None,
        "target": (request.form.get('target') or '').upper()
    }
    # remove falsy values (None, empty strings)
    new_rule = {k: v for k, v in new_rule.items() if v}
    config.setdefault('rules', []).append(new_rule)
    save_rules_to_file(config)

    success, message = apply_rules_to_iptables()
    if success:
        flash('Rule added and firewall updated successfully!', 'success')
    else:
        flash(f'Failed to apply rules: {message}', 'error')
    return redirect(url_for('index'))

# app.py

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    # Get the index from the form data
    rule_index_str = request.form.get('rule_index')

    try:
        # Convert the index string to an integer
        rule_index = int(rule_index_str)
        
        config = get_rules_from_file()
        rules_list = config.get('rules', [])

        # Check if the index is valid
        if 0 <= rule_index < len(rules_list):
            # Use pop() to remove the rule at the specific index
            rules_list.pop(rule_index) 
            config['rules'] = rules_list # Update the list in config (optional, pop modifies in place)
            
            save_rules_to_file(config)
            
            success, message = apply_rules_to_iptables()
            if success:
                flash('Rule deleted and firewall updated successfully!', 'success')
            else:
                flash(f'Failed to apply rules: {message}', 'error')
        else:
            flash('Invalid rule index provided.', 'warning')
            
    except (ValueError, KeyError, TypeError) as e:
        # Catches errors if rule_index_str is not an integer or other errors
        flash(f'Invalid request to delete rule: {e}', 'error')
        
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Try applying rules at startup (useful in a container)
    try:
        ok, msg = apply_rules_to_iptables()
        if not ok:
            logging.warning(f"Initial apply_rules_to_iptables() failed: {msg}")
    except Exception as e:
        logging.exception("Exception while applying rules at startup")

    app.run(host='0.0.0.0', port=5000)
