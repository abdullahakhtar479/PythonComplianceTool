from flask import Flask, render_template, jsonify, request
from script import (
    check_firewall_enabled,
    check_third_party_firewalls_enabled,
    check_antivirus_updated,
    check_backup_and_recovery,
    check_uac_enabled,
    check_security_updates,
    check_password_policy_compliance,
    check_system_info
)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/run_checks', methods=['POST'])
def run_checks():
    results = {
        "firewall_status": check_firewall_enabled(),
        "third_party_firewalls_status": check_third_party_firewalls_enabled(),
        "antivirus_status": check_antivirus_updated(),
        "backup_and_recovery_status": check_backup_and_recovery(),
        "uac_status": check_uac_enabled(),
        "security_updates_status": check_security_updates(),
        "password_policy_compliance_status": check_password_policy_compliance(),
        "system_info_status": check_system_info(),
    }
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
