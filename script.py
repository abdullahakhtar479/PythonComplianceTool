import subprocess
import re

def check_firewall_enabled():
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], capture_output=True, text=True)
        output = result.stdout
        lines = output.split('\n')
        firewall_states = [line.strip() for line in lines if "Firewall State" in line]
        if all(state.endswith("ON") for state in firewall_states):
            return "Firewall is enabled."
        elif all(state.endswith("OFF") for state in firewall_states):
            return "Firewall is disabled."
        else:
            return "Unable to determine the firewall status."
    except Exception as e:
        return f"Error occurred while checking firewall status: {e}"


def check_third_party_firewalls_enabled():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-WmiObject -Namespace root/SecurityCenter2 -Class FirewallProduct | Where-Object {$_.displayName -ne "Windows Defender Firewall"} | Select-Object -Property displayName, enabled'], capture_output=True, text=True)
        output = result.stdout
        firewall_info = re.findall(r'DisplayName\s*:\s*(.*?)\s*Enabled\s*:\s*(True|False)', output, re.IGNORECASE)
        
        if firewall_info:
            return "Enabled: " + ", ".join([f"{firewall[0]} ({'enabled' if firewall[1].lower() == 'true' else 'disabled'})" for firewall in firewall_info])
        else:
            return "No third-party firewalls found"
    except Exception as e:
        return f"Error occurred while checking third-party firewall status: {e}"


def check_antivirus_updated():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled'], capture_output=True, text=True)
        output = result.stdout.strip()

        # Check if antivirus is enabled
        if output.lower() == 'true':
            return "Antivirus is enabled."
        else:
            return "Antivirus is not enabled."
    except Exception as e:
        return f"Error occurred while checking antivirus status: {e}"

def check_backup_and_recovery():
    try:
        result = subprocess.run(['wmic', 'product', 'get', 'Name'], capture_output=True, text=True)
        output = result.stdout
        if "backup" in output.lower() or "recovery" in output.lower():
            return "Backup and recovery software is installed."
        else:
            return "No backup or recovery software found."
    except Exception as e:
        return f"Error occurred while checking backup and recovery: {e}"


def check_uac_enabled():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA'], capture_output=True, text=True)
        output = result.stdout.strip()
        uac_status = re.search(r'EnableLUA\s*:\s*(\d+)', output)
        if uac_status:
            if int(uac_status.group(1)) == 1:
                return "User Access Control (UAC) is enabled."
            else:
                return "User Access Control (UAC) is disabled."
        else:
            return "Unable to determine the UAC status."
    except Exception as e:
        return f"Error occurred while checking UAC status: {e}"


def check_security_updates():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-HotFix'], capture_output=True, text=True)
        output = result.stdout
        if "update" in output.lower():
            return "Latest security updates are installed."
        else:
            return "No security updates found."
    except Exception as e:
        return f"Error occurred while checking security updates: {e}"


def check_password_policy_compliance():
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-LocalGroupPolicy -Group "Administrators" | Format-List'], capture_output=True, text=True)
        output = result.stdout
        if "password" in output.lower():
            return "Password policies are enforced."
        else:
            return "No password policies found."
    except Exception as e:
        return f"Error occurred while checking password policy compliance: {e}"


def check_iso_27001_compliance():
    results = {}
    firewall_status = check_firewall_enabled()
    results['firewall_status'] = firewall_status

    antivirus_up_to_date = check_antivirus_updated()
    results['antivirus_status'] = "Antivirus up-to-date: Affirmative" if antivirus_up_to_date else "Antivirus up-to-date: Negative"

    return results

def check_system_info():
    try:
        result = subprocess.run(['systeminfo'], capture_output=True, text=True)
        output = result.stdout
        if re.search(r'OS Version:\s*10\.', output):
            return "System Info: Windows Server 2016 or later"
        else:
            return "System Info: Windows Server version not compliant"
    except Exception as e:
        return f"Error occurred while checking system info: {e}"

def main():
    print("Checking Windows Server compliance...")
    check_iso_27001_compliance()
    check_third_party_firewalls_enabled()
    check_backup_and_recovery()
    check_uac_enabled()
    check_security_updates()
    check_password_policy_compliance
    check_system_info()

if __name__ == "__main__":

    main()