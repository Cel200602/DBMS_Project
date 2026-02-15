
import requests
from bs4 import BeautifulSoup

BASE_URL = 'http://127.0.0.1:5000'
LOGIN_URL = f'{BASE_URL}/login'
DASHBOARD_URL = f'{BASE_URL}/user/dashboard'
INCIDENT_LOGIN_URL = f'{BASE_URL}/user/incident_login'
INCIDENTS_URL = f'{BASE_URL}/user/incidents'

s = requests.Session()

def test_login():
    print(f"1. Accessing {LOGIN_URL}...")
    r = s.get(LOGIN_URL)
    if r.status_code != 200:
        print(f"[FAIL] Failed to access login page. Status: {r.status_code}")
        return False
    
    print("2. Attempting login as 'testuser'...")
    payload = {'username': 'testuser', 'password': 'user123'}
    r = s.post(LOGIN_URL, data=payload)
    
    if r.url == DASHBOARD_URL:
        print(f"[PASS] Successfully redirected to {DASHBOARD_URL}")
    elif r.url == LOGIN_URL:
         print(f"[FAIL] Redirected back to login. Login failed.")
         return False
    else:
        print(f"[WARN] Redirected to unexpected URL: {r.url}")

    # Check dashboard content
    if "User Dashboard" in r.text:
        print("[PASS] 'User Dashboard' found in response.")
    else:
        print("[FAIL] 'User Dashboard' NOT found in response.")

    return True

def test_incident_access():
    print(f"3. Accessing {INCIDENTS_URL} (should redirect to incident_login)...")
    r = s.get(INCIDENTS_URL)
    if r.url == INCIDENT_LOGIN_URL or 'incident_login' in r.url:
        print(f"[PASS] Correctly redirected to {r.url}")
    else:
         print(f"[FAIL] Expected redirect to incident_login, got {r.url}")
         return False

    print("4. Attempting incident login...")
    payload = {'username': 'testuser', 'password': 'user123'}
    r = s.post(INCIDENT_LOGIN_URL, data=payload)
    
    if r.url == INCIDENTS_URL:
        print(f"[PASS] Successfully redirected to {INCIDENTS_URL}")
    else:
        print(f"[FAIL] Failed to redirect to incidents. Got {r.url}")
        return False
        
    if "My Incidents" in r.text or "Reported Incidents" in r.text:
         print("[PASS] Incidents page content verified.")
    else:
         print("[WARN] Incidents page content might be missing expected text.")
         
    return True

def check_debug_users():
    print(f"0. Checking {BASE_URL}/debug/users...")
    try:
        r = s.get(f"{BASE_URL}/debug/users")
        print(f"Debug Users Response: {r.text}")
    except Exception as e:
        print(f"Failed to check debug users: {e}")

if __name__ == '__main__':
    check_debug_users()
    if test_login():
        test_incident_access()
