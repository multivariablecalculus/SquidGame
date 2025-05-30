#I should be proud since I was not lazy making this and used full variable names for better understanding.
#Do consider understanding the logic in certain portions, but Flask is not very hard, so nvm.

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import random
import re

app = Flask(__name__)
app.secret_key = 'hacker_haven' #reminds me of something...
bcrypt = Bcrypt(app)

# MongoDB Setup

client = MongoClient(
    "mongodb+srv://x_codemcu_x:abhradeep%402010@squidgame.f4kia.mongodb.net/squidgame?retryWrites=true&w=majority", #I beg you, pls do not steal this :(
    tlsAllowInvalidCertificates=True,  #Disable strict SSL verification
    serverSelectionTimeoutMS=50000  #Increase timeout
)

db = client['squidgame']
players_collection = db['players']

MAX_PLAYERS = 25
MAX_EMPLOYEES = 25
EMPLOYEE_RANKS = ["Guard", "Soldier", "Manager"]
ROLE_LIMITS = {"Manager": 7, "Soldier": 9, "Guard": 9}


def ipv4(ip_list):
    for ip in ip_list.split(','):
        ip = ip.strip()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return ip
    return None


@app.route('/get-ip')
def get_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    real_ip = ipv4(forwarded_for) or request.remote_addr
    return jsonify({"ipv4": real_ip})


@app.route('/save-ip', methods=['POST'])
def save_ip():
    data = request.get_json()
    user_ip = data.get("ip")
    return jsonify({"received_ip": user_ip})


def get_next_available_number(role):
    if role == "Player":
        taken_numbers = {p.get('player_no') for p in players_collection.find({'role': 'Player'}, {'player_no': 1})}
        for num in range(2, 26):
            player_no = f"{num:03}"
            if player_no not in taken_numbers:
                return player_no
        return None

    else:
        taken_numbers = {e.get('employee_no') for e in players_collection.find({'role': {'$ne': 'Player'}}, {'employee_no': 1})}
        for num in range(1, 26):
            employee_no = f"{num:03}"
            if employee_no not in taken_numbers:
                return employee_no
        return None

def employee_rank():
    role_counts = {
        "Manager": players_collection.count_documents({"rank": "Manager"}),
        "Soldier": players_collection.count_documents({"rank": "Soldier"}),
        "Guard": players_collection.count_documents({"rank": "Guard"})
    }

    available_roles = []
    
    if role_counts["Manager"] < ROLE_LIMITS["Manager"]:
        available_roles.extend(["Manager"] * 2)
    
    if role_counts["Soldier"] < ROLE_LIMITS["Soldier"]:
        available_roles.extend(["Soldier"] * 3)

    if role_counts["Guard"] < ROLE_LIMITS["Guard"]:
        available_roles.extend(["Guard"] * 5)

    return random.choice(available_roles) if available_roles else None

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        dob = request.form['dob']
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        user_ip = request.form.get('user_ip', '0.0.0.0')

        if user_ip != "152.58.176.218":
            if players_collection.find_one({'user_ip': user_ip}):
                return "You have already registered with this IP address!"

        assigned_number = get_next_available_number(role)
        if not assigned_number:
            return f"Maximum {role.lower()} limit reached."

        if role == "Player":
            rank = "Player"
        else:
            rank = employee_rank()
            if not rank:
                return "Maximum employee limit reached."

        player_data = {
            'name': name,
            'dob': dob,
            'username': username,
            'password': password,
            'role': role,
            'rank': rank,
            'user_ip': user_ip
        }

        if role == "Player":
            player_data['player_no'] = assigned_number
        else:
            player_data['employee_no'] = assigned_number

        players_collection.insert_one(player_data)

        session['username'] = username
        session['role'] = role
        session['rank'] = rank
        if role == "Player":
            session['player_no'] = assigned_number
        else:
            session['employee_no'] = assigned_number

        return redirect(url_for('dashboard'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_ip = request.form.get('user_ip', '0.0.0.0')  # Get IPv4 from form

        user = players_collection.find_one({'username': username})

        if user and bcrypt.check_password_hash(user['password'], password):
            #Update username in MongoDB
            players_collection.update_one({'username': username}, {'$set': {'user_ip': user_ip}})

            session['username'] = username
            session['role'] = user['role']
            session['rank'] = user.get('rank', None)

            if user['role'] == "Player":
                session['player_no'] = user.get('player_no', None)
            else:
                session['employee_no'] = user.get('employee_no', None)

            if username == "codemcu": #pls do not use these creds; these are mine :(
                session['is_admin'] = True
                return redirect(url_for('admin_panel'))

            return redirect(url_for('dashboard'))

        return "Invalid credentials. Try again."

    return render_template('login.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if not session.get('is_admin'):
        return "Access Denied."

    if request.method == 'POST':
        target_username = request.form['username']
        user = players_collection.find_one({'username': target_username})

        if user:
            session['username'] = target_username
            session['role'] = user['role']
            session['rank'] = user.get('rank', None)

            if user['role'] == "Player":
                session['player_no'] = user.get('player_no', None)
            else:
                session['employee_no'] = user.get('employee_no', None)

            return redirect(url_for('dashboard'))

        return "User not found."

    return render_template('admin_panel.html')


@app.route('/view-admin-dashboard')
def admin_dashboard():
    if session.get('username') == "codemcu":
        user = players_collection.find_one({'username': 'codemcu'})
        return render_template("dashboard_player.html", user=user)
    return "Access Denied."


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = players_collection.find_one({'username': session['username']})

    if not user:
        return "User not found."

    if user['role'] == "Player":
        return render_template("dashboard_player.html", user=user)
    else:
        return render_template("dashboard_employee.html", user=user)


@app.route('/manage_accounts')
def manage_accounts():
    if 'username' not in session or session.get('rank') != "The Officer":
        return "Access Denied."

    accounts = list(players_collection.find(
        {'username': {'$ne': 'codemcu'}, 'role': {'$ne': 'admin'}},
        {'_id': 0}
    ))

    return render_template('manage_accounts.html', accounts=accounts)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
