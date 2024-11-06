from flask import Flask, request, render_template, redirect, url_for
from pymongo import MongoClient
from datetime import datetime
from collections import defaultdict



app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb+srv://admin:password12345678@cluster0.qjpuf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['soc_monitoring_db']
blocked_ips_collection = db['blocked_ips']  # Collection to store blocked IPs
incident_logs_collection = db['incident_logs']  # Collection for recording incidents

# Rate limit configuration
RATE_LIMIT = 100  # Max requests allowed per minute per IP
TIME_WINDOW = 60  # Time window for the rate limit (in seconds)

# Dictionary to track requests per IP within the time window
request_counts = defaultdict(list)

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Middleware to check for DDoS and rate limit
@app.before_request
def check_rate_limit():
    client_ip = request.remote_addr  # Get client's IP address

    # Record the current timestamp of the request
    current_time = datetime.utcnow().timestamp()
    request_counts[client_ip].append(current_time)

    # Clean up old requests (older than the time window)
    request_counts[client_ip] = [timestamp for timestamp in request_counts[client_ip] if current_time - timestamp < TIME_WINDOW]

    # Check if the number of requests exceeds the limit
    if len(request_counts[client_ip]) > RATE_LIMIT:
        # Block the IP and log the incident
        block_ip(client_ip)
        return "Too many requests, you have been blocked due to possible DDoS attack.", 403

    return None

# Block the IP and record the incident in the database
def block_ip(ip):
    # Check if the IP is already blocked
    existing_block = blocked_ips_collection.find_one({"ip": ip})
    if existing_block is None:
        # Add the IP to the blocked list with the time of block
        blocked_ips_collection.insert_one({
            "ip": ip,
            "blocked_at": datetime.utcnow(),
        })

    # Log the DDoS incident
    incident_logs_collection.insert_one({
        "ip": ip,
        "incident_time": datetime.utcnow(),
        "message": "DDoS attack detected, IP blocked"
    })

# Admin route (accessible after login)
@app.route('/admin')
def admin():
    # Get blocked IPs and incidents
    blocked_ips = list(blocked_ips_collection.find())
    incidents = list(incident_logs_collection.find())
    return render_template('admin.html', blocked_ips=blocked_ips, incidents=incidents)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'password12345678':
            return redirect(url_for('admin'))
        else:
            return "Invalid credentials, please try again."
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
