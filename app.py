from flask import Flask, render_template, request, redirect, url_for, flash, session,g
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import random
from instamojo_wrapper import Instamojo
import requests
from werkzeug.security import generate_password_hash, check_password_hash
import functools
import io
import csv
from flask import Response



app = Flask(__name__, static_folder='static') # 



app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'authentication700@gmail.com'
app.config['MAIL_PASSWORD'] = 'uzytyvyhpklqgoxv'

db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    college = db.Column(db.String(120), nullable=False)
    year = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    payment = db.Column(db.String(6), nullable=True)
    pay_ID=db.Column(db.String(120), nullable=True)

# Define Event Registration Model (Simplified)
class EventRegistration(db.Model):
    __tablename__ = 'event_registration'
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(100), nullable=False)
    team_name = db.Column(db.String(100), nullable=True)
    participant_email = db.Column(db.String(120), nullable=False)
    extra_data = db.Column(db.JSON, nullable=True)  # Store additional fields like paper_id, paper_theme
    registered_at = db.Column(db.DateTime, default=db.func.now())


def send_otp(email, otp):
    msg = Message('Your OTP for Password Reset', sender='authentication700@gmail.com', recipients=[email])
    msg.body = f'Your OTP is {otp}. It is valid for 10 minutes.'
    mail.send(msg)

def send_otp_signup(email, otp):
    msg = Message('Your OTP for Signup', sender='authentication700@gmail.com', recipients=[email])
    msg.body = f'Your OTP is {otp}. It is valid for 10 minutes.'
    mail.send(msg)

@app.route('/')
def home():
    user_name = session.get('name', None) 
    payment=session.get('payment'); # Get logged-in user's name if exists
    return render_template('index.html', user_name=user_name,payment=payment)

@app.route('/profile')
def profile():
    if 'email' in session:
        return "<h1>PROFILE!!</h1>"
    else:
        flash('login first', 'danger')
        return redirect(url_for('login'))

@app.before_request
def before_request():
        g.user_name=session.get('name')
        g.email=session.get('email')
        g.phone=session.get('phone')
        g.college=session.get('college')
        g.year=session.get('year')
        g.payment=session.get('payment')

EVENTS = {
    "paperpres": "events/paperpres.html",
    "squidtronics": "events/squidtronics.html",
    "technowaves": "events/technowaves.html",
    "screenbug": "events/screenbug.html",
    "ipl": "events/ipl.html",
    "channel": "events/channel.html",
    "electromania": "events/electromania.html",
    "electrospark": "events/electrospark.html",
    "drone": "events/drone.html",
    "revotron": "events/revotron.html",
    "stage": "events/stage.html",
    "treasure": "events/treasure.html",
    "defend": "events/defend.html",
}

def create_route(event_name, template_path):
    @functools.wraps(lambda: None)  # Dummy function for wrapping
    def event_route():
        return render_template(template_path)

    # Set the endpoint name dynamically! This is the CRUCIAL fix
    event_route.__name__ = f"{event_name}_event"  # Unique endpoint names

    app.add_url_rule(f'/events/{event_name}', view_func=event_route, endpoint=f"{event_name}_event") # Explicitly set endpoint
    return event_route

for event_name, template_path in EVENTS.items():
    create_route(event_name, template_path)  # Call the

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form['otp']
        
        otp_session = session.get('otp')
        
        if otp_input == otp_session:
            new_user = User(
                name=session['name'],
                phone=session['phone'], 
                email=session['email'], 
                password=session['password'], 
                otp=None,
                year=session['year'],
                college=session['college'],
                payment="NO",
                pay_ID=None
            )
            db.session.add(new_user)
            db.session.commit()
            
            session.pop('name', None)
            session.pop('phone', None)
            session.pop('email', None)
            session.pop('password', None)
            session.pop('otp', None)
            session.pop('college', None)
            session.pop('year', None)


            
            flash('Signup successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('verify_otp'))
    
    return render_template('otp_verify.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'email' in session:  # Check if the user is already logged in
        flash('You are already logged in!', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        password = request.form['password']
        year=request.form['year']
        college=request.form['college']

        otp = str(random.randint(100000, 999999))
        
        existing_user = User.query.filter((User.phone == phone) | (User.email == email)).first()
        if existing_user:
            flash('Phone or Email already registered!', 'danger')
            return redirect(url_for('login'))
        
        session['name'] = name
        session['phone'] = phone
        session['email'] = email
        session['password'] = password
        session['otp'] = otp
        session['college']=college
        session['year']=year
        
        send_otp_signup(email, otp)
        flash('OTP sent to your email!', 'info')
        return redirect(url_for('verify_otp'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'email' in session:  # Check if the user is already logged in
        flash('You are already logged in!', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        identifier = request.form['identifier']
        password = request.form['password']
        
        user = User.query.filter((User.email == identifier) | (User.phone == identifier)).first()
        
        if user:
            if user.password == password:
                session['email'] = user.email
                session['name'] = user.name 
                session['phone'] = user.phone
                session['payment'] = user.payment
                flash('Login successful!', 'success')
                return redirect(url_for('home'))  
            else:
                flash('Invalid password. Please try again.', 'danger')
                return redirect(url_for('login')) 
        else:
            flash('User not found. Please sign up.', 'danger')
            return redirect(url_for('login')) 
    
    return render_template('login.html')


api_key = "e0c97f7f54762e076c7ee1afe2e0378c "
auth_token = "34c93658e03618e7efe91c588f751ec2"
headers = { "X-Api-Key": api_key, "X-Auth-Token": auth_token}

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if 'name' in session and 'email' in session and 'phone' in session:
        name = session['name']
        email = session['email']
        phone = session['phone']
        payment=session['payment']
        if(payment=='YES'):
            flash("Already Paid","success")
            return redirect(url_for('home'))

        payload = {
            'purpose': 'Revotronics 2025',
            'amount': 150,
            'buyer_name': name,
            'email': email,
            'phone': phone,
            'redirect_url': url_for('payment_success', _external=True),
            'send_email': 'True',
            'send_sms': 'False',
            'allow_repeated_payments': 'False',
        }

        if request.method == 'POST':
            response = requests.post("https://www.instamojo.com/api/1.1/payment-requests/", data=payload, headers=headers)
            print(response)
            if response.ok:
                payment_url = response.json()['payment_request']['longurl']
                return redirect(payment_url)
            else:
                flash("Error processing payment. Try again.", "danger")
                return redirect(url_for('payment'))
    else:
        flash("Session doesn't exist. Please log in again.", 'danger')
        return redirect(url_for('login'))

    return render_template('payment.html', name=name, email=email, phone=phone)


@app.route('/payment_success')
def payment_success():
    payment_request_id = request.args.get('payment_request_id')
    payment_id = request.args.get('payment_id')

    if not payment_request_id or not payment_id:
        flash("Invalid payment details!", "danger")
        return redirect(url_for('home'))

    # Verify payment with Instamojo API
    response = requests.get(
        f"https://www.instamojo.com/api/1.1/payment-requests/{payment_request_id}/",
        headers=headers
    )

    if response.ok:
        payment_status = response.json()["payment_request"]["payments"][0]["status"]  # Get payment status

        if payment_status == "Credit":
            # Mark payment as successful in the database
            user = User.query.filter_by(email=session.get('email')).first()
            if user:
                user.payment = "YES"
                user.pay_ID=payment_id
                db.session.commit()
                flash("Payment Successful!", "success")
            return redirect(url_for('home'))

        else:
            flash("Payment Pending or Failed!", "danger")
            return redirect(url_for('payment'))
    else:
        flash("Payment verification failed!", "danger")
        return redirect(url_for('home'))
EVENTS = {
    "drone": {"min_per_team": 1, "max_per_team": 1, "max_teams": 30, "extra_fields": []},
    "revothon": {"min_per_team": 2, "max_per_team": 4, "max_teams": 30,"extra_fields": ["paper_theme", "paper_id"] },
    "ipl": {"min_per_team": 3, "max_per_team": 4, "max_teams": 30, "extra_fields": []},
    "treasure": {"min_per_team": 2, "max_per_team": 3, "max_teams": 12, "extra_fields": []},
    "paperpres": {"min_per_team": 1, "max_per_team": 3, "max_teams": 20,"extra_fields": []},
    "stage": {"min_per_team": 1, "max_per_team": 3, "max_teams": 20, "extra_fields": ["performance_type"]},
    "squidtronics": {"min_per_team": 3, "max_per_team": 3, "max_teams": 15, "extra_fields": []},
    "screenbug": {"min_per_team": 2, "max_per_team": 3, "max_teams": 15, "extra_fields": []},
    "electrospark": {"min_per_team": 2, "max_per_team": 2, "max_teams": 18, "extra_fields": []},
    "defend": {"min_per_team": 1, "max_per_team": 1, "max_teams": 25, "extra_fields": []},
    "technowaves": {"min_per_team": 2, "max_per_team": 3, "max_teams": 18, "extra_fields": []},
    "channel": {"min_per_team": 3, "max_per_team": 5, "max_teams": 13, "extra_fields": []},
    "electromania": {"min_per_team": 1, "max_per_team": 2, "max_teams": 20, "extra_fields":[]},
}



@app.route('/register_event/<event_name>', methods=['GET', 'POST'])
def register_event(event_name):
    # Check if the event exists in the dictionary
    if event_name not in EVENTS:
        flash('Invalid event name', 'danger')
        return redirect(url_for('home'))

    # Check if the email is present in the session
    if 'email' not in session:
        flash('Please log in to register for the event', 'danger')
        return redirect(url_for('login'))

    event_config = EVENTS[event_name]

    if request.method == 'GET':
        # For GET requests, render the event registration form
        return render_template('register_event.html', event_name=event_name, event_config=event_config)

    if request.method == 'POST':
        team_name = request.form.get('team_name')
        participant_emails = request.form.get('participants').split(',')
        extra_data = {}

        # Special fields validation for Revothon and Stage Unplugged
        if "extra_fields" in event_config:
            for field in event_config["extra_fields"]:
                extra_field_value = request.form.get(field)
                if not extra_field_value:
                    flash(f'Missing required field: {field}', 'danger')
                    return redirect(url_for('register_event', event_name=event_name))
                extra_data[field] = extra_field_value

            # Validate performance type for Stage Unplugged
            if event_name == "stage" and extra_data["performance_type"] not in ["singing", "dancing", "acting", "performance"]:
                flash('Invalid performance type. Choose from: singing, dancing, acting, performance', 'danger')
                return redirect(url_for('register_event', event_name=event_name))

        # Validate team size
        if not (event_config["min_per_team"] <= len(participant_emails) <= event_config["max_per_team"]):
            flash(f'Team size must be between {event_config["min_per_team"]} and {event_config["max_per_team"]}', 'danger')
            return redirect(url_for('register_event', event_name=event_name))

        # Check if the maximum number of teams has been reached
        existing_teams_count = EventRegistration.query.filter(EventRegistration.event_name == event_name).distinct(EventRegistration.team_name).count()
        
        if existing_teams_count >= event_config.get("max_teams", 0):  # Default max_teams if not specified
            flash('Sorry, this event has reached the maximum number of teams. Registration is closed.', 'danger')
            return redirect(url_for('home'))

        # Fetch participant details and validate
        participants = User.query.filter(User.email.in_(participant_emails)).all()

        if len(participants) != len(participant_emails):
            flash('One or more participants not found in the database', 'danger')
            return redirect(url_for('register_event', event_name=event_name))

        # Check payment status
        for participant in participants:
            if participant.payment != "YES":
                flash(f'{participant.email} has not completed payment', 'danger')
                return redirect(url_for('register_event', event_name=event_name))

        # Check if any participant is already registered in the event
        existing_participants = EventRegistration.query.filter(
            EventRegistration.event_name == event_name,
            EventRegistration.participant_email.in_(participant_emails)
        ).all()

        if existing_participants:
            flash('One or more participants are already registered for this event', 'danger')
            return redirect(url_for('register_event', event_name=event_name))

        # Register the team and participants
        try:
            for participant in participants:
                registration = EventRegistration(
                    event_name=event_name,
                    team_name=team_name,
                    participant_email=participant.email,
                    extra_data=extra_data  # Stores extra fields for special events
                )
                db.session.add(registration)

            db.session.commit()
            flash(f'Successfully registered for {event_name}', 'success')
            return redirect(url_for('home'))

        except IntegrityError:
            db.session.rollback()
            flash('Database error occurred. Try again', 'danger')
            return redirect(url_for('register_event', event_name=event_name))



@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

@app.route('/password_recovery', methods=['GET', 'POST'])
def password_recovery():
    if 'email' in session:
        flash("already logged in","info")
        return redirect(url_for('home'))
    else:
        if request.method == 'POST':
            email = request.form['email']
            
            user = User.query.filter_by(email=email).first()
            if user:
                otp = str(random.randint(100000, 999999))
                user.otp = otp
                db.session.commit()
                send_otp(email, otp)
                flash('OTP sent to your email!', 'info')
                return redirect(url_for('reset_password', email=email))
            else:
                flash('Email not found.', 'danger')
                return redirect(url_for('password_recovery'))
        
        return render_template('password_recovery.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    if 'email' in session:
        flash("already logged in","info")
        return redirect(url_for('home'))
    else:
        user = User.query.filter_by(email=email).first()
        if user is None:
            flash('Invalid email address!', 'danger')
            return redirect(url_for('home'))
        
        if request.method == 'POST':
            otp_input = request.form['otp']
            new_password = request.form['new_password']
            
            if otp_input == user.otp:
                user.password = new_password
                user.otp = None  # Clear OTP after use
                db.session.commit()
                flash('Password successfully reset!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
                return redirect(url_for('reset_password', email=email))
        
        return render_template('reset_password.html', email=email)



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    session.clear()
    if 'admin' in session:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate admin credentials (this is a simple check, you can use a database for real use cases)
        if username == 'admin' and check_password_hash(generate_password_hash('adminpassword'), password):
            session['admin'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials, please try again', 'danger')
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    event_data = []
    paid_users_count = User.query.filter_by(payment="YES").count()
    for event_name, event_config in EVENTS.items():
        # Get the count of teams registered for each event
        team_count = EventRegistration.query.filter_by(event_name=event_name).distinct(EventRegistration.team_name).count()
        event_data.append({
            'event_name': event_name,
            'description': event_config.get('description', 'No description available'),
            'team_count': team_count
        })
    
    return render_template('admin_dashboard.html', event_data=event_data,paid_users_count=paid_users_count)

@app.route('/admin/download_event_data/<event_name>')
def download_event_data(event_name):
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    # Query the event registrations based on event_name
    registrations = EventRegistration.query.filter_by(event_name=event_name).all()

    # Prepare CSV content
    output = io.StringIO()
    writer = csv.writer(output)

    # Write the header row
    writer.writerow(['Team Name', 'Event Name', 'Participant Name', 'Email', 'College', 'Year', 'Extra Data'])

    # Loop through registrations and gather data from both EventRegistration and User
    for registration in registrations:
        participant_email = registration.participant_email
        # Query user details by email
        user = User.query.filter_by(email=participant_email).first()

        # If user is found, write the data to CSV
        if user:
            writer.writerow([
                registration.team_name,  # Team Name
                registration.event_name,  # Event Name
                user.name,  # Participant Name
                user.email,  # Email
                user.college,  # College
                user.year,  # Year
                registration.extra_data  # Extra Data (from EventRegistration)
            ])

    output.seek(0)
    
    # Return the CSV file as a downloadable response
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename={event_name}_registrations.csv"})

@app.route('/admin/download_paid_users')
def download_paid_users():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    # Query users with payment == "YES"
    paid_users = User.query.filter_by(payment="YES").all()

    # Prepare CSV content
    output = io.StringIO()
    writer = csv.writer(output)

    # Write the header row for the CSV file
    writer.writerow(['Name', 'Email', 'College', 'Year'])

    # Loop through paid users and write their details to the CSV
    for user in paid_users:
        writer.writerow([user.name, user.email, user.college, user.year])

    output.seek(0)
    
    # Return the CSV file as a downloadable response
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=paid_users.csv"})


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)  # Clear the admin session
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
