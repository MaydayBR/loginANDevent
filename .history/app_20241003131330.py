from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, DateField, TimeField, TextAreaField
from wtforms.validators import DataRequired
import requests
import json
from dotenv import load_dotenv
import os
from datetime import datetime
import pytz

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key securely
csrf = CSRFProtect(app)

# Eventbrite API credentials
EVENTBRITE_TOKEN = os.getenv('EVENTBRITE_TOKEN')

if not EVENTBRITE_TOKEN:
    raise ValueError("Eventbrite token must be set in environment variables.")

# Function to retrieve ORGANIZATION_ID
def get_organization_id():
    headers = {
        'Authorization': f'Bearer {EVENTBRITE_TOKEN}',
    }
    try:
        response = requests.get('https://www.eventbriteapi.com/v3/users/me/organizations/', headers=headers)
        response.raise_for_status()
        data = response.json()
        organizations = data.get('organizations', [])
        if organizations:
            organization_id = organizations[0]['id']
            return organization_id
        else:
            raise ValueError("No organizations found associated with your account.")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while retrieving organization ID: {http_err}")
        raise
    except Exception as err:
        print(f"An error occurred while retrieving organization ID: {err}")
        raise

# Retrieve ORGANIZATION_ID
ORGANIZATION_ID = get_organization_id()
print(f"Using ORGANIZATION_ID: {ORGANIZATION_ID}")

# Flask-WTF Form
class EventForm(FlaskForm):
    event_name = StringField('Event Name', validators=[DataRequired()])
    event_description = TextAreaField('Event Description', validators=[DataRequired()])
    event_date = DateField('Event Date (YYYY-MM-DD)', format='%Y-%m-%d', validators=[DataRequired()])
    event_start_time = TimeField('Event Start Time (HH:MM)', format='%H:%M', validators=[DataRequired()])
    event_end_time = TimeField('Event End Time (HH:MM)', format='%H:%M', validators=[DataRequired()])

# Route for the home page
@app.route('/', methods=['GET', 'POST'])
def home():
    form = EventForm()
    if form.validate_on_submit():
        # Process the form data
        event_name = form.event_name.data
        event_description = form.event_description.data
        event_date = form.event_date.data
        event_start_time = form.event_start_time.data
        event_end_time = form.event_end_time.data

        # Combine date and time
        local_timezone = pytz.timezone('America/New_York')
        local_start_datetime = local_timezone.localize(datetime.combine(event_date, event_start_time))
        local_end_datetime = local_timezone.localize(datetime.combine(event_date, event_end_time))

        # Convert to UTC
        event_utc_start_time = local_start_datetime.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        event_utc_end_time = local_end_datetime.astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Eventbrite API request data for event creation
        event_data = {
            "event": {
                "name": {
                    "html": event_name
                },
                "description": {
                    "html": event_description
                },
                "start": {
                    "timezone": "America/New_York",
                    "utc": event_utc_start_time
                },
                "end": {
                    "timezone": "America/New_York",
                    "utc": event_utc_end_time
                },
                "currency": "USD",
                "online_event": False,
                "listed": True,
                "shareable": True,
                "invite_only": False,
                "show_remaining": True,
                "capacity": 100,
                "locale": "en_US"
            }
        }

        # Headers for the request
        headers = {
            'Authorization': f'Bearer {EVENTBRITE_TOKEN}',
            'Content-Type': 'application/json'
        }

        try:
            # Step 1: Create the event
            response = requests.post(
                f'https://www.eventbriteapi.com/v3/organizations/{ORGANIZATION_ID}/events/',
                headers=headers,
                data=json.dumps(event_data)
            )
            response.raise_for_status()
            event_response = response.json()
            event_id = event_response['id']

            # Step 2: Create a free ticket class for the event
            ticket_data = {
                "ticket_class": {
                    "name": "General Admission",
                    "free": True,
                    "quantity_total": 100
                }
            }

            ticket_response = requests.post(
                f'https://www.eventbriteapi.com/v3/events/{event_id}/ticket_classes/',
                headers=headers,
                data=json.dumps(ticket_data)
            )
            ticket_response.raise_for_status()

            flash('Event created successfully with a free ticket class!', 'success')
            return redirect(url_for('home'))

        except requests.exceptions.HTTPError as http_err:
            try:
                error_message = response.json().get('error_description', str(http_err))
            except:
                error_message = str(http_err)
            print(f"HTTP error occurred: {http_err}")
            flash(f"Error creating event: {error_message}", 'error')
            return redirect(url_for('home'))

        except Exception as err:
            print(f"Other error occurred: {err}")
            flash(f"An error occurred: {err}", 'error')
            return redirect(url_for('home'))

    return render_template('create_event.html', form=form)

# Route to list all events for the organization
@app.route('/events', methods=['GET'])
def list_events():
    headers = {
        'Authorization': f'Bearer {EVENTBRITE_TOKEN}',
    }

    try:
        # Make the GET request to list events for the organization
        response = requests.get(
            f'https://www.eventbriteapi.com/v3/organizations/{ORGANIZATION_ID}/events/',
            headers=headers
        )
        response.raise_for_status()
        events_info = response.json()

        events = events_info.get('events', [])

        return render_template('events_list.html', events=events)

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        flash(f"Error retrieving events: {http_err}", 'error')
        return redirect(url_for('home'))

    except Exception as err:
        print(f"Other error occurred: {err}")
        flash(f"An error occurred: {err}", 'error')
        return redirect(url_for('home'))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('create_event'))
    return render_template('login.html', form=form)


@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    return render_template('create_event.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # This ensures that all tables are created
    app.run(debug=True)