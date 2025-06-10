import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
import psycopg2
import psycopg2.extras
import bcrypt
import pytz
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from calendar import monthrange
from psycopg2 import Error as Psycopg2Error
from forms import ScheduleForm 
from psycopg2 import IntegrityError

load_dotenv()  # Load .env file in development

# --- App Configuration ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')  # Required in production
local_tz = pytz.timezone(os.getenv('TZ', 'UTC'))  # Default to UTC

# --- Database Configuration ---
def get_db():
    conn = psycopg2.connect(
         host=os.getenv('DB_HOST'),
         database=os.getenv('DB_NAME'),
         user=os.getenv('DB_USER'),
         password=os.getenv('DB_PASSWORD', ''),
         port=os.getenv('DB_PORT')
    )
    conn.autocommit = True
    return conn
    

@app.context_processor
def inject_now():
    return {'now': datetime.now(local_tz)}

# Add this before creating routes
@app.template_filter('format_date')
def format_date_filter(value, format_str):
    """Convert UTC datetime to local timezone and format"""
    if not value:
        return ""
    
    # If datetime is naive, assume it's UTC
    if value.tzinfo is None:
        value = pytz.utc.localize(value)
    
    try:
        local_time = value.astimezone(local_tz)
        return local_time.strftime(format_str)
    except Exception as e:
        print(f"Date formatting error: {e}")
        return value.strftime(format_str)        


# Index route
@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('index.html')

    
    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    user = None
    latest_reading = None
    schedules = []
    readings_count = 0
    upcoming_schedules_count = 0

    try:
        # Get user info
        cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        user_row = cursor.fetchone()
        if user_row:
            user = dict(user_row)

        # Get latest meter reading for dashboard
        cursor.execute("""
            SELECT reading, created_at
            FROM meter_readings
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (session['user_id'],))
        reading_row = cursor.fetchone()

        if reading_row:
            latest_reading = dict(reading_row)
            created_at_utc = latest_reading['created_at']
            if created_at_utc.tzinfo is None:
                created_at_utc = created_at_utc.replace(tzinfo=pytz.utc)
            latest_reading['formatted_date'] = created_at_utc.astimezone(local_tz).strftime('%b %d, %Y %I:%M %p')

        # Get total readings count
        cursor.execute("SELECT COUNT(*) FROM meter_readings WHERE user_id = %s", (session['user_id'],))
        readings_count = cursor.fetchone()[0]

        # Get upcoming schedules
        cursor.execute("""
            SELECT id, title, description, scheduled_date
            FROM schedules
            WHERE is_completed = FALSE
              AND scheduled_date >= NOW()
            ORDER BY scheduled_date ASC
            LIMIT 5
        """)
    
        schedule_rows = cursor.fetchall()
        for row in schedule_rows:
            schedule = dict(row)
            scheduled_date_utc = schedule['scheduled_date']
            if scheduled_date_utc.tzinfo is None:
                scheduled_date_utc = scheduled_date_utc.replace(tzinfo=pytz.utc)
            schedule['scheduled_date'] = scheduled_date_utc.astimezone(local_tz)
            schedules.append(schedule)

        # Get count of upcoming schedules
        cursor.execute("""
            SELECT COUNT(*)
            FROM schedules
            WHERE is_completed = FALSE
              AND scheduled_date >= NOW()
        """)
        upcoming_schedules_count = cursor.fetchone()[0]


             # Announcement
        cursor.execute("""
                SELECT title, message, created_at
                FROM announcements              
                 ORDER BY created_at DESC
                 LIMIT 5  
             """)
        
        announcements = []
        for row in cursor.fetchall():      
            announcement_item = dict(row)
            announcement_item['created_at'] = announcement_item['created_at'].astimezone(local_tz)
            announcements.append(announcement_item)

    except psycopg2.Error as e:
        flash(f"Error fetching data: {e.pgerror}", 'danger')

    finally:
        cursor.close()
        conn.close()

    return render_template('index.html',
                           user=user,
                           latest_reading=latest_reading,
                           schedules=schedules,
                           readings_count=readings_count,
                           upcoming_schedules_count=upcoming_schedules_count,
                           announcements=announcements,
                           now=datetime.now(local_tz),
                           is_admin=session.get('is_admin', False))


# --- User login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # process login form
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cursor.fetchone()

                if user and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['is_admin'] = user['is_admin']
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Invalid username or password', 'danger')
        except psycopg2.Error as e:
            flash(f'Database error: {str(e)}', 'danger')
        finally:
            conn.close()

    # Always return this for GET requests or after failure
    return render_template('login.html')


# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        unit_number = request.form['unit_number']

        if not username or not email or not password or not confirm_password or not unit_number:
            flash('All fields, including Unit Number, are required!', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT * FROM users
                    WHERE username = %s OR email = %s OR unit_number = %s
                """, (username, email, unit_number))
                existing_user = cursor.fetchone()

                if existing_user:
                    if existing_user['username'] == username:
                        flash('Username already exists!', 'danger')
                    elif existing_user['email'] == email:
                        flash('Email already exists!', 'danger')
                    elif existing_user['unit_number'] == unit_number:
                        flash('Unit number already registered!', 'danger')
                    return redirect(url_for('register'))

                hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
                cursor.execute("""
                    INSERT INTO users (username, email, password, unit_number)
                    VALUES (%s, %s, %s, %s)
                """, (username, email, hashed_password, unit_number))
                conn.commit()

                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))

        except psycopg2.Error as e:
            conn.rollback()
            flash(f'Database error: {e}', 'danger')
            return redirect(url_for('register'))

        finally:
            conn.close()

    return render_template('register.html')


# Promote user
@app.route('/admin/promote', methods=['POST'])
def promote_user():
    if not session.get('is_admin', False):
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    user_id = request.form['user_id']
    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # Toggle boolean value
            cursor.execute("""
                UPDATE users 
                SET is_admin = NOT is_admin
                WHERE id = %s
                RETURNING username, is_admin
            """, (user_id,))
            result = cursor.fetchone()
            if result:
                status = "Admin" if result[1] else "Regular"
                flash(f"{result[0]} status: {status}", 'success')
    except psycopg2.Error as e:
        flash(f'Update failed: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('view_users'))


# Delete user
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard')) # Or appropriate redirect

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            # IMPORTANT: Delete related records from other tables first!
            # Delete associated meter readings
            cursor.execute("DELETE FROM meter_readings WHERE user_id = %s", (user_id,))
            flash(f"Deleted {cursor.rowcount} meter readings for user {user_id}", 'info')

            # Delete associated schedules (if schedules are user-specific)
            cursor.execute("DELETE FROM schedules WHERE user_id = %s", (user_id,))
            flash(f"Deleted {cursor.rowcount} schedules for user {user_id}", 'info')

            # Now, delete the user itself
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            flash('User deleted successfully', 'success')
            conn.commit()

    except psycopg2.Error as e:
        conn.rollback()
        flash(f'Delete user failed: {e.pgerror}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('view_users')) 

# --- View Announcements ---
@app.route('/announcements')
def announcements():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    announcements_list = []

    try:
        cursor.execute('''
            SELECT id, title, message, created_at 
            FROM announcements 
            ORDER BY created_at DESC
        ''')
        
        for row in cursor.fetchall():
            ann = dict(row)
            # Convert UTC to local timezone
            utc_time = ann['created_at']
            if utc_time.tzinfo is None:
                utc_time = pytz.utc.localize(utc_time)
            ann['created_at'] = utc_time.astimezone(local_tz)
            announcements_list.append(ann)

    except psycopg2.Error as e:
        flash(f'Error loading announcements: {e.pgerror}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return render_template('announcements.html',
                         announcements=announcements_list,
                         is_admin=session.get('is_admin', False))
          
            
# Meter route
@app.route('/meter', methods=['GET', 'POST'])
def meter():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            reading = float(request.form['reading'])
            if reading < 0:
                flash('Meter reading cannot be negative', 'danger')
                return redirect(url_for('meter'))
        except ValueError:
            flash('Invalid reading format', 'danger')
            return redirect(url_for('meter'))

        notes = request.form.get('notes', '')
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO meter_readings (user_id, reading, notes)
                VALUES (%s, %s, %s)
            """, (session['user_id'], reading, notes))
            flash('Reading saved successfully!', 'success')
        except psycopg2.Error as e:
            flash(f'Error saving reading: {e.pgerror}', 'danger')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('meter'))

    return render_template('meter.html')


# History route
@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    formatted_readings = []

    try:
        cursor.execute("""
            SELECT id, reading, notes, created_at
            FROM meter_readings
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (session['user_id'],))

        for row in cursor.fetchall():
            # Get the datetime object from the database row
            dt_from_db = row['created_at']

            # Check if the datetime object is naive (no tzinfo)
            if dt_from_db.tzinfo is None:
                # If naive, assume it's UTC and localize it
                created_at_utc_aware = pytz.utc.localize(dt_from_db)
            else:
                # If already timezone-aware, use it directly (it's likely already in UTC or its original timezone)
                created_at_utc_aware = dt_from_db

            # Now convert the timezone-aware datetime to the local timezone
            created_at_local = created_at_utc_aware.astimezone(local_tz)

            formatted_readings.append({
                'id': row['id'],
                'reading': row['reading'],
                'notes': row['notes'],
                'date': created_at_local.strftime('%Y-%m-%d'),
                'time': created_at_local.strftime('%H:%M:%S'),
                'datetime': created_at_local.strftime('%Y-%m-%d %H:%M'),
            })

    except psycopg2.Error as e:
        flash(f"Error fetching history: {e.pgerror}", 'danger')
    finally:
        cursor.close()
        conn.close()

    return render_template('history.html', readings=formatted_readings)


# Create schedule
@app.route('/admin/schedules/create', methods=['GET', 'POST'])
def create_schedule():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    form = ScheduleForm()

    if form.validate_on_submit():
        conn = None
        try:
            # Convert local datetime to UTC
            local_dt = local_tz.localize(form.scheduled_date.data)
            utc_dt = local_dt.astimezone(pytz.utc)

            conn = get_db()
            cursor = conn.cursor()

            # Insert a single system-wide schedule with user_id as NULL
            cursor.execute("""
                INSERT INTO schedules
                (title, description, scheduled_date, user_id)
                VALUES (%s, %s, %s, %s)
            """, (
                form.title.data.strip(),
                form.description.data.strip(),
                utc_dt,
                None # Set user_id to NULL for a system-wide schedule
            ))

            conn.commit()
            flash('System-wide schedule created!', 'success')
            return redirect(url_for('admin_schedules'))

        except psycopg2.Error as e:
            conn.rollback()
            flash(f'Database error: {e.pgerror}', 'danger')
        finally:
            if conn:
                conn.close()

    return render_template('create_schedule.html', form=form)



# --- Admin: Post Announcement ---
@app.route('/admin/announce', methods=['GET', 'POST'])
def post_announcement():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        message = request.form['message']

        if not title or not message:
            flash('Title and Message are required for an announcement!', 'danger')
            return render_template('admin_announcements.html') # Render again to show error

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO announcements (title, message) VALUES (%s, %s)
            ''', (title, message))
            conn.commit() # Don't forget to commit
            flash('Announcement posted successfully!', 'success')
            return redirect(url_for('admin_dashboard')) # Redirect to admin dashboard after success
        except psycopg2.Error as e:
            conn.rollback() # Rollback on error
            flash(f'Error posting announcement: {e.pgerror}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('admin_announcements.html')

# --- Delete Announcement Route ---
@app.route('/delete-announcement/<int:announcement_id>', methods=['POST'])
def delete_announcement(announcement_id):
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('announcements'))

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM announcements WHERE id = %s", (announcement_id,))
            conn.commit()
            flash('Announcement deleted successfully', 'success')
    except psycopg2.Error as e:
        conn.rollback()
        flash(f'Delete failed: {e.pgerror}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('announcements'))


# Normal user
@app.route('/schedule') 
def user_schedules():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    schedules = []
    current_time_local = datetime.now(local_tz) # Get current time in local timezone

    try:
        # Get system-wide schedules (user_id IS NULL)     
        cursor.execute("""
            SELECT 
                s.id, s.title, s.description, s.scheduled_date, s.is_completed, s.user_id,
                CASE
                    WHEN s.user_id IS NULL THEN 'Admin' -- System-wide schedules by Admin
                    ELSE u.username -- User-specific schedules (if you ever add them)
                END AS creator_name
            FROM schedules s
            LEFT JOIN users u ON s.user_id = u.id -- Join to get username for user-specific schedules
            WHERE s.user_id IS NULL -- Only show system-wide schedules here
            ORDER BY s.scheduled_date DESC
        """)

        for row in cursor.fetchall():
            schedule = dict(row)

            # Convert to local timezone
            scheduled_date_utc = schedule['scheduled_date']
            if scheduled_date_utc.tzinfo is None:
                scheduled_date_utc = pytz.utc.localize(scheduled_date_utc) # Localize as UTC if naive
            schedule['scheduled_date'] = scheduled_date_utc.astimezone(local_tz)

            # Add is_past and is_completed logic for template
            schedule['is_past'] = schedule['scheduled_date'] < current_time_local and not schedule['is_completed']
            # The is_completed is already in DB, just ensure it's a boolean-like value if needed

            # Set creator name for template
            schedule['creator'] = schedule['creator_name'] if schedule['creator_name'] else 'Unknown'

            schedules.append(schedule)

    except psycopg2.Error as e:
        flash(f"Error fetching schedules: {e.pgerror}", 'danger')
    finally:
        cursor.close()
        conn.close()

    # Pass is_admin to the template
    return render_template('schedule.html',
                           schedules=schedules,
                           is_admin=session.get('is_admin', False),
                           now=current_time_local) # Pass current_time_local for comparison


# Route to mark a schedule as complete
@app.route('/admin/schedules/complete/<int:schedule_id>', methods=['POST'])
def complete_schedule(schedule_id):
    # Ensure only admins can access this route
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('admin_schedules')) # Redirect to admin schedules or dashboard

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE schedules SET is_completed = TRUE WHERE id = %s",
            (schedule_id,)
        )
        conn.commit()
        flash('Schedule marked as completed!', 'success')
    except psycopg2.Error as e:
        conn.rollback()
        flash(f'Error marking schedule complete: {e.pgerror}', 'danger')
    finally:
        cursor.close()
        conn.close()

    # Redirect back to the admin schedules page after the action
    return redirect(url_for('admin_schedules'))


# --- Logout ---
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



# --- Submit Meter Reading ---
@app.route('/submit', methods=['GET', 'POST'])
def submit_reading():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            reading = float(request.form['reading'])
        except ValueError:
            flash('Invalid reading format')
            return redirect(url_for('submit_reading'))

        with get_db() as cur:
            cur.execute("""
                INSERT INTO meter_readings (user_id, reading)
                VALUES (%s, %s)
            """, (session['user_id'], reading))

        flash('Reading submitted')
        return redirect(url_for('dashboard'))

    return render_template('submit.html')


# --- Schedule Entry ---
@app.route('/schedule', methods=['GET', 'POST'])
def schedule():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'GET':
        conn = get_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            # Get user's schedules
            cursor.execute("""
                SELECT id, title, scheduled_date 
                FROM schedules 
                WHERE user_id = %s 
                ORDER BY scheduled_date DESC
            """, (session['user_id'],))
            
            schedules = []
            for row in cursor.fetchall():
                schedule = dict(row)
                # Ensure datetime is timezone-aware
                if schedule['scheduled_date'].tzinfo is None:
                    schedule['scheduled_date'] = pytz.utc.localize(schedule['scheduled_date'])
                schedules.append(schedule)
                
        except psycopg2.Error as e:
            flash(f"Error fetching schedules: {e.pgerror}", 'danger')
        finally:
            cursor.close()
            conn.close()
            
        return render_template('schedule.html', schedules=schedules)
    
# Admin schedule
@app.route('/admin/schedules')
def admin_schedules():
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    schedules = []

    try:
        # Get only system-wide schedules (where user_id is NULL)
        cursor.execute("""
            SELECT id, title, description, scheduled_date
            FROM schedules
            WHERE user_id IS NULL
            ORDER BY scheduled_date DESC
        """)
        
        for row in cursor.fetchall():
            schedule = dict(row)
            # Convert to local timezone
            schedule['scheduled_date'] = schedule['scheduled_date'].astimezone(local_tz)
            schedules.append(schedule)

    except psycopg2.Error as e:
        flash(f'Database error: {e.pgerror}', 'danger')
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_schedules.html', schedules=schedules)   


# Delete schedule
@app.route('/admin/delete-schedule/<int:schedule_id>', methods=['POST'])
def delete_schedule(schedule_id):
    if not session.get('is_admin'):
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM schedules WHERE id = %s", (schedule_id,))
            flash('Schedule deleted successfully', 'success')
    except psycopg2.Error as e:
        flash(f'Delete failed: {e.pgerror}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_schedules'))


# --- Admin: View Users ---
@app.route('/admin/users')
def view_users():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute('SELECT id, username, email, unit_number, is_admin, created_at FROM users')
        users = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_users.html', users=users)


# Admin history route
@app.route('/admin/history', methods=['GET'])
def admin_history():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    all_readings = []

    month = request.args.get('month', type=int)
    year = request.args.get('year', type=int)
    unit_number = request.args.get('unit_number', type=str)  # New filter parameter

    try:
        query = """
            SELECT mr.id, mr.reading, mr.notes, mr.created_at,
                   u.username, u.unit_number
            FROM meter_readings mr
            JOIN users u ON mr.user_id = u.id
        """
        params = []
        where_clauses = []

        if month and year:
            start_of_month_local = datetime(year, month, 1, 0, 0, 0, tzinfo=local_tz)
            end_day = monthrange(year, month)[1]
            end_of_month_local = datetime(year, month, end_day, 23, 59, 59, tzinfo=local_tz)

            start_date_utc = start_of_month_local.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')
            end_date_utc = end_of_month_local.astimezone(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')

            where_clauses.append("mr.created_at BETWEEN %s AND %s")
            params.extend([start_date_utc, end_date_utc])

        if unit_number:
            where_clauses.append("u.unit_number = %s")
            params.append(unit_number)

        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        query += " ORDER BY CAST(u.unit_number AS INTEGER) ASC, mr.created_at DESC"

        cursor.execute(query, params)

        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]

        for row in rows:
            reading = dict(zip(columns, row))
            created_at_utc = reading['created_at']
            if isinstance(created_at_utc, str):
                created_at_utc = datetime.strptime(created_at_utc, '%Y-%m-%d %H:%M:%S%z')
            elif created_at_utc.tzinfo is None:
                created_at_utc = created_at_utc.replace(tzinfo=pytz.utc)

            created_at_local = created_at_utc.astimezone(local_tz)

            reading['formatted_date'] = created_at_local.strftime('%Y-%m-%d %H:%M')
            reading['date'] = created_at_local.strftime('%Y-%m-%d')
            reading['time'] = created_at_local.strftime('%H:%M:%S')
            all_readings.append(reading)

    except Exception as e:
        flash(f"Error fetching history: {e}", 'danger')
    finally:
        cursor.close()
        conn.close()

    return render_template('admin_history.html',
                           readings=all_readings,
                           selected_month=month,
                           selected_year=year,
                           selected_unit=unit_number)  # Pass the selected unit to template


# --- Admin: Unit Pincode Management ---
@app.route('/admin/unit-pincode', methods=['GET', 'POST'])
def unit_pincode():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    if request.method == 'POST':
        unit_number = request.form['unit_number'].strip()

        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute("SELECT id FROM users WHERE unit_number = %s", (unit_number,))
                if not cur.fetchone():
                    flash('Unit number does not exist!', 'danger')
                    return redirect(url_for('unit_pincode'))

            pin_code = ''.join(random.choices(string.digits, k=4))

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO unit_pincode (unit_number, pin_code)
                    VALUES (%s, %s)
                    ON CONFLICT (unit_number) DO UPDATE
                    SET pin_code = EXCLUDED.pin_code
                """, (unit_number, pin_code))
                conn.commit()
                flash('Pincode updated successfully', 'success')

        except Psycopg2Error as e:
            conn.rollback()
            flash(f'Database error: {e.pgerror}', 'danger')
        finally:
            conn.close()
        return redirect(url_for('unit_pincode'))

    # GET request handling with search
    search_query = request.args.get('search', '').strip()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            if search_query:
                cur.execute("""
                    SELECT up.id, up.unit_number, up.pin_code, up.created_at
                    FROM unit_pincode up
                    WHERE up.unit_number ILIKE %s
                    ORDER BY up.created_at DESC
                """, (f'%{search_query}%',))
            else:
                cur.execute("""
                    SELECT up.id, up.unit_number, up.pin_code, up.created_at
                    FROM unit_pincode up
                    ORDER BY up.created_at DESC
                """)

            pincodes = []
            for row in cur.fetchall():
                p = dict(row)
                if p['created_at'].tzinfo is None:
                    p['created_at'] = pytz.utc.localize(p['created_at'])
                p['created_at'] = p['created_at'].astimezone(local_tz)
                pincodes.append(p)

    except Psycopg2Error as e:
        flash(f'Database error: {e.pgerror}', 'danger')
        pincodes = []
    finally:
        conn.close()

    return render_template('unit_pincode.html',
                           pincodes=pincodes,
                           search_query=search_query,
                           is_admin=session.get('is_admin', False))

# Delete pin code
@app.route('/admin/delete-pincode/<unit_number>', methods=['POST', 'GET'])
def delete_pincode(unit_number):
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM unit_pincode WHERE unit_number = %s", (unit_number,))
            conn.commit()
            flash(f"Pincode for unit {unit_number} deleted successfully.", 'success')
    except Psycopg2Error as e:
        conn.rollback()
        flash(f"Database error: {e.pgerror}", 'danger')
    finally:
        conn.close()

    return redirect(url_for('unit_pincode'))


# Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            # System statistics
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM meter_readings")
            reading_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM unit_pincode")
            pincode_count = cursor.fetchone()[0]
            
            # Full user list
            cursor.execute("""
                SELECT id, username, unit_number, is_admin, created_at
                FROM users 
                ORDER BY created_at ASC
            """)
            all_users = cursor.fetchall()
            
            # Recent users
            cursor.execute("""
                SELECT username, unit_number 
                FROM users 
                ORDER BY created_at DESC 
                LIMIT 5
            """)
            recent_users = cursor.fetchall()
            
    except psycopg2.Error as e:
        flash(f'Database error: {e.pgerror}', 'danger')
    finally:
        conn.close()
    
    return render_template('admin_dashboard.html',
                         user_count=user_count,
                         reading_count=reading_count,
                         pincode_count=pincode_count,
                         recent_users=recent_users,
                         all_users=all_users)

# Export the data
@app.route('/admin/export')
def export_data():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    conn = get_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    try:
        cursor.execute("""
            SELECT u.unit_number, u.username, mr.reading, mr.notes, mr.created_at
            FROM meter_readings mr
            JOIN users u ON mr.user_id = u.id
            ORDER BY mr.created_at DESC
        """)
        
        # Generate CSV content
        csv_data = "Unit Number,Username,Reading,Notes,Date (UTC)\n"
        for row in cursor:
            # Properly escape quotes in notes
            notes = row['notes'].replace('"', '""') if row['notes'] else ''
            # Format datetime
            created_at = row['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            csv_data += f'"{row["unit_number"]}","{row["username"]}",{row["reading"]},"{notes}","{created_at}"\n'
        
        # Create response with CSV headers
        response = Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=meter_readings.csv"}
        )
        return response
        
    except psycopg2.Error as e:
        flash(f'Export failed: {e.pgerror}', 'danger')
        return redirect(url_for('admin_dashboard'))
    finally:
        cursor.close()
        conn.close()


# --- Initialize App ---
if __name__ == '__main__':
    #init_db()
    app.run(debug=True)