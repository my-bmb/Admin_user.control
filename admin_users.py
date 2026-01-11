# admin_users.py - Users Management Admin Panel
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='admin_templates', static_folder='admin_static')
app.secret_key = os.environ.get('ADMIN_SECRET_KEY', 'admin-secret-key-change-in-production')

def parse_location_data(location_string):
    """
    Parse location string in format: "Address | Latitude | Longitude | MapLink"
    Returns: Dictionary with all components
    """
    if not location_string:
        return {
            'address': '',
            'latitude': None,
            'longitude': None,
            'map_link': None,
            'is_auto_detected': False
        }
    
    if ' | ' in location_string:
        parts = location_string.split(' | ')
        if len(parts) >= 4:
            try:
                return {
                    'address': parts[0],
                    'latitude': float(parts[1]) if parts[1] else None,
                    'longitude': float(parts[2]) if parts[2] else None,
                    'map_link': parts[3],
                    'is_auto_detected': True,
                    'full_string': location_string
                }
            except ValueError:
                pass
    
    return {
        'address': location_string,
        'latitude': None,
        'longitude': None,
        'map_link': None,
        'is_auto_detected': False,
        'full_string': location_string
    }

def get_db_connection():
    """Establish database connection"""
    database_url = os.environ.get('DATABASE_URL')
    
    if not database_url:
        raise ValueError("DATABASE_URL environment variable is not set")
    
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    
    try:
        conn = psycopg.connect(database_url, row_factory=dict_row)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

# Admin credentials
ADMIN_CREDENTIALS = {
    'username': os.environ.get('ADMIN_USERNAME', 'admin'),
    'password': os.environ.get('ADMIN_PASSWORD', 'admin123')
}

# Login required decorator
def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash('Please login to access admin panel', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def root():
    """Root URL - Redirect to admin login page"""
    return redirect(url_for('admin_login'))

@app.route('/login')
def public_login():
    """Alternative login route"""
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_CREDENTIALS['username'] and password == ADMIN_CREDENTIALS['password']:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/')
@admin_login_required
def admin_dashboard():
    """Admin dashboard - Users management"""
    return render_template('dashboard.html')

@app.route('/admin/api/users/stats')
@admin_login_required
def get_users_stats():
    """Get users statistics"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as total_users FROM users")
                total_users = cur.fetchone()['total_users']
                
                cur.execute("SELECT COUNT(*) as auto_users FROM users WHERE location LIKE '% | % | % | %'")
                auto_users = cur.fetchone()['auto_users']
                
                today = datetime.now().date()
                cur.execute("SELECT COUNT(*) as today_users FROM users WHERE DATE(created_at) = %s", (today,))
                today_users = cur.fetchone()['today_users']
                
                week_ago = today - timedelta(days=7)
                cur.execute("SELECT COUNT(*) as week_users FROM users WHERE DATE(created_at) >= %s", (week_ago,))
                week_users = cur.fetchone()['week_users']
                
                active_users = total_users
                blocked_users = 0
                
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'auto_users': auto_users,
                'today_users': today_users,
                'week_users': week_users,
                'active_users': active_users,
                'blocked_users': blocked_users
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/users')
@admin_login_required
def get_users():
    """Get all users with filtering and pagination"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))
        search = request.args.get('search', '')
        location_filter = request.args.get('location_filter', 'all')
        date_filter = request.args.get('date_filter', 'all')
        
        offset = (page - 1) * per_page
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                conditions = []
                params = []
                
                if search:
                    conditions.append("(full_name ILIKE %s OR phone ILIKE %s OR email ILIKE %s OR location ILIKE %s)")
                    search_term = f"%{search}%"
                    params.extend([search_term, search_term, search_term, search_term])
                
                if location_filter == 'auto':
                    conditions.append("location LIKE '% | % | % | %'")
                elif location_filter == 'manual':
                    conditions.append("location NOT LIKE '% | % | % | %'")
                
                if date_filter != 'all':
                    if date_filter == 'today':
                        conditions.append("DATE(created_at) = CURRENT_DATE")
                    elif date_filter == 'week':
                        conditions.append("created_at >= CURRENT_DATE - INTERVAL '7 days'")
                    elif date_filter == 'month':
                        conditions.append("created_at >= CURRENT_DATE - INTERVAL '30 days'")
                
                where_clause = " AND ".join(conditions) if conditions else "1=1"
                
                count_query = f"SELECT COUNT(*) as total FROM users WHERE {where_clause}"
                cur.execute(count_query, params)
                total = cur.fetchone()['total']
                
                # ✅ CORRECTED: No # comments in PostgreSQL SQL
                query = f"""
                    SELECT id, profile_pic, full_name, phone, email, location, 
                           created_at, 
                           created_at AS last_updated -- Using created_at as last_updated
                    FROM users 
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([per_page, offset])
                cur.execute(query, params)
                users = cur.fetchall()
                
                for user in users:
                    parsed_loc = parse_location_data(user['location'])
                    user['parsed_location'] = parsed_loc
                    user['is_auto_detected'] = parsed_loc['is_auto_detected']
                    user['formatted_created'] = user['created_at'].strftime('%d %b %Y, %I:%M %p')
                    user['formatted_updated'] = user['last_updated'].strftime('%d %b %Y, %I:%M %p')
                    user['status'] = 'active'
                
        return jsonify({
            'success': True,
            'users': users,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': (total + per_page - 1) // per_page
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/users/<int:user_id>', methods=['GET'])
@admin_login_required
def get_user_details(user_id):
    """Get single user details"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, profile_pic, full_name, phone, email, location, 
                           password, created_at
                    FROM users WHERE id = %s
                """, (user_id,))
                user = cur.fetchone()
                
                if not user:
                    return jsonify({'success': False, 'error': 'User not found'})
                
                parsed_loc = parse_location_data(user['location'])
                user['parsed_location'] = parsed_loc
                user['formatted_created'] = user['created_at'].strftime('%d %b %Y, %I:%M %p')
                user['status'] = 'active'
                
        return jsonify({'success': True, 'user': user})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/users/<int:user_id>', methods=['PUT'])
@admin_login_required
def update_user(user_id):
    """Update user details"""
    try:
        data = request.get_json()
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
                if not cur.fetchone():
                    return jsonify({'success': False, 'error': 'User not found'})
                
                if 'email' in data:
                    cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (data['email'], user_id))
                    if cur.fetchone():
                        return jsonify({'success': False, 'error': 'Email already registered to another user'})
                
                if 'phone' in data:
                    cur.execute("SELECT id FROM users WHERE phone = %s AND id != %s", (data['phone'], user_id))
                    if cur.fetchone():
                        return jsonify({'success': False, 'error': 'Phone number already registered to another user'})
                
                update_fields = []
                update_values = []
                
                if 'full_name' in data:
                    update_fields.append("full_name = %s")
                    update_values.append(data['full_name'])
                
                if 'email' in data:
                    update_fields.append("email = %s")
                    update_values.append(data['email'])
                
                if 'phone' in data:
                    update_fields.append("phone = %s")
                    update_values.append(data['phone'])
                
                if 'location' in data:
                    update_fields.append("location = %s")
                    update_values.append(data['location'])
                
                if 'password' in data and data['password']:
                    hashed_password = generate_password_hash(data['password'])
                    update_fields.append("password = %s")
                    update_values.append(hashed_password)
                
                if update_fields:
                    update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
                    update_values.append(user_id)
                    
                    cur.execute(update_query, update_values)
                    conn.commit()
                    
                    return jsonify({
                        'success': True, 
                        'message': 'User updated successfully'
                    })
                else:
                    return jsonify({
                        'success': False, 
                        'error': 'No fields to update'
                    })
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/users/<int:user_id>/status', methods=['PUT'])
@admin_login_required
def update_user_status(user_id):
    """Update user status - DISABLED"""
    return jsonify({
        'success': False, 
        'error': 'Status feature is not available. Status column does not exist in database.'
    })

@app.route('/admin/api/users/<int:user_id>', methods=['DELETE'])
@admin_login_required
def delete_user(user_id):
    """Delete user"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT full_name, email FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()
                
                if not user:
                    return jsonify({'success': False, 'error': 'User not found'})
                
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                conn.commit()
                
                return jsonify({
                    'success': True, 
                    'message': f'User {user["full_name"]} deleted successfully'
                })
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/users/export')
@admin_login_required
def export_users():
    """Export users data to CSV"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, full_name, phone, email, location, created_at
                    FROM users 
                    ORDER BY created_at DESC
                """)
                users = cur.fetchall()
                
                csv_data = "ID,Full Name,Phone,Email,Address,Latitude,Longitude,Map Link,Registration Date\n"
                
                for user in users:
                    parsed_loc = parse_location_data(user['location'])
                    
                    address = parsed_loc['address'].replace(',', ';')
                    email = user['email'].replace(',', ';')
                    
                    csv_data += f'{user["id"]},"{user["full_name"]}","{user["phone"]}","{email}","{address}",'
                    csv_data += f'"{parsed_loc["latitude"]}","{parsed_loc["longitude"]}","{parsed_loc["map_link"]}",'
                    csv_data += f'"{user["created_at"]}"\n'
                
                return jsonify({
                    'success': True,
                    'csv_data': csv_data,
                    'filename': f'users_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                })
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/health')
def admin_health():
    """Health check endpoint"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as user_count FROM users")
                count = cur.fetchone()['user_count']
                
        return jsonify({
            'status': 'healthy', 
            'service': 'Users Admin Panel',
            'users_count': count
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
