# admin_users.py - Users Management Admin Panel
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client
from dotenv import load_dotenv
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='admin_templates', static_folder='admin_static')
app.secret_key = os.environ.get('ADMIN_SECRET_KEY', 'admin-secret-key-change-in-production')

# Supabase configuration
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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
        # Get total users
        total_response = supabase.table('users').select('id', count='exact').execute()
        total_users = total_response.count
        
        # Get auto-detected location users
        auto_response = supabase.table('users').select('id', count='exact')\
            .like('location', '% | % | % | %').execute()
        auto_users = auto_response.count
        
        # Get today's users
        today = datetime.now().date().isoformat()
        today_response = supabase.table('users').select('id', count='exact')\
            .gte('created_at', f'{today}T00:00:00').execute()
        today_users = today_response.count
        
        # Get last 7 days users
        week_ago = (datetime.now().date() - timedelta(days=7)).isoformat()
        week_response = supabase.table('users').select('id', count='exact')\
            .gte('created_at', f'{week_ago}T00:00:00').execute()
        week_users = week_response.count
        
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
        
        # Start building the query
        query = supabase.table('users').select('*', count='exact')
        
        # Apply search filter
        if search:
            search_term = f"%{search}%"
            query = query.or_(f"full_name.ilike.{search_term},phone.ilike.{search_term},email.ilike.{search_term},location.ilike.{search_term}")
        
        # Apply location filter
        if location_filter == 'auto':
            query = query.like('location', '% | % | % | %')
        elif location_filter == 'manual':
            query = query.not_.like('location', '% | % | % | %')
        
        # Apply date filter
        if date_filter == 'today':
            today = datetime.now().date().isoformat()
            query = query.gte('created_at', f'{today}T00:00:00')
        elif date_filter == 'week':
            week_ago = (datetime.now().date() - timedelta(days=7)).isoformat()
            query = query.gte('created_at', f'{week_ago}T00:00:00')
        elif date_filter == 'month':
            month_ago = (datetime.now().date() - timedelta(days=30)).isoformat()
            query = query.gte('created_at', f'{month_ago}T00:00:00')
        
        # Get total count first
        count_response = query.execute()
        total = count_response.count
        
        # Apply pagination and ordering
        response = query.order('created_at', desc=True)\
            .range(offset, offset + per_page - 1)\
            .execute()
        
        users = response.data
        
        # Format user data
        for user in users:
            parsed_loc = parse_location_data(user.get('location', ''))
            user['parsed_location'] = parsed_loc
            user['is_auto_detected'] = parsed_loc['is_auto_detected']
            
            # Format dates
            created_at = user.get('created_at')
            if created_at:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                user['formatted_created'] = created_at.strftime('%d %b %Y, %I:%M %p')
                user['formatted_updated'] = created_at.strftime('%d %b %Y, %I:%M %p')
            else:
                user['formatted_created'] = 'N/A'
                user['formatted_updated'] = 'N/A'
            
            user['status'] = 'active'
        
        return jsonify({
            'success': True,
            'users': users,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'total_pages': (total + per_page - 1) // per_page if total > 0 else 1
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/api/users/<int:user_id>', methods=['GET'])
@admin_login_required
def get_user_details(user_id):
    """Get single user details"""
    try:
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        
        if not response.data:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user = response.data[0]
        parsed_loc = parse_location_data(user.get('location', ''))
        user['parsed_location'] = parsed_loc
        
        created_at = user.get('created_at')
        if created_at:
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
            user['formatted_created'] = created_at.strftime('%d %b %Y, %I:%M %p')
        
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
        
        # Check if user exists
        existing = supabase.table('users').select('id').eq('id', user_id).execute()
        if not existing.data:
            return jsonify({'success': False, 'error': 'User not found'})
        
        # Check email uniqueness
        if 'email' in data and data['email']:
            email_check = supabase.table('users').select('id')\
                .eq('email', data['email'])\
                .neq('id', user_id)\
                .execute()
            if email_check.data:
                return jsonify({'success': False, 'error': 'Email already registered to another user'})
        
        # Check phone uniqueness
        if 'phone' in data and data['phone']:
            phone_check = supabase.table('users').select('id')\
                .eq('phone', data['phone'])\
                .neq('id', user_id)\
                .execute()
            if phone_check.data:
                return jsonify({'success': False, 'error': 'Phone number already registered to another user'})
        
        # Prepare update data
        update_data = {}
        
        if 'full_name' in data:
            update_data['full_name'] = data['full_name']
        
        if 'email' in data:
            update_data['email'] = data['email']
        
        if 'phone' in data:
            update_data['phone'] = data['phone']
        
        if 'location' in data:
            update_data['location'] = data['location']
        
        if 'password' in data and data['password']:
            update_data['password'] = generate_password_hash(data['password'])
        
        if update_data:
            response = supabase.table('users').update(update_data).eq('id', user_id).execute()
            
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
        # Get user info before deletion
        user_response = supabase.table('users').select('full_name, email').eq('id', user_id).execute()
        
        if not user_response.data:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user = user_response.data[0]
        
        # Delete the user
        supabase.table('users').delete().eq('id', user_id).execute()
        
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
        response = supabase.table('users').select('id, full_name, phone, email, location, created_at')\
            .order('created_at', desc=True)\
            .execute()
        
        users = response.data
        
        csv_data = "ID,Full Name,Phone,Email,Address,Latitude,Longitude,Map Link,Registration Date\n"
        
        for user in users:
            parsed_loc = parse_location_data(user.get('location', ''))
            
            address = parsed_loc['address'].replace(',', ';')
            email = user.get('email', '').replace(',', ';')
            
            csv_data += f'{user["id"]},"{user.get("full_name", "")}","{user.get("phone", "")}","{email}","{address}",'
            csv_data += f'"{parsed_loc["latitude"]}","{parsed_loc["longitude"]}","{parsed_loc["map_link"]}",'
            
            created_at = user.get('created_at')
            if created_at:
                if isinstance(created_at, str):
                    created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                csv_data += f'"{created_at}"\n'
            else:
                csv_data += '""\n'
        
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
        response = supabase.table('users').select('id', count='exact').limit(1).execute()
        
        return jsonify({
            'status': 'healthy',
            'service': 'Users Admin Panel',
            'users_count': response.count if response.count else 0
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)