import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime
import uuid
import traceback
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

load_dotenv()
app = Flask(__name__)

# Allows your frontend (port 5500) to communicate with this server (port 5000)
CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500", "http://127.0.0.1:3000"]}})

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

# Validate that credentials are loaded
if not url or not key:
    raise ValueError("SUPABASE_URL and SUPABASE_KEY environment variables are required!")

try:
    supabase: Client = create_client(url, key)
    logger.info("Supabase client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/auth/admin/login', methods=['POST'])
def admin_login():
    """Admin/Manager login with access code"""
    data = request.json
    
    if data.get("accessCode") != "12345678":
        return jsonify({"message": "Invalid Approval Code"}), 403
    
    try:
        res = supabase.auth.sign_in_with_password({
            "email": data.get("email"),
            "password": data.get("password")
        })
        
        return jsonify({
            "token": res.session.access_token,
            "user": {
                "id": res.user.id,
                "email": res.user.email,
                "role": "admin"
            }
        }), 200
    except Exception as e:
        logger.error(f"Admin login error: {str(e)}")
        return jsonify({"message": str(e)}), 401


@app.route('/api/auth/employee/login', methods=['POST'])
def employee_login():
    """Employee login without access code"""
    data = request.json
    
    try:
        res = supabase.auth.sign_in_with_password({
            "email": data.get("email"),
            "password": data.get("password")
        })
        
        return jsonify({
            "token": res.session.access_token,
            "user": {
                "id": res.user.id,
                "email": res.user.email,
                "role": "employee"
            }
        }), 200
    except Exception as e:
        logger.error(f"Employee login error: {str(e)}")
        return jsonify({"message": str(e)}), 401


# ==================== LEAVE REQUEST ENDPOINTS ====================

@app.route('/api/leave/apply', methods=['POST'])
def apply_leave():
    """Employee applies for leave"""
    try:
        data = request.json
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({"message": "Unauthorized - Missing token"}), 401
        
        logger.info(f"Processing leave application from user: {data.get('user_id')}")
        
        # Validate required fields
        required_fields = ['user_id', 'leave_type', 'start_date', 'end_date', 'reason']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({"message": f"Missing required fields: {', '.join(missing_fields)}"}), 400
        
        # Prepare leave request data
        leave_data = {
            "id": str(uuid.uuid4()),
            "user_id": data.get("user_id"),
            "employee_name": data.get("employee_name", ""),
            "department": data.get("department", "Not Specified"),
            "leave_type": data.get("leave_type"),
            "start_date": data.get("start_date"),
            "end_date": data.get("end_date"),
            "reason": data.get("reason"),
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        logger.info(f"Leave data prepared: {leave_data}")
        
        # Insert into Supabase
        result = supabase.table('leave_requests').insert(leave_data).execute()
        
        logger.info(f"Leave request inserted successfully: {result}")
        
        return jsonify({
            "message": "Leave application submitted successfully",
            "data": leave_data,
            "id": leave_data["id"]
        }), 201
        
    except Exception as e:
        logger.error(f"Error applying leave: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "message": f"Failed to submit application: {str(e)}",
            "error": str(e)
        }), 500


@app.route('/api/leave/requests', methods=['GET'])
def get_all_leave_requests():
    """Admin: Get all leave requests"""
    try:
        result = supabase.table('leave_requests').select("*").execute()
        logger.info(f"Retrieved {len(result.data)} leave requests")
        return jsonify({"data": result.data}), 200
    except Exception as e:
        logger.error(f"Error fetching leave requests: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/my-requests', methods=['GET'])
def get_employee_leave_requests():
    """Employee: Get their own leave requests"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({"message": "user_id parameter is required"}), 400
        
        logger.info(f"Fetching leave requests for user: {user_id}")
        
        result = supabase.table('leave_requests').select("*").eq("user_id", user_id).execute()
        
        logger.info(f"Retrieved {len(result.data)} leave requests for user {user_id}")
        
        return jsonify({"data": result.data}), 200
    except Exception as e:
        logger.error(f"Error fetching employee leave requests: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/approve/<request_id>', methods=['POST'])
def approve_leave_request(request_id):
    """Admin: Approve a leave request"""
    try:
        logger.info(f"Approving leave request: {request_id}")
        
        result = supabase.table('leave_requests').update({
            "status": "approved",
            "approved_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }).eq("id", request_id).execute()
        
        if not result.data:
            return jsonify({"message": "Leave request not found"}), 404
        
        logger.info(f"Leave request approved: {request_id}")
        
        return jsonify({
            "message": "Leave request approved",
            "data": result.data
        }), 200
    except Exception as e:
        logger.error(f"Error approving leave request: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/leave/decline/<request_id>', methods=['POST'])
def decline_leave_request(request_id):
    """Admin: Decline a leave request"""
    try:
        data = request.json or {}
        
        logger.info(f"Declining leave request: {request_id}")
        
        result = supabase.table('leave_requests').update({
            "status": "declined",
            "decline_reason": data.get("reason", ""),
            "declined_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }).eq("id", request_id).execute()
        
        if not result.data:
            return jsonify({"message": "Leave request not found"}), 404
        
        logger.info(f"Leave request declined: {request_id}")
        
        return jsonify({
            "message": "Leave request declined",
            "data": result.data
        }), 200
    except Exception as e:
        logger.error(f"Error declining leave request: {str(e)}")
        return jsonify({"message": str(e)}), 500


# ==================== SETTINGS ENDPOINTS ====================

@app.route('/api/settings/profile', methods=['GET'])
def get_profile_settings():
    """Get user profile settings"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({"message": "user_id parameter is required"}), 400
        
        result = supabase.table('user_settings').select("*").eq("user_id", user_id).execute()
        
        if result.data:
            return jsonify({"data": result.data[0]}), 200
        return jsonify({"data": None}), 200
    except Exception as e:
        logger.error(f"Error fetching profile settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/settings/profile', methods=['PUT'])
def update_profile_settings():
    """Update user profile settings"""
    try:
        data = request.json
        user_id = data.get("user_id")
        
        if not user_id:
            return jsonify({"message": "user_id is required"}), 400
        
        settings_data = {
            "user_id": user_id,
            "full_name": data.get("full_name", ""),
            "phone": data.get("phone", ""),
            "department": data.get("department", ""),
            "profile_picture": data.get("profile_picture", ""),
            "updated_at": datetime.now().isoformat()
        }
        
        # Try to update first, if no rows affected, insert new
        result = supabase.table('user_settings').update(settings_data).eq("user_id", user_id).execute()
        
        if not result.data:
            # If update didn't work, insert instead
            result = supabase.table('user_settings').insert(settings_data).execute()
        
        return jsonify({
            "message": "Settings updated successfully",
            "data": settings_data
        }), 200
    except Exception as e:
        logger.error(f"Error updating profile settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/settings/notifications', methods=['GET'])
def get_notification_settings():
    """Get notification preferences"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({"message": "user_id parameter is required"}), 400
        
        result = supabase.table('notification_settings').select("*").eq("user_id", user_id).execute()
        
        if result.data:
            return jsonify({"data": result.data[0]}), 200
        return jsonify({"data": None}), 200
    except Exception as e:
        logger.error(f"Error fetching notification settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


@app.route('/api/settings/notifications', methods=['PUT'])
def update_notification_settings():
    """Update notification preferences"""
    try:
        data = request.json
        user_id = data.get("user_id")
        
        if not user_id:
            return jsonify({"message": "user_id is required"}), 400
        
        settings_data = {
            "user_id": user_id,
            "email_notifications": data.get("email_notifications", True),
            "sms_notifications": data.get("sms_notifications", False),
            "in_app_notifications": data.get("in_app_notifications", True),
            "updated_at": datetime.now().isoformat()
        }
        
        result = supabase.table('notification_settings').update(settings_data).eq("user_id", user_id).execute()
        
        if not result.data:
            result = supabase.table('notification_settings').insert(settings_data).execute()
        
        return jsonify({
            "message": "Notification settings updated",
            "data": settings_data
        }), 200
    except Exception as e:
        logger.error(f"Error updating notification settings: {str(e)}")
        return jsonify({"message": str(e)}), 500


# ==================== DASHBOARD STATS ENDPOINTS ====================

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        all_requests = supabase.table('leave_requests').select("*").execute()
        data = all_requests.data
        
        stats = {
            "total_pending": len([r for r in data if r.get('status') == 'pending']),
            "total_approved": len([r for r in data if r.get('status') == 'approved']),
            "total_declined": len([r for r in data if r.get('status') == 'declined']),
            "on_leave_today": 0
        }
        
        return jsonify({"data": stats}), 200
    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {str(e)}")
        return jsonify({"message": str(e)}), 500


# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test Supabase connection
        supabase.table('leave_requests').select("id").limit(1).execute()
        return jsonify({
            "status": "healthy",
            "supabase": "connected"
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"message": "Internal server error"}), 500


if __name__ == '__main__':
    print("=" * 50)
    print("LeaveFlow Backend Server Starting")
    print("=" * 50)
    print(f"Supabase URL: {url[:50]}...")
    print("Running on http://127.0.0.1:5000")
    print("=" * 50)
    app.run(port=5000, debug=True)