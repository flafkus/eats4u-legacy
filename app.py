import os
from flask import Flask, request, jsonify, render_template, redirect, send_from_directory, session
import stripe
from dotenv import load_dotenv
import uuid
from datetime import datetime, timedelta
import requests
import json
import base64
import traceback
import hmac
from collections import defaultdict
import hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import random
import pymongo
from pymongo import MongoClient
import re

load_dotenv()

app = Flask(__name__, static_folder='static')

csrf = CSRFProtect()
csrf.init_app(app)

mongo_uri = os.environ.get('MONGODB_URI')
client = MongoClient(mongo_uri, maxPoolSize=10, minPoolSize=1)
db = client.get_database("eats4u")


limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=mongo_uri,  # Use MongoDB for persistent rate limiting
    strategy="fixed-window",  # Choose an appropriate strategy
    default_limits=["200 per day", "50 per hour"],  # Global default limit
    headers_enabled=True,  # Enable RateLimit headers in response
)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

app.secret_key = os.environ.get('FLASK_SECRET_KEY')

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

nowpayments_api_key = os.environ.get('NOWPAYMENTS_API_KEY')
nowpayments_api_url = os.environ.get('NOWPAYMENTS_API_URL')
nowpayments_ipn_secret = os.environ.get('NOWPAYMENTS_IPN_SECRET')

paypal_client_id = os.environ.get('PAYPAL_CLIENT_ID')
paypal_client_secret = os.environ.get('PAYPAL_CLIENT_SECRET')
paypal_api_url = os.environ.get('PAYPAL_API_URL', 'https://api-m.sandbox.paypal.com')

resend_api_key = os.environ.get('RESEND_API_KEY')
from_email = os.environ.get('FROM_EMAIL', 'noreply@orders.eats4u.org')

stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
stripe_webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/faq')
def faq():
    """Render the FAQ page"""
    return render_template('faq.html')

@app.route('/payment-failed')
def payment_failed():
    return send_from_directory('.', 'payment-failed.html')

@app.route('/products/<product_id>')
def product_page(product_id):
    """Render a product page"""
    product_file = f"{product_id}.html"
    if os.path.exists(os.path.join('products', product_file)):
        return send_from_directory('products', product_file)
    return app.send_static_file('404.html'), 404

@app.route('/product-<product_id>')
def redirect_product(product_id):
    """Redirect /product-XX to /products/product-XX"""
    return redirect(f"/products/product-{product_id}")

#temp redirect from old site
@app.route('/product/just-eat-10-off-15')
def redirect_product_old():
    return redirect(f"/products/product-15")

@app.route('/<path:path>')
def serve_files(path):
    print(f"Requested path: {path}")
    
    if os.path.isfile(path):
        print(f"Serving file from root: {path}")
        return send_from_directory('.', path)
    
    if os.path.isfile(f"{path}.html"):
        print(f"Serving file from root with .html: {path}.html")
        return send_from_directory('.', f"{path}.html")
    
    if os.path.isfile(os.path.join('static', path)):
        print(f"Serving file from static: {path}")
        return send_from_directory('static', path)
    
    print(f"File not found: {path}")
    return app.send_static_file('404.html'), 404

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://www.paypal.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

def setup_mongodb_indexes():
    # Indexes for codes collection
    db.codes.create_index([("product_id", 1), ("used", 1)])
    db.codes.create_index([("product_id", 1), ("code", 1)], unique=True)
    
    # Indexes for orders collection
    db.orders.create_index("order_id", unique=True)
    db.orders.create_index("timestamp")
    db.orders.create_index("payment_id")
    db.orders.create_index([("product_id", 1), ("timestamp", 1)])
    db.orders.create_index([("payment_method", 1)])
    db.orders.create_index("promo_code")
    db.orders.create_index("total_price")
    
    # Index for processed orders
    db.processed_orders.create_index("order_id", unique=True)
    
    # Index for temp orders
    db.temp_orders.create_index("order_id", unique=True)
    db.temp_orders.create_index("timestamp")
    
    # Index for promo codes
    db.promo_codes.create_index("code", unique=True)
    db.promo_codes.create_index("valid_until")
    
    # Indexes for webhook logs and error logs
    db.webhook_logs.create_index("timestamp")
    db.webhook_logs.create_index("type")
    db.error_logs.create_index("timestamp")
    db.error_logs.create_index("type")
    db.logs.create_index("timestamp")
    db.logs.create_index("type")
    db.api_logs.create_index("timestamp")
    db.unsent_codes.create_index("timestamp")
    db.email_backups.create_index("timestamp")

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors gracefully"""
    return jsonify({
        "error": "Rate limit exceeded",
        "message": str(e.description),
        "retry_after": e.retry_after
    }), 429

# Add a route to explicitly serve static files if needed
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/api/stock/<product_id>', methods=['GET'])
@limiter.limit("30 per minute; 300 per hour")
def get_stock(product_id):
    """Simple API endpoint to get stock information for a product"""
    
    # Clean up product ID if needed
    if '/' in product_id:
        parts = product_id.split('/')
        product_id = parts[-1]
        
    if product_id.endswith('.html'):
        product_id = product_id.replace('.html', '')
        
    if product_id.isdigit() or not product_id.startswith('product-'):
        product_id = f"product-{product_id}"
    
    # Get product codes to determine stock level
    available_codes = get_product_codes(product_id)
    stock_count = len(available_codes)
    
    # Determine status based on stock count
    status = "In Stock"
    if stock_count <= 0:
        status = "Out of Stock"
    elif stock_count < 10:
        status = "Limited Stock"
    
    # Return simple stock data
    return jsonify({
        #"stock": stock_count,
        "status": status
    })

def is_order_processed(order_id):
    """Check if an order has been processed by checking MongoDB"""
    try:
        # Look for the order ID in the processed orders collection
        result = db.processed_orders.find_one({"order_id": order_id})
        
        # Return True if the order is found, False otherwise
        return result is not None
    except Exception as e:
        print(f"Error checking if order is processed: {str(e)}")
        traceback.print_exc()
        return False

def mark_order_processed(order_id):
    """Mark an order as processed in MongoDB"""
    try:
        # Insert a document into the processed_orders collection
        db.processed_orders.insert_one({
            "order_id": order_id,
            "processed_at": datetime.now()
        })
        print(f"Marked order {order_id} as processed")
        return True
    except Exception as e:
        print(f"Error marking order as processed: {str(e)}")
        traceback.print_exc()
        return False

def check_nowpayments_status(payment_id):
    """Check the status of a NowPayments payment"""
    try:
        headers = {
            'x-api-key': nowpayments_api_key,
            'Content-Type': 'application/json',
        }
        
        response = requests.get(
            f"{nowpayments_api_url}/v1/payment/{payment_id}",
            headers=headers
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"NowPayments status check error: {response.text}")
            return None
    except Exception as e:
        print(f"Error checking NowPayments status: {str(e)}")
        return None
    
@app.route('/gooner/dashboard')
def admin_dashboard():
    """Admin dashboard for data visualization using MongoDB"""
    if not session.get('logged_in'):
        return redirect('/gooner/login')
    
    # Get filter parameters
    start_date_str = request.args.get('start')
    end_date_str = request.args.get('end')
    product_filter = request.args.get('product', 'all')
    
    # Set default date range (last 30 days) if not specified
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    # Parse dates if provided
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        except ValueError:
            pass
    
    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            # Set to end of day
            end_date = end_date.replace(hour=23, minute=59, second=59)
        except ValueError:
            pass
    
    # Format dates for the template
    start_date_str = start_date.strftime('%Y-%m-%d')
    end_date_str = end_date.strftime('%Y-%m-%d')
    
    # Load orders data from MongoDB
    orders_data = load_orders_data()
    
    # Filter orders by date range and product if needed
    filtered_orders = []
    for order in orders_data:
        # Parse order timestamp
        try:
            order_timestamp = order.get('timestamp')
            if isinstance(order_timestamp, str):
                order_date = datetime.fromisoformat(order_timestamp)
            else:
                # Handle if timestamp is already a datetime object
                order_date = order_timestamp
        except (ValueError, TypeError):
            # Skip orders with invalid timestamps
            continue
        
        # Check if order is within date range
        if start_date <= order_date <= end_date:
            # Filter by product if specified
            if product_filter != 'all' and order.get('product_id') != product_filter:
                continue
            
            filtered_orders.append(order)
    
    # Calculate total revenue metrics
    total_revenue, total_orders, total_codes = calculate_totals(orders_data)
    period_revenue, period_orders, period_codes = calculate_totals(filtered_orders)
    
    # Generate chart data
    chart_data = generate_chart_data(filtered_orders, start_date, end_date)
    
    # Get recent orders (latest 20)
    recent_orders = sorted(
        filtered_orders, 
        key=lambda x: datetime.fromisoformat(x['timestamp']) if isinstance(x.get('timestamp'), str) else x.get('timestamp', datetime.min), 
        reverse=True
    )[:20]
    
    # Load products for the filter dropdown
    products = load_products()
    
    payment_stats = calculate_payment_stats(orders_data)
    
    # Render the dashboard template
    return render_template(
        'admin_dashboard.html',
        start_date=start_date_str,
        end_date=end_date_str,
        total_revenue=format(total_revenue / 100, '.2f'),  # Convert from pennies to pounds
        total_orders=total_orders,
        total_codes=total_codes,
        period_revenue=format(period_revenue / 100, '.2f'),  # Convert from pennies to pounds
        period_orders=period_orders,
        period_codes=period_codes,
        recent_orders=recent_orders,
        products=products,
        chart_data=chart_data,
        payment_stats=payment_stats
    )

def load_orders_data():
    """Load orders data from MongoDB with complete details"""
    orders = []
    
    try:
        # Find all orders and sort by timestamp (newest first)
        cursor = db.orders.find().sort('timestamp', -1)
        
        for order in cursor:
            # Convert MongoDB's _id to string and remove it to avoid serialization issues
            order_dict = {k: v for k, v in order.items() if k != '_id'}
            
            # Calculate price if available fields exist
            if 'payment_method' in order_dict and 'price' not in order_dict:
                if order_dict['payment_method'] == 'stripe':
                    order_dict['price'] = 200  # Default price in pence for Stripe
                elif order_dict['payment_method'] == 'paypal':
                    order_dict['price'] = 200  # Default price in pence for PayPal
                elif order_dict['payment_method'] == 'nowpayments':
                    order_dict['price'] = 260  # Default price in cents for crypto
                else:
                    order_dict['price'] = 200  # Default fallback price
            
            # Convert quantity to int if present
            if 'quantity' in order_dict:
                try:
                    order_dict['quantity'] = int(order_dict['quantity'])
                except (ValueError, TypeError):
                    order_dict['quantity'] = 1
            else:
                order_dict['quantity'] = 1
            
            # Calculate total price - PRIORITY ORDER:
            # 1. Use stored total_price if available
            # 2. Calculate from price (which might be discounted) and quantity
            # 3. Calculate from original price minus discount
            # 4. Default to price * quantity
            if 'total_price' in order_dict:
                # Use the stored total price directly
                order_dict['display_price'] = order_dict['total_price'] / 100  # Convert to pounds for display
            elif 'price' in order_dict and 'discount_amount' in order_dict and 'original_price' in order_dict:
                # This is a discounted order, show the discounted price
                order_dict['display_price'] = order_dict['price'] / 100  # Convert to pounds for display
            elif 'price' in order_dict:
                # Regular price without discount
                order_dict['display_price'] = order_dict['price'] / 100  # Convert to pounds for display
            
            # Format the timestamp for display if needed
            if 'timestamp' in order_dict and isinstance(order_dict['timestamp'], str):
                try:
                    # Parse the ISO timestamp and reformat to a more readable format
                    dt = datetime.fromisoformat(order_dict['timestamp'])
                    order_dict['formatted_date'] = dt.strftime('%b %d, %Y %H:%M')
                except:
                    order_dict['formatted_date'] = order_dict['timestamp']
            
            orders.append(order_dict)
            
        return orders
    except Exception as e:
        print(f"Error loading orders data: {str(e)}")
        traceback.print_exc()
        return []

def save_temp_order(order_id, order_data):
    """Save temporary order data to MongoDB"""
    try:
        # Add a timestamp if not present
        if 'timestamp' not in order_data:
            order_data['timestamp'] = datetime.now().isoformat()
            
        # Add order_id to the data if not already there
        order_data['order_id'] = order_id
        
        # Use upsert to update if exists or insert if not
        result = db.temp_orders.update_one(
            {"order_id": order_id}, 
            {"$set": order_data},
            upsert=True
        )
        
        print(f"Temporary order saved for {order_id}")
        return True
    except Exception as e:
        print(f"Error saving temporary order: {str(e)}")
        traceback.print_exc()
        return False

def get_temp_order(order_id):
    """Get temporary order data from MongoDB"""
    try:
        temp_order = db.temp_orders.find_one({"order_id": order_id})
        
        if temp_order:
            # Remove the MongoDB _id field
            if '_id' in temp_order:
                del temp_order['_id']
            return temp_order
        
        print(f"Temp order not found for {order_id}")
        return None
    except Exception as e:
        print(f"Error getting temporary order: {str(e)}")
        traceback.print_exc()
        return None
    
def delete_temp_order(order_id):
    """Delete temporary order data from MongoDB"""
    try:
        result = db.temp_orders.delete_one({"order_id": order_id})
        
        if result.deleted_count > 0:
            print(f"Temporary order deleted for {order_id}")
            return True
        
        print(f"No temporary order found to delete for {order_id}")
        return False
    except Exception as e:
        print(f"Error deleting temporary order: {str(e)}")
        traceback.print_exc()
        return False

def calculate_totals(orders):
    """Calculate total revenue, orders, and codes sold with proper handling of discounts"""
    total_revenue = 0
    total_orders = len(orders)
    total_codes = 0
    
    for order in orders:
        # Add order total to revenue - prioritize total_price if available
        if 'total_price' in order:
            total_revenue += order.get('total_price', 0)
        else:
            # Calculate from price and quantity as fallback
            price = order.get('price', 200)  # Default to 200 pence if not specified
            quantity = order.get('quantity', 1)
            total_revenue += price * quantity
        
        # Add quantity to total codes
        total_codes += order.get('quantity', 1)
    
    return total_revenue, total_orders, total_codes

def generate_chart_data(orders, start_date, end_date):
    """Generate data for the dashboard charts using MongoDB data"""
    # Initialize data structures
    chart_data = {
        'daily_revenue': {'labels': [], 'data': []},
        'daily_orders': {'labels': [], 'data': []},
        'product_breakdown': {'labels': [], 'data': [], 'quantities': [], 'revenue': []},
        'payment_methods': {'labels': [], 'data': []},
        'product_trends': {'labels': [], 'datasets': []},
        'payment_trends': {'labels': [], 'datasets': []}
    }
    
    # Generate date range for daily charts
    date_range = []
    current_date = start_date
    while current_date <= end_date:
        date_range.append(current_date)
        current_date += timedelta(days=1)
    
    # Format date labels for charts
    date_labels = [date.strftime('%Y-%m-%d') for date in date_range]
    chart_data['daily_revenue']['labels'] = date_labels
    chart_data['daily_orders']['labels'] = date_labels
    chart_data['product_trends']['labels'] = date_labels
    chart_data['payment_trends']['labels'] = date_labels
    
    # Initialize daily data with zeros
    daily_revenue = [0] * len(date_range)
    daily_orders = [0] * len(date_range)
    
    # Track product and payment method data
    product_data = defaultdict(lambda: {'count': 0, 'revenue': 0, 'daily_counts': [0] * len(date_range)})
    payment_data = defaultdict(lambda: {'count': 0, 'daily_counts': [0] * len(date_range)})
    
    # Process orders
    for order in orders:
        # Skip orders without timestamp
        order_timestamp = order.get('timestamp')
        if not order_timestamp:
            continue
            
        # Parse order date
        try:
            if isinstance(order_timestamp, str):
                order_date = datetime.fromisoformat(order_timestamp)
            else:
                # Handle if timestamp is already a datetime object
                order_date = order_timestamp
        except (ValueError, TypeError):
            continue
        
        # Find day index in date range
        day_index = (order_date.date() - start_date.date()).days
        if 0 <= day_index < len(date_range):
            # Add to daily revenue
            daily_revenue[day_index] += order.get('total_price', 0)
            
            # Add to daily orders
            daily_orders[day_index] += 1
            
            # Normalize product name by removing quantity information (e.g., "(x2)")
            product_name = order.get('product_name', 'Unknown')
            normalized_product_name = re.sub(r'\s*\(\s*x\d+\s*\)\s*$', '', product_name)
            
            # Add to product data using normalized name
            product_data[normalized_product_name]['count'] += order.get('quantity', 1)
            product_data[normalized_product_name]['revenue'] += order.get('total_price', 0)
            product_data[normalized_product_name]['daily_counts'][day_index] += order.get('quantity', 1)
            
            # Add to payment data
            payment_method = order.get('payment_method', 'Unknown')
            # Format payment method name
            if payment_method == 'stripe':
                payment_method = 'Stripe'
            elif payment_method == 'paypal':
                payment_method = 'PayPal'
            elif payment_method == 'nowpayments':
                payment_method = 'Crypto'
            
            payment_data[payment_method]['count'] += 1
            payment_data[payment_method]['daily_counts'][day_index] += 1
    
    # Set daily revenue and orders data
    chart_data['daily_revenue']['data'] = [round(revenue / 100, 2) for revenue in daily_revenue]  # Convert to pounds
    chart_data['daily_orders']['data'] = daily_orders
    
    # Set product breakdown data
    for product_name, data in product_data.items():
        chart_data['product_breakdown']['labels'].append(product_name)
        chart_data['product_breakdown']['data'].append(data['count'])
        chart_data['product_breakdown']['quantities'].append(data['count'])
        chart_data['product_breakdown']['revenue'].append(round(data['revenue'] / 100, 2))  # Convert to pounds
    
    # Set payment methods data
    for payment_method, data in payment_data.items():
        chart_data['payment_methods']['labels'].append(payment_method)
        chart_data['payment_methods']['data'].append(data['count'])
    
    # Generate product trend datasets
    colors = [
        'rgba(138, 107, 255, 1)',
        'rgba(75, 192, 192, 1)',
        'rgba(255, 206, 86, 1)',
        'rgba(255, 99, 132, 1)',
        'rgba(54, 162, 235, 1)'
    ]
    
    # Product trends
    for i, (product_name, data) in enumerate(product_data.items()):
        color = colors[i % len(colors)]
        chart_data['product_trends']['datasets'].append({
            'label': product_name,
            'data': data['daily_counts'],
            'borderColor': color,
            'backgroundColor': color.replace('1)', '0.1)'),
            'borderWidth': 2,
            'tension': 0.1
        })
    
    # Payment method trends
    for i, (payment_method, data) in enumerate(payment_data.items()):
        color = colors[i % len(colors)]
        chart_data['payment_trends']['datasets'].append({
            'label': payment_method,
            'data': data['daily_counts'],
            'borderColor': color,
            'backgroundColor': color.replace('1)', '0.1)'),
            'borderWidth': 2,
            'tension': 0.1
        })
    
    return chart_data

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """API endpoint to get a CSRF token for use in static HTML pages"""
    return jsonify({'csrf_token': generate_csrf()})

@limiter.limit("10 per minute")
@app.route('/create-nowpayments-order', methods=['POST'])
def create_nowpayments_order():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        
        try:
            quantity = int(data.get('quantity', 1))
            if quantity <= 0:
                return jsonify({"error": "Quantity must be greater than zero"}), 400
        except ValueError:
            return jsonify({"error": "Invalid quantity value"}), 400
        
        promo_code = data.get('promoCode') 
        customer_email = data.get('customer_email', '')
        
        db.logs.insert_one({
            "type": "nowpayments_request",
            "timestamp": datetime.now(),
            "data": data
        })
            
        if product_id.isdigit() or not product_id.startswith('product-'):
            product_id = f"product-{product_id}"
        
        products = load_products()
        if product_id not in products:
            # One last attempt to save the request with a default
            product_id = 'product-15'
            if product_id not in products:
                return jsonify({"error": "Product not found"}), 404
            
        # Check if enough codes are available
        available_codes = get_product_codes(product_id)
        if len(available_codes) < quantity:
            return jsonify({"error": f"Not enough codes available. Only {len(available_codes)} left"}), 400
        
        product = products[product_id]
        
        # Apply promo code discount if present
        discount_amount = 0
        if promo_code:
            # Load and validate promo code
            promo_codes = load_promo_codes()
            promo_code = promo_code.upper()
            
            if promo_code in promo_codes:
                promo_data = promo_codes[promo_code]
                
                # Verify promo code is valid
                is_valid = True
                
                # Check if promo code is valid for this product
                if promo_data['product_ids'] and product_id not in promo_data['product_ids']:
                    is_valid = False
                
                # Check if promo code has reached max uses
                if promo_data['max_uses'] > 0 and promo_data['used_count'] >= promo_data['max_uses']:
                    is_valid = False
                
                # Check if promo code is expired
                if promo_data['valid_until'] and promo_data['valid_until'] < datetime.now():
                    is_valid = False
                
                if is_valid:
                    # Calculate discount
                    if promo_data['discount_type'] == 'percentage':
                        discount_amount = int((product['price'] * promo_data['discount_value']) / 100)
                    else:
                        discount_amount = int(promo_data['discount_value'])
                    
                    # Safety check to prevent negative prices
                    if discount_amount >= product['price']:
                        discount_amount = product['price'] - 1  # At least 1 cent/penny
        
        # Adjust price with discount
        final_price = product['price'] - discount_amount
        if final_price < 1:
            final_price = 1  # Minimum price of 1 cent/penny
        
        # Calculate total price in the original currency (GBP)
        total_price_gbp = final_price * quantity
        
        # Convert from pennies to pounds
        total_price_gbp = total_price_gbp / 100
        
        # Create a unique order ID using full UUID
        order_id = f"np-{str(uuid.uuid4())}"
         
        db.logs.insert_one({
            "type": "nowpayments_order",
            "timestamp": datetime.now(),
            "order_id": order_id,
            "product_id": product_id,
            "quantity": quantity,
            "total_price_gbp": total_price_gbp,
            "promo_code": promo_code if promo_code else '',
            "discount_amount": discount_amount,
            "customer_email": customer_email
        })    
        
        # Get the codes for this order now, but don't remove them yet
        selected_codes = available_codes[:quantity]
        code_text = "\n".join(selected_codes)
        
        # Create NowPayments payment
        headers = {
            'x-api-key': nowpayments_api_key,
            'Content-Type': 'application/json',
        }
        
        success_url = request.host_url + f"nowpayments-success?order_id={order_id}"
        cancel_url = request.host_url + f"products/product-{product_id.replace('product-', '')}.html"
        ipn_callback_url = request.host_url + "webhook/nowpayments"
        
        payload = {
            "price_amount": total_price_gbp,
            "price_currency": "gbp",
            "order_id": order_id,
            "order_description": f"Purchase of {product['name']} x{quantity}",
            "ipn_callback_url": ipn_callback_url,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "is_fee_paid_by_user": False
        }
        
        db.logs.insert_one({
            "type": "nowpayments_api_request",
            "timestamp": datetime.now(),
            "payload": payload
        })
        
        response = requests.post(
            f"{nowpayments_api_url}/v1/invoice",
            headers=headers,
            json=payload
        )
        
        db.logs.insert_one({
            "type": "nowpayments_api_response",
            "timestamp": datetime.now(),
            "status_code": response.status_code,
            "response_text": response.text
        })
        
        if response.status_code in (200, 201):
            payment_data = response.json()
            
            # If promo code was used successfully, increment its usage
            if promo_code and discount_amount > 0:
                increment_promo_code_usage(promo_code)
                        
            temp_order_data = {
                'order_id': order_id,
                'nowpayments_id': payment_data.get('id'),
                'product_id': product_id,
                'product_name': f"{product['name']} (x{quantity})" if quantity > 1 else product['name'],
                'quantity': quantity,
                'total_price': total_price_gbp,
                'currency': 'gbp',
                'timestamp': datetime.now().isoformat(),
                'promo_code': promo_code if promo_code else '',
                'original_price': product['price'],
                'discount_amount': discount_amount,
                'original_currency': product['currency'],
                'customer_email': customer_email,
                'codes': code_text  # Store the codes here
            }
            save_temp_order(order_id, temp_order_data)
            
            # Return the invoice URL to redirect the customer
            return jsonify({
                "id": payment_data.get('id'),
                "url": payment_data.get('invoice_url')
            })
        else:
            print(f"NowPayments error: {response.text}")
            return jsonify({"error": f"NowPayments API error: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error in create_nowpayments_order: {str(e)}")
        traceback.print_exc()
        
        db.error_logs.insert_one({
            "type": "nowpayments_error",
            "timestamp": datetime.now(),
            "function": "create_nowpayments_order",
            "error": str(e),
            "traceback": traceback.format_exc()
        })
            
        return jsonify(error=str(e)), 500

@app.route('/nowpayments-success')
def nowpayments_success():
    try:
        order_id = request.args.get('order_id')
        print(f"NowPayments success redirect for order: {order_id}")
        
        if not order_id:
            return redirect('/payment-failed.html')
            
        # Check if the order has been processed by the webhook
        if is_order_processed(order_id):
            # Order has been processed, find it in MongoDB
            print(f"Order {order_id} already processed by webhook")
            
            order = db.orders.find_one({"payment_id": order_id})
            if order:
                # Found the completed order, use its details
                promo_info = ""
                if order.get('promo_code'):
                    promo_info = f"<p><strong>Promo Code:</strong> {order.get('promo_code')}</p>"
                    
                return render_template('success.html',
                                     order_id=order.get('order_id'),
                                     product_name=order.get('product_name'),
                                     code=order.get('code').replace(' | ', '\n'),  # Convert back to newlines
                                     promo_info=promo_info)
            
            # If we get here, we didn't find the order, which is odd
            # Let's try to create a minimal success page with what we know
            temp_order_data = get_temp_order(order_id)
            if temp_order_data:
                promo_info = ""
                if temp_order_data.get('promo_code'):
                    promo_info = f"<p><strong>Promo Code:</strong> {temp_order_data.get('promo_code')}</p>"
                    
                return render_template('success.html',
                                     order_id=order_id,
                                     product_name=temp_order_data.get('product_name', 'Your Product'),
                                     code="Please check your email for your code.",
                                     promo_info=promo_info)
            
            # Ultimate fallback
            return render_template('success.html',
                                 order_id=order_id,
                                 product_name="Your Product",
                                 code="Your payment was successful. Please check your email for your code.")
        
        # Order hasn't been processed yet by the webhook
        # This means the success page loaded before the webhook was received
        print(f"Order {order_id} not yet processed by webhook")
                
        # Load the temp order data and show the codes, but don't process
        temp_order_data = get_temp_order(order_id)
        
        if temp_order_data:
            # Check if a promo code was used
            promo_info = ""
            if temp_order_data.get('promo_code'):
                promo_info = f"<p><strong>Promo Code:</strong> {temp_order_data.get('promo_code')}</p>"
                
            # Display the order details and codes
            return render_template('success.html',
                                 order_id=order_id,
                                 product_name=temp_order_data.get('product_name', 'Your Product'),
                                 code=temp_order_data.get('codes', 'Please check your email for your code.'),
                                 promo_info=promo_info,
                                 is_crypto=True)
        
        # Fallback if we can't find the temp file
        return render_template('success.html',
                             order_id=order_id,
                             product_name="Your Product",
                             code="Your payment is being processed. Please check your email for your code.",
                             is_crypto=True)
        
    except Exception as e:
        print(f"Error in nowpayments_success: {str(e)}")
        traceback.print_exc()
        return redirect('/payment-failed.html')

# Add this endpoint to check the payment status
@csrf.exempt
@app.route('/check-nowpayments-status/<payment_id>', methods=['GET'])
def check_payment_status(payment_id):
    """Check the status of a NowPayments payment"""
    try:
        # Verify user is allowed to check this payment
        # In a real app, you might want to add authentication here
        
        payment_data = check_nowpayments_status(payment_id)
        
        if payment_data:
            # Format the response for the user
            return jsonify({
                'payment_id': payment_id,
                'status': payment_data.get('payment_status'),
                'created_at': payment_data.get('created_at'),
                'updated_at': payment_data.get('updated_at'),
                'pay_amount': payment_data.get('pay_amount'),
                'pay_currency': payment_data.get('pay_currency')
            })
        else:
            return jsonify({"error": "Payment not found"}), 404
            
    except Exception as e:
        print(f"Error in check_payment_status: {str(e)}")
        traceback.print_exc()
        return jsonify(error=str(e)), 500

@csrf.exempt
@app.route('/webhook/nowpayments', methods=['POST'])
def nowpayments_webhook():
    try:
        # Get the request data
        payload = request.get_data()
        request_json = request.get_json()
        
        # Verify the HMAC signature (authenticate that it's really from NowPayments)
        signature = request.headers.get('X-Nowpayments-Sig')
        
        if signature and nowpayments_ipn_secret:
            # Create the HMAC signature to verify the request
            calculated_hmac = hmac.new(
                bytes(nowpayments_ipn_secret, 'utf-8'),
                payload,
                hashlib.sha512
            ).hexdigest()
            
            # Compare signatures
            if calculated_hmac != signature:
                print("NowPayments IPN: Invalid signature")
                return jsonify({"error": "Invalid signature"}), 401
        else:
            print("NowPayments IPN: Missing signature or IPN secret")
            # In production, you might want to reject these requests
            # For testing, we'll accept them for now
        
        # Process the payment
        payment_status = request_json.get('payment_status')
        order_id = request_json.get('order_id')
        
        # Log the webhook for debugging
        db.webhook_logs.insert_one({
            "type": "nowpayments",
            "timestamp": datetime.now(),
            "payload": request_json,
            "signature": signature or "missing"
        })
            
        # Check if this order has already been processed
        if is_order_processed(order_id):
            print(f"Order {order_id} already processed, ignoring webhook")
            return jsonify({"status": "already processed"})
        
        # Only process completed payments
        if payment_status == 'finished':
            # Get temporary order data
            temp_order_data = get_temp_order(order_id)
            
            if not temp_order_data:
                print(f"Temp order data not found for {order_id}")
                return jsonify({"error": "Order data not found"}), 404
            
            product_id = temp_order_data.get('product_id')
            quantity = int(temp_order_data.get('quantity', 1))
            customer_email = temp_order_data.get('customer_email', '')
            codes = temp_order_data.get('codes', '')
            promo_code = temp_order_data.get('promo_code', '')
            original_price = temp_order_data.get('original_price', 0)
            discount_amount = temp_order_data.get('discount_amount', 0)
            
            # Get crypto payment details
            crypto_currency = request_json.get('pay_currency', '')
            crypto_amount = request_json.get('pay_amount', 0)
            
            # Get fiat payment details (total amount paid in fiat currency)
            # Convert to pence for consistency with other payment methods
            price_amount = temp_order_data.get('total_price', 0)
            total_price_pence = int(price_amount * 100) if price_amount else 0
            
            # Generate a finalized order ID
            final_order_id = str(uuid.uuid4())
            
            # Get product name from the temp order
            product_name = temp_order_data.get('product_name', 'Unknown Product')
            
            # Create the finalized order
            finalized_order = {
                'order_id': final_order_id,
                'product_id': product_id,
                'product_name': product_name,
                'email': customer_email,
                'code': codes.replace('\n', ' | '),  # Replace newlines for storage
                'timestamp': datetime.now().isoformat(),
                'payment_id': order_id,
                'quantity': quantity,
                'payment_method': 'nowpayments',
                'crypto_currency': crypto_currency,
                'crypto_amount': crypto_amount,
                'promo_code': promo_code,
                'price': original_price - discount_amount,  # Unit price after discount
                'original_price': original_price,           # Original unit price
                'discount_amount': discount_amount,         # Discount amount per unit
                'total_price': total_price_pence            # Total price in pence
            }
            
            # Save the finalized order
            save_result = save_order(finalized_order)
            print(f"Order saved: {save_result}")
            
            # IMPORTANT: Send the email with the codes immediately after payment is confirmed
            if customer_email and '@' in customer_email:
                try:
                    print(f"Sending email to {customer_email} for order {final_order_id}")
                    send_code_email(customer_email, product_name, codes, final_order_id)
                    print(f"Email sent successfully to {customer_email}")
                except Exception as email_err:
                    print(f"Error sending email: {str(email_err)}")
                    # Log email errors
                    db.error_logs.insert_one({
                        "type": "email_error",
                        "timestamp": datetime.now(),
                        "order_id": final_order_id,
                        "email": customer_email,
                        "error": str(email_err)
                    })
            else:
                print(f"Invalid email or missing email: {customer_email}")
            
            # Remove used codes from available codes
            if codes:
                code_list = codes.split('\n')
                for code in code_list:
                    if code.strip():
                        remove_used_code(product_id, code.strip())
                        
            # Mark order as processed
            mark_order_processed(order_id)
            
            # Try to remove the temp order
            try:
                delete_temp_order(order_id)
            except:
                pass
                
            # Log the successful processing
            db.webhook_logs.insert_one({
                "type": "nowpayments_success",
                "timestamp": datetime.now(),
                "order_id": order_id,
                "final_order_id": final_order_id
            })
        
        return jsonify({"status": "success"})
        
    except Exception as e:
        print(f"Error processing NowPayments webhook: {str(e)}")
        traceback.print_exc()
        
        # Log errors to MongoDB
        db.error_logs.insert_one({
            "type": "nowpayments_webhook_error",
            "timestamp": datetime.now(),
            "error": str(e),
            "traceback": traceback.format_exc()
        })
        
        return jsonify({"error": str(e)}), 500

def load_promo_codes():
    """Load promo codes from MongoDB"""
    promo_codes = {}
    
    try:
        # Get all promo codes from MongoDB
        cursor = db.promo_codes.find()
        
        for promo_doc in cursor:
            # Skip documents without code
            if not promo_doc.get('code'):
                continue
                
            code = promo_doc['code'].strip().upper()
            
            # Remove MongoDB _id field
            if '_id' in promo_doc:
                del promo_doc['_id']
            
            # Parse date strings if they are stored as strings in MongoDB
            valid_until = promo_doc.get('valid_until')
            if valid_until and isinstance(valid_until, str):
                try:
                    valid_until = datetime.fromisoformat(valid_until)
                    promo_doc['valid_until'] = valid_until
                except:
                    promo_doc['valid_until'] = None
            
            # Parse creation date if it's a string
            created_at = promo_doc.get('created_at')
            if created_at and isinstance(created_at, str):
                try:
                    created_at = datetime.fromisoformat(created_at)
                    promo_doc['created_at'] = created_at
                except:
                    promo_doc['created_at'] = datetime.now()
            
            promo_codes[code] = promo_doc
        
        return promo_codes
    except Exception as e:
        print(f"Error loading promo codes: {str(e)}")
        traceback.print_exc()
        return {}
    
def increment_promo_code_usage(code):
    """Increment the usage count for a promo code in MongoDB"""
    try:
        code = code.upper()
        
        # Update the promo code document to increment used_count
        result = db.promo_codes.update_one(
            {"code": code},
            {"$inc": {"used_count": 1}}
        )
        
        # Check if a document was actually updated
        if result.modified_count > 0:
            print(f"Incremented usage count for promo code {code}")
            return True
        else:
            print(f"Promo code {code} not found for incrementing")
            return False
    except Exception as e:
        print(f"Error incrementing promo code usage: {str(e)}")
        traceback.print_exc()
        return False

def save_promo_codes(promo_codes):
    """Save promo codes to MongoDB"""
    try:
        # Start a MongoDB session to handle bulk operations
        with client.start_session() as session:
            # Delete all existing promo codes and insert new ones in a transaction
            with session.start_transaction():
                # Remove all existing promo codes
                db.promo_codes.delete_many({})
                
                # Prepare documents for bulk insert
                promo_docs = []
                for code, data in promo_codes.items():
                    # Convert datetime objects to strings for MongoDB
                    promo_doc = dict(data)  # Create a copy to avoid modifying the original
                    
                    if isinstance(promo_doc.get('valid_until'), datetime):
                        promo_doc['valid_until'] = promo_doc['valid_until'].isoformat()
                    
                    if isinstance(promo_doc.get('created_at'), datetime):
                        promo_doc['created_at'] = promo_doc['created_at'].isoformat()
                    
                    promo_docs.append(promo_doc)
                
                # Insert all promo codes
                if promo_docs:
                    db.promo_codes.insert_many(promo_docs)
        
        print(f"Successfully saved {len(promo_codes)} promo codes to MongoDB")
        return True
    except Exception as e:
        print(f"Error saving promo codes: {str(e)}")
        traceback.print_exc()
        return False

# Function to get PayPal access token
def get_paypal_access_token():
    """Get PayPal OAuth access token"""
    try:
        # Encode client ID and secret
        auth = base64.b64encode(f"{paypal_client_id}:{paypal_client_secret}".encode()).decode()
        
        # Make the request to PayPal OAuth API
        response = requests.post(
            f"{paypal_api_url}/v1/oauth2/token",
            headers={
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data="grant_type=client_credentials"
        )
        
        if response.status_code == 200:
            return response.json().get('access_token')
        else:
            print(f"Error getting PayPal token: {response.text}")
            return None
    except Exception as e:
        print(f"PayPal token error: {str(e)}")
        return None

@app.route('/gooner/promo-codes', methods=['GET'])
def promo_codes():
    """Admin page to manage promo codes"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return redirect('/gooner/login')
    
    # Load promo codes and products
    promo_codes = load_promo_codes()
    products = load_products()
    
    # Get current date for template
    now = datetime.now()
    
    return render_template('promo_codes.html', 
                         promo_codes=promo_codes, 
                         products=products,
                         now=now)

@app.route('/gooner/promo-codes/create', methods=['POST'])
def create_promo_code():
    """Create a new promo code in MongoDB"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Not authorized"}), 401
    
    try:
        # Get form data
        code = request.form.get('code', '').strip().upper()
        discount_type = request.form.get('discount_type')
        discount_value = float(request.form.get('discount_value', 0))
        max_uses = int(request.form.get('max_uses', 0))
        valid_until = request.form.get('valid_until')
        product_scope = request.form.get('product_scope')
        
        # Validate code
        if not code or len(code) < 4 or len(code) > 20:
            return jsonify({"success": False, "error": "Promo code must be between 4-20 characters"}), 400
        
        # Security check for suspicious characters
        suspicious_chars = ['<', '>', '\'', '"', ';', '--', '=', '/']
        if any(char in code for char in suspicious_chars):
            return jsonify({"success": False, "error": "Invalid characters in promo code"}), 400
        
        # Validate discount value
        if discount_type == 'percentage' and (discount_value <= 0 or discount_value > 100):
            return jsonify({"success": False, "error": "Percentage discount must be between 1-100%"}), 400
        elif discount_value <= 0:
            return jsonify({"success": False, "error": "Discount value must be greater than 0"}), 400
        
        # Parse valid_until date
        valid_until_date = None
        if valid_until:
            try:
                valid_until_date = datetime.fromisoformat(valid_until)
            except:
                return jsonify({"success": False, "error": "Invalid date format"}), 400
        
        # Get product IDs
        product_ids = []
        if product_scope == 'specific':
            product_ids = request.form.getlist('products[]')
            if not product_ids:
                return jsonify({"success": False, "error": "No products selected"}), 400
        
        # Convert fixed discount to pence/cents
        if discount_type == 'fixed':
            discount_value = int(discount_value)
        
        # Check if code already exists in MongoDB
        existing_code = db.promo_codes.find_one({"code": code})
        if existing_code:
            return jsonify({"success": False, "error": "Promo code already exists"}), 400
        
        # Create new promo code document
        promo_code_doc = {
            'code': code,
            'discount_type': discount_type,
            'discount_value': discount_value,
            'max_uses': max_uses,
            'used_count': 0,
            'valid_until': valid_until_date.isoformat() if valid_until_date else None,
            'product_ids': product_ids,
            'created_at': datetime.now().isoformat()
        }
        
        # Insert the promo code into MongoDB
        result = db.promo_codes.insert_one(promo_code_doc)
        
        if result.inserted_id:
            return jsonify({
                "success": True,
                "message": f"Promo code {code} created successfully"
            })
        else:
            return jsonify({"success": False, "error": "Error saving promo code"}), 500
    
    except Exception as e:
        print(f"Error creating promo code: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@limiter.limit("5 per minute")
@app.route('/validate-promo', methods=['POST'])
def validate_promo():
    """Validate a promo code using MongoDB"""
    try:
        print("Received promo validation request")
        data = request.get_json()
        
        if not data:
            print("No data provided in request")
            return jsonify({
                'valid': False,
                'message': 'No data provided'
            }), 400
        
        promo_code = data.get('promoCode', '').strip().upper()
        product_id = data.get('productId', '')
        
        print(f"Validating promo code: {promo_code} for product: {product_id}")
        
        # Basic validation
        if not promo_code or len(promo_code) < 4 or len(promo_code) > 20:
            return jsonify({
                'valid': False,
                'message': 'Invalid promo code format'
            }), 400
        
        # Find the promo code in MongoDB
        promo_data = db.promo_codes.find_one({"code": promo_code})
        
        if not promo_data:
            return jsonify({
                'valid': False,
                'message': 'Promo code not found'
            }), 404
        
        # Check if promo code is valid for this product
        if promo_data.get('product_ids') and product_id not in promo_data['product_ids']:
            return jsonify({
                'valid': False,
                'message': 'Promo code not valid for this product'
            }), 400
        
        # Check if promo code has reached max uses
        if promo_data.get('max_uses', 0) > 0 and promo_data.get('used_count', 0) >= promo_data['max_uses']:
            return jsonify({
                'valid': False,
                'message': 'Promo code has reached maximum uses'
            }), 400
        
        # Check if promo code is expired
        if promo_data.get('valid_until'):
            # Parse the date if it's stored as a string
            valid_until = promo_data['valid_until']
            if isinstance(valid_until, str):
                try:
                    valid_until = datetime.fromisoformat(valid_until)
                except:
                    valid_until = None
            
            if valid_until and valid_until < datetime.now():
                return jsonify({
                    'valid': False,
                    'message': 'Promo code has expired'
                }), 400
        
        # Return valid promo code with discount information
        return jsonify({
            'valid': True,
            'type': promo_data.get('discount_type', 'percentage'),
            'discountPercentage': promo_data.get('discount_value', 0) if promo_data.get('discount_type') == 'percentage' else 0,
            'discountAmount': promo_data.get('discount_value', 0) if promo_data.get('discount_type') == 'fixed' else 0
        })
        
    except Exception as e:
        print(f"Error validating promo code: {str(e)}")
        traceback.print_exc()
        return jsonify({
            'valid': False,
            'message': 'Error processing promo code'
        }), 500

@app.route('/gooner/promo-codes/delete/<code>', methods=['POST'])
def delete_promo_code(code):
    """Delete a promo code from MongoDB"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Not authorized"}), 401
    
    try:
        code = code.upper()
        
        # Delete the promo code from MongoDB
        result = db.promo_codes.delete_one({"code": code})
        
        if result.deleted_count > 0:
            return jsonify({
                "success": True,
                "message": f"Promo code {code} deleted successfully"
            })
        else:
            return jsonify({"success": False, "error": "Promo code not found"}), 404
    
    except Exception as e:
        print(f"Error deleting promo code: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@limiter.limit("10 per minute")
@app.route('/create-paypal-order', methods=['POST'])
def create_paypal_order():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))
        promo_code = data.get('promoCode')  # Get promo code if provided
        
        # Clean up product ID if needed
        if '/' in product_id:
            parts = product_id.split('/')
            product_id = parts[-1]
            
        if product_id.endswith('.html'):
            product_id = product_id.replace('.html', '')
            
        if product_id.isdigit() or not product_id.startswith('product-'):
            product_id = f"product-{product_id}"
        
        products = load_products()
        if product_id not in products:
            return jsonify({"error": "Product not found"}), 404
            
        # Check if enough codes are available
        available_codes = get_product_codes(product_id)
        if len(available_codes) < quantity:
            return jsonify({"error": f"Not enough codes available. Only {len(available_codes)} left"}), 400
        
        product = products[product_id]
        
        # Apply promo code discount if present
        discount_amount = 0
        if promo_code:
            # Load and validate promo code
            promo_codes = load_promo_codes()
            promo_code = promo_code.upper()
            
            if promo_code in promo_codes:
                promo_data = promo_codes[promo_code]
                
                # Verify promo code is valid
                is_valid = True
                
                # Check if promo code is valid for this product
                if promo_data['product_ids'] and product_id not in promo_data['product_ids']:
                    is_valid = False
                
                # Check if promo code has reached max uses
                if promo_data['max_uses'] > 0 and promo_data['used_count'] >= promo_data['max_uses']:
                    is_valid = False
                
                # Check if promo code is expired
                if promo_data['valid_until'] and promo_data['valid_until'] < datetime.now():
                    is_valid = False
                
                if is_valid:
                    # Calculate discount
                    if promo_data['discount_type'] == 'percentage':
                        discount_amount = int((product['price'] * promo_data['discount_value']) / 100)
                    else:
                        discount_amount = int(promo_data['discount_value'])
                    
                    # Safety check to prevent negative prices
                    if discount_amount >= product['price']:
                        discount_amount = product['price'] - 1  # At least 1 cent/penny
        
        # Adjust price with discount
        final_price = product['price'] - discount_amount
        if final_price < 1:
            final_price = 1  # Minimum price of 1 cent/penny
        
        # Get access token
        access_token = get_paypal_access_token()
        if not access_token:
            return jsonify({"error": "Could not authenticate with PayPal"}), 500
        
        # Convert price from cents to dollars/pounds
        unit_amount = final_price / 100
        
        # Create PayPal order
        paypal_order_data = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "amount": {
                        "currency_code": product['currency'].upper(),
                        "value": str(unit_amount * quantity),
                        "breakdown": {
                            "item_total": {
                                "currency_code": product['currency'].upper(),
                                "value": str(unit_amount * quantity)
                            }
                        }
                    },
                    "description": product['description'],
                    "items": [
                        {
                            "name": product['name'],
                            "description": product['description'],
                            "quantity": str(quantity),
                            "unit_amount": {
                                "currency_code": product['currency'].upper(),
                                "value": str(unit_amount)
                            }
                        }
                    ],
                    "custom_id": json.dumps({
                        "product_id": product_id,
                        "quantity": quantity,
                        "promo_code": promo_code if promo_code else '',
                        "original_price": product['price'],
                        "discount_amount": discount_amount
                    })
                }
            ],
            "application_context": {
                "return_url": request.host_url + "paypal-success",
                "cancel_url": request.host_url + "products/product-" + product_id.replace('product-', '')
            }
        }
        
        # Call PayPal API to create order
        response = requests.post(
            f"{paypal_api_url}/v2/checkout/orders",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            },
            json=paypal_order_data
        )
        
        if response.status_code in (200, 201):
            order_data = response.json()
            
            # Find the approval URL
            approve_link = next(
                (link for link in order_data.get('links', []) if link.get('rel') == 'approve'),
                None
            )
            
            # If promo code was used successfully, increment its usage
            if promo_code and discount_amount > 0:
                increment_promo_code_usage(promo_code)
            
            if approve_link:
                return jsonify({
                    'id': order_data.get('id'),
                    'url': approve_link.get('href')
                })
            else:
                return jsonify({"error": "No approval URL found in PayPal response"}), 500
        else:
            print(f"PayPal error: {response.text}")
            return jsonify({"error": f"PayPal error: {response.status_code}"}), response.status_code
            
    except Exception as e:
        print(f"Error in create_paypal_order: {str(e)}")
        traceback.print_exc()
        return jsonify(error=str(e)), 500

# Add these new routes to your app.py file

@app.route('/api/codes/<product_id>', methods=['GET'])
@csrf.exempt
def get_codes_api(product_id):
    """API endpoint to get codes for a product with pagination and search from MongoDB"""
    search = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    
    try:
        # Build the query
        query = {"product_id": product_id, "used": False}
        
        # Add search filter if provided
        if search:
            query["code"] = {"$regex": search, "$options": "i"}  # Case-insensitive search
        
        # Calculate pagination
        skip = (page - 1) * per_page
        
        # Get total count first (for pagination info)
        total_codes = db.codes.count_documents(query)
        
        # Get paginated results, sorted alphabetically
        cursor = db.codes.find(
            query,
            {"code": 1, "_id": 0}  # Only return the code field
        ).sort("code", 1).skip(skip).limit(per_page)
        
        # Extract codes from cursor
        codes = [doc["code"] for doc in cursor]
        
        return jsonify({
            "codes": codes,
            "total": total_codes
        })
    except Exception as e:
        print(f"Error getting codes for product {product_id}: {str(e)}")
        traceback.print_exc()
        return jsonify({"codes": [], "total": 0})

@app.route('/api/codes/<product_id>/<path:code>', methods=['DELETE'])
@csrf.exempt
def delete_code_api(product_id, code):
    """API endpoint to delete a specific code from MongoDB"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Not authorized"}), 401
    
    try:
        # Delete the code from MongoDB
        result = db.codes.delete_one({"product_id": product_id, "code": code})
        
        if result.deleted_count > 0:
            print(f"Successfully deleted code {code} for product {product_id}")
            return jsonify({
                "success": True,
                "message": f"Successfully deleted code: {code}"
            })
        else:
            print(f"Code {code} not found for product {product_id}")
            return jsonify({"success": False, "error": "Code not found"}), 404
    except Exception as e:
        print(f"Error deleting code: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/codes/<product_id>/bulk-delete', methods=['POST'])
@csrf.exempt
def bulk_delete_codes_api(product_id):
    """API endpoint to delete multiple codes at once from MongoDB"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Not authorized"}), 401
    
    try:
        data = request.get_json()
        codes_to_delete = data.get('codes', [])
        
        if not codes_to_delete:
            return jsonify({"success": False, "error": "No codes provided"}), 400
        
        # Delete multiple codes in one operation
        result = db.codes.delete_many({
            "product_id": product_id,
            "code": {"$in": codes_to_delete}
        })
        
        deleted_count = result.deleted_count
        
        return jsonify({
            "success": True,
            "message": f"Successfully deleted {deleted_count} codes",
            "deleted_count": deleted_count
        })
    except Exception as e:
        print(f"Error bulk deleting codes: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500
    
@app.route('/api/codes/<product_id>/delete-all', methods=['POST'])
@csrf.exempt
def delete_all_codes_api(product_id):
    """API endpoint to delete all codes for a product from MongoDB"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return jsonify({"success": False, "error": "Not authorized"}), 401
    
    try:
        # First, count how many codes will be deleted
        count = db.codes.count_documents({"product_id": product_id})
        
        # Then delete all codes for this product
        result = db.codes.delete_many({"product_id": product_id})
        
        return jsonify({
            "success": True,
            "message": f"Successfully deleted all {result.deleted_count} codes",
            "deleted_count": result.deleted_count
        })
    except Exception as e:
        print(f"Error deleting all codes: {str(e)}")
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500

def calculate_payment_stats(orders):
    """Calculate payment statistics from MongoDB order data"""
    stats = {
        'stripe': {'display_name': 'Stripe', 'orders': 0, 'revenue': 0, 'total_value': 0},
        'paypal': {'display_name': 'PayPal', 'orders': 0, 'revenue': 0, 'total_value': 0},
        'nowpayments': {'display_name': 'Crypto', 'orders': 0, 'revenue': 0, 'total_value': 0},
    }
    
    # Process orders to calculate statistics
    for order in orders:
        payment_method = order.get('payment_method', 'unknown')
        if payment_method in stats:
            stats[payment_method]['orders'] += 1
            order_value = order.get('total_price', 0) / 100  # Convert from pence to pounds
            stats[payment_method]['revenue'] += order_value
            stats[payment_method]['total_value'] += order_value
    
    # Calculate averages and rates
    for method, data in stats.items():
        if data['orders'] > 0:
            data['avg_order_value'] = data['total_value'] / data['orders']
            # You'd need to track attempted checkouts to calculate true conversion rate
            data['conversion_rate'] = round(random.uniform(60, 80), 1) 
        else:
            data['avg_order_value'] = 0
            data['conversion_rate'] = 0
    
    return stats

@app.route('/gooner/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 20 per hour")
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Set session variable to indicate user is logged in
            session['logged_in'] = True
            session['username'] = username
            return redirect('/gooner/dashboard')
        else:
            return render_template('login.html', error='Invalid username or password')
    
    # If user is already logged in, redirect to admin page
    if session.get('logged_in'):
        return redirect('/gooner/dashboard')
        
    return render_template('login.html')

@app.route('/gooner/logout')
def admin_logout():
    """Admin logout"""
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect('/')

@app.route('/gooner/quick-add', methods=['GET', 'POST'])
def quick_add():
    """Admin page to quickly add discount codes using MongoDB"""
    # Check if user is logged in
    if not session.get('logged_in'):
        return redirect('/gooner/login')
        
    if request.method == 'GET':
        # Get list of products
        products = load_products()
        
        # Get counts of available codes
        code_counts = {}
        for product_id in products:
            code_count = db.codes.count_documents({"product_id": product_id, "used": False})
            code_counts[product_id] = code_count
        
        return render_template('quick_add.html', products=products, code_counts=code_counts)
    
    elif request.method == 'POST':
        product_id = request.form.get('product_id')
        codes_text = request.form.get('codes')
        
        if not product_id or not codes_text:
            return jsonify({"success": False, "error": "Product ID and codes are required"}), 400
            
        # Split the codes by newline
        new_codes = [code.strip() for code in codes_text.split('\n') if code.strip()]
        
        if not new_codes:
            return jsonify({"success": False, "error": "At least one valid code is required"}), 400
        
        try:
            # Check for existing codes to avoid duplicates
            existing_codes_cursor = db.codes.find(
                {"product_id": product_id, "code": {"$in": new_codes}},
                {"code": 1, "_id": 0}
            )
            existing_codes = [doc["code"] for doc in existing_codes_cursor]
            
            # Filter out codes that already exist
            codes_to_add = [code for code in new_codes if code not in existing_codes]
            
            # Create documents for bulk insert
            code_documents = [
                {"product_id": product_id, "code": code, "used": False, "created_at": datetime.now()}
                for code in codes_to_add
            ]
            
            # Insert new codes
            if code_documents:
                result = db.codes.insert_many(code_documents)
                added_count = len(result.inserted_ids)
            else:
                added_count = 0
            
            skipped_count = len(new_codes) - added_count
            
            return jsonify({
                "success": True, 
                "added": added_count,
                "skipped": skipped_count,
                "message": f"Added {added_count} new code(s). Skipped {skipped_count} duplicate(s)."
            })
            
        except Exception as e:
            print(f"Error adding codes: {str(e)}")
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e)}), 500

# Update to /paypal-success route
@app.route('/paypal-success')
def paypal_success():
    try:
        # Get the order ID from PayPal
        paypal_order_id = request.args.get('token')
        
        print(f"PayPal Success - Token: {paypal_order_id}")
        
        if not paypal_order_id:
            print("No PayPal token found")
            return redirect('/payment-failed.html')
        
        # Get access token
        access_token = get_paypal_access_token()
        if not access_token:
            print("Failed to get PayPal access token")
            return redirect('/payment-failed.html')
        
        # Get order details from PayPal
        order_response = requests.get(
            f"{paypal_api_url}/v2/checkout/orders/{paypal_order_id}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        
        if order_response.status_code != 200:
            print(f"Failed to get order details: {order_response.text}")
            return redirect('/payment-failed.html')
            
        order_data = order_response.json()
        print(f"PayPal Order Data: {json.dumps(order_data)}")
        
        # Accept APPROVED or COMPLETED status
        if order_data.get('status') not in ['APPROVED', 'COMPLETED']:
            print(f"Order not approved: {order_data.get('status')}")
            return redirect('/payment-failed.html')
        
        # Extract quantity from order data
        quantity = 1  # Default fallback
        product_id = 'product-15'  # Default fallback
        promo_code = ''  # Default value
        
        # First check if we can get quantity and promo code from the custom_id
        if 'purchase_units' in order_data:
            for unit in order_data['purchase_units']:
                # Try custom_id first to get product_id, quantity, and promo_code
                if 'custom_id' in unit:
                    try:
                        custom_data = json.loads(unit['custom_id'])
                        if 'quantity' in custom_data:
                            quantity = int(custom_data['quantity'])
                            print(f"Found quantity in order custom_id: {quantity}")
                        if 'product_id' in custom_data:
                            product_id = custom_data['product_id']
                        if 'promo_code' in custom_data and custom_data['promo_code']:
                            promo_code = custom_data['promo_code']
                            print(f"Found promo code in order custom_id: {promo_code}")
                    except:
                        print("Error parsing order custom_id")
                
                # Check for items
                if 'items' in unit:
                    for item in unit['items']:
                        if 'quantity' in item:
                            try:
                                item_quantity = int(item['quantity'])
                                if item_quantity > quantity:
                                    quantity = item_quantity
                                    print(f"Found quantity in order items: {quantity}")
                            except:
                                print("Error parsing order item quantity")
        
        print(f"Quantity from order: {quantity}")
        
        # Extract total price paid in the order
        total_price = 0
        if 'purchase_units' in order_data:
            for unit in order_data['purchase_units']:
                if 'amount' in unit and 'value' in unit['amount']:
                    try:
                        # PayPal returns the actual currency value (e.g. 2.00), convert to pence
                        price_value = float(unit['amount']['value'])
                        total_price = int(price_value * 100)  # Convert to pence
                        print(f"Total price in pence: {total_price}")
                    except:
                        print("Error parsing order amount")
                        
        # Capture the payment
        capture_response = requests.post(
            f"{paypal_api_url}/v2/checkout/orders/{paypal_order_id}/capture",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
        )
        
        if capture_response.status_code not in (200, 201):
            print(f"Failed to capture payment: {capture_response.text}")
            return redirect('/payment-failed.html')
            
        capture_data = capture_response.json()
        print(f"Capture response: {json.dumps(capture_data)}")
        
        # Get payer email
        payer_email = "customer@example.com"  # Default fallback
        if 'payer' in capture_data and 'email_address' in capture_data['payer']:
            payer_email = capture_data['payer']['email_address']
            print(f"Payer email: {payer_email}")
        
        # Load products and get available codes
        products = load_products()
        available_codes = get_product_codes(product_id)
        print(f"Available codes: {len(available_codes)}")
        
        if available_codes:
            # Generate a unique order ID
            order_id = str(uuid.uuid4())
            
            # Make sure we don't exceed available codes
            if len(available_codes) < quantity:
                print(f"Adjusting quantity from {quantity} to {len(available_codes)}")
                quantity = len(available_codes)
            
            # Select the codes
            order_codes = []
            for i in range(quantity):
                order_codes.append(available_codes[i])
            
            print(f"Selected {len(order_codes)} codes: {order_codes}")
            
            # Join codes with newlines
            code_text = "\n".join(order_codes)
            
            # Format product name with quantity
            product_info = products.get(product_id, {"name": "Discount Code"})
            product_name = f"{product_info['name']} (x{quantity})" if quantity > 1 else product_info['name']
            
            # Calculate price per unit for reporting - use the product's base price or derive from total
            unit_price = products.get(product_id, {}).get('price', 200)  # Default to 200 pence (£2)
            
            # Save the order data
            order_data = {
                'order_id': order_id,
                'product_id': product_id,
                'product_name': product_name,
                'email': payer_email,
                'code': code_text,
                'timestamp': datetime.now().isoformat(),
                'payment_id': paypal_order_id,
                'quantity': quantity,
                'payment_method': 'paypal',
                'price': unit_price,          # Individual price in pence
                'total_price': total_price,   # Total price paid in pence
                'promo_code': promo_code      # Add promo code to the order data
            }
            
            save_result = save_order(order_data)
            print(f"Order saved: {save_result}")
            
            # Send the email
            try:
                send_code_email(payer_email, product_name, code_text, order_id)
                print(f"Email sent to {payer_email}")
            except Exception as email_err:
                print(f"Email error: {str(email_err)}")
            
            # Remove used codes
            for code in order_codes:
                remove_used_code(product_id, code)
            
            # Final verification of code_text
            final_codes = code_text.split('\n')
            print(f"Code text splits into {len(final_codes)} parts")
            
            # Redirect to success page
            return redirect(f"/success?order_id={order_id}")
        else:
            print("No available codes found")
            
        return redirect('/payment-failed.html')
        
    except Exception as e:
        print(f"PayPal success error: {str(e)}")
        traceback.print_exc()
        return redirect('/payment-failed.html')

@app.context_processor
def inject_vercel_analytics():
    """Add Vercel Analytics flag to all templates"""
    return {
        'use_vercel_analytics': True
    }

def import_codes_to_mongodb(product_id, codes):
    """Import a list of codes to MongoDB for a specific product"""
    try:
        # Prepare documents for bulk insert
        code_documents = [
            {"product_id": product_id, "code": code.strip(), "used": False, "created_at": datetime.now()}
            for code in codes if code.strip()
        ]
        
        if not code_documents:
            return 0
        
        # Insert the codes but ignore duplicates
        result = db.codes.insert_many(code_documents, ordered=False)
        
        # Return the number of successfully inserted codes
        return len(result.inserted_ids)
    except pymongo.errors.BulkWriteError as bwe:
        # Handle duplicate key errors
        print(f"Some codes were duplicates and not inserted: {str(bwe)}")
        return len(bwe.details.get('nInserted', 0))
    except Exception as e:
        print(f"Error importing codes for {product_id}: {str(e)}")
        traceback.print_exc()
        return 0

def get_product_price(product_id):
    """Get the price for a specific product"""
    try:
        # Load the products dictionary
        products = load_products()
        
        # Clean up product ID if necessary
        if product_id.startswith('product-'):
            # The ID is already in the correct format
            pass
        elif product_id.isdigit():
            # Convert numeric ID to product-XX format
            product_id = f"product-{product_id}"
        
        # Check if the product exists in our products dictionary
        if product_id in products:
            return products[product_id]['price']
        
        # Log that we're using a default price
        print(f"Product {product_id} not found in products dictionary, using default price")
        return 200  # Default fallback price (£2.00)
    except Exception as e:
        print(f"Error getting product price: {str(e)}")
        return 200  # Default fallback in case of error

def get_product_codes(product_id):
    """Get available codes for a product from MongoDB"""
    try:
        print(f"Looking for codes in MongoDB for product: {product_id}")
        
        # Find all codes for this product that are not marked as used
        codes_cursor = db.codes.find(
            {"product_id": product_id, "used": False},
            {"code": 1, "_id": 0}  # Only return the code field, not the _id
        )
        
        # Extract the codes from the cursor
        codes = [doc["code"] for doc in codes_cursor]
        
        print(f"Found {len(codes)} available codes for {product_id}")
        return codes
    except Exception as e:
        print(f"Error reading codes for {product_id}: {str(e)}")
        traceback.print_exc()
        return []


def remove_used_code(product_id, code):
    """Mark a code as used in MongoDB"""
    try:
        # Update the code document to mark it as used
        result = db.codes.update_one(
            {"product_id": product_id, "code": code, "used": False},
            {"$set": {"used": True, "used_at": datetime.now()}}
        )
        
        # Check if a document was actually updated
        if result.modified_count > 0:
            print(f"Marked code {code} as used for product {product_id}")
            return True
        else:
            print(f"Code {code} not found or already used for product {product_id}")
            return False
    except Exception as e:
        print(f"Error marking code {code} as used for {product_id}: {str(e)}")
        traceback.print_exc()
        return False

def save_order(order_data):
    """Save order details to MongoDB with improved price handling"""
    try:
        # Add a timestamp if not already present
        if 'timestamp' not in order_data:
            order_data['timestamp'] = datetime.now().isoformat()
        
        # Make sure quantity is present and numeric
        if 'quantity' not in order_data:
            order_data['quantity'] = 1
            print("No quantity found in order data, defaulting to 1")
        else:
            # Ensure it's an integer
            try:
                order_data['quantity'] = int(order_data['quantity'])
                print(f"Using quantity: {order_data['quantity']}")
            except (ValueError, TypeError):
                print(f"Invalid quantity value: {order_data['quantity']}, defaulting to 1")
                order_data['quantity'] = 1
        
        # Get product_id and ensure it's in the correct format
        product_id = order_data.get('product_id')
        if product_id:
            # Ensure price is set correctly based on the product
            if 'price' not in order_data:
                # Get the correct price for this product
                price = get_product_price(product_id)
                order_data['price'] = price
                print(f"Set price to {price} based on product ID: {product_id}")
        elif 'price' not in order_data:
            # No product_id, use default price based on payment method
            if 'payment_method' in order_data:
                # Set default price based on payment method
                if order_data['payment_method'] == 'stripe':
                    order_data['price'] = 200  # Default to £2.00 (200 pence)
                elif order_data['payment_method'] == 'paypal':
                    order_data['price'] = 200
                elif order_data['payment_method'] == 'nowpayments':
                    order_data['price'] = 260  # Default price in cents for crypto
                else:
                    order_data['price'] = 200  # Default fallback
            else:
                order_data['price'] = 200  # Default fallback if no payment method

        # Calculate and ensure total_price is set
        if 'total_price' not in order_data:
            order_data['total_price'] = order_data['price'] * order_data['quantity']
            print(f"Calculated total_price: {order_data['total_price']}")
        
        # Ensure formatted date for display
        if 'timestamp' in order_data and isinstance(order_data['timestamp'], str):
            try:
                dt = datetime.fromisoformat(order_data['timestamp'])
                order_data['formatted_date'] = dt.strftime('%b %d, %Y %H:%M')
            except:
                order_data['formatted_date'] = order_data['timestamp']
        
        # Ensure promo_code is always present in the order data (even if empty)
        if 'promo_code' not in order_data:
            order_data['promo_code'] = ''
        
        # Insert the order into MongoDB
        result = db.orders.insert_one(order_data)
        print(f"Order saved successfully: {order_data['order_id']} with MongoDB ID: {result.inserted_id}")
        
        return True
    except Exception as e:
        print(f"Error saving order: {str(e)}")
        traceback.print_exc()
        return False

def load_all_code_counts():
    """Load counts of available codes for all products from MongoDB"""
    products = load_products()
    counts = {}
    
    try:
        # Use MongoDB aggregation to get counts for all products in one query
        pipeline = [
            {"$match": {"used": False}},
            {"$group": {"_id": "$product_id", "count": {"$sum": 1}}}
        ]
        
        result = db.codes.aggregate(pipeline)
        
        # Initialize all products with zero
        for product_id in products:
            counts[product_id] = 0
        
        # Update counts from the aggregation result
        for doc in result:
            counts[doc["_id"]] = doc["count"]
        
        return counts
    except Exception as e:
        print(f"Error loading code counts: {str(e)}")
        traceback.print_exc()
        
        # Fallback to individual queries if aggregation fails
        for product_id in products:
            try:
                counts[product_id] = db.codes.count_documents({"product_id": product_id, "used": False})
            except:
                counts[product_id] = 0
        
        return counts

def load_products():
    """Load product information"""
    return {
        "product-15": {
            "name": "Just Eat - £10 Off £15",
            "price": 200,  # Price in pence
            "currency": "gbp",
            "description": "£10 off £15 Just Eat discount code"
        },
        "product-je-grocery": {
            "name": "Just Eat Grocery - £10 off £15",
            "price": 100,  # Price in pence
            "currency": "gbp",
            "description": "Just Eat grocery discount code"
        }
    }

@app.route('/create-checkout-session', methods=['POST'])
@limiter.limit("5 per minute; 30 per hour")
def create_checkout_session():
    try:
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = int(data.get('quantity', 1))
        promo_code = data.get('promoCode')  # Get promo code if provided
        
        # Clean up product ID if needed
        if '/' in product_id:
            parts = product_id.split('/')
            product_id = parts[-1]
            
        if product_id.endswith('.html'):
            product_id = product_id.replace('.html', '')
            
        if product_id.isdigit() or not product_id.startswith('product-'):
            product_id = f"product-{product_id}"
        
        products = load_products()
        if product_id not in products:
            return jsonify({"error": "Product not found"}), 404
            
        # Check if enough codes are available
        available_codes = get_product_codes(product_id)
        if len(available_codes) < quantity:
            return jsonify({"error": f"Not enough codes available. Only {len(available_codes)} left"}), 400
        
        product = products[product_id]
        
        # Apply promo code discount if present
        discount_amount = 0
        if promo_code:
            # Load and validate promo code
            promo_codes = load_promo_codes()
            promo_code = promo_code.upper()
            
            if promo_code in promo_codes:
                promo_data = promo_codes[promo_code]
                
                # Verify promo code is valid
                is_valid = True
                
                # Check if promo code is valid for this product
                if promo_data['product_ids'] and product_id not in promo_data['product_ids']:
                    is_valid = False
                
                # Check if promo code has reached max uses
                if promo_data['max_uses'] > 0 and promo_data['used_count'] >= promo_data['max_uses']:
                    is_valid = False
                
                # Check if promo code is expired
                if promo_data['valid_until'] and promo_data['valid_until'] < datetime.now():
                    is_valid = False
                
                if is_valid:
                    # Calculate discount
                    if promo_data['discount_type'] == 'percentage':
                        discount_amount = int((product['price'] * promo_data['discount_value']) / 100)
                    else:
                        discount_amount = int(promo_data['discount_value'])
                    
                    # Safety check to prevent negative prices
                    if discount_amount >= product['price']:
                        discount_amount = product['price'] - 1  # At least 1 cent/penny
        
        # Adjust price with discount
        final_price = product['price'] - discount_amount
        if final_price < 1:
            final_price = 1  # Minimum price of 1 cent/penny
        
        # Create Stripe checkout session with the adjusted price
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': product['currency'],
                    'product_data': {
                        'name': product['name'],
                        'description': product['description'],
                    },
                    'unit_amount': final_price,
                },
                'quantity': quantity,
            }],
            mode='payment',
            success_url=request.host_url + 'success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'products/product-' + product_id.replace('product-', ''),
            metadata={
                'product_id': product_id,
                'quantity': str(quantity),
                'promo_code': promo_code if promo_code else '',
                'original_price': str(product['price']),
                'discount_amount': str(discount_amount)
            }
        )
        
        # If promo code was used successfully, increment its usage
        if promo_code and discount_amount > 0:
            increment_promo_code_usage(promo_code)
        
        return jsonify({'id': checkout_session.id, 'url': checkout_session.url})
            
    except Exception as e:
        return jsonify(error=str(e)), 500

@csrf.exempt
@app.route('/webhook/stripe', methods=['POST'])
@app.route('/webhook/stripe/', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_secret
        )
    except ValueError as e:
        # Invalid payload
        return jsonify({"error": "Invalid payload"}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify({"error": "Invalid signature"}), 400
    
    # Log the webhook event
    db.webhook_logs.insert_one({
        "type": "stripe",
        "timestamp": datetime.now(),
        "event_type": event['type'],
        "event_id": event['id']
    })
    
    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        
        # Retrieve session details to get customer email
        session_details = stripe.checkout.Session.retrieve(
            session.id,
            expand=['customer', 'line_items']
        )
        
        customer_email = session_details.customer_details.email
        product_id = session.metadata.get('product_id')
        
        # Get quantity
        quantity = 1
        if hasattr(session_details, 'line_items') and session_details.line_items.data:
            quantity = session_details.line_items.data[0].quantity
        elif session.metadata.get('quantity'):
            quantity = int(session.metadata.get('quantity', 1))
            
        if quantity < 1:
            quantity = 1
            
        # Get promo code from metadata
        promo_code = session.metadata.get('promo_code', '')
        
        # Get original price and discount amount from metadata
        original_price = 0
        discount_amount = 0
        
        if session.metadata.get('original_price'):
            try:
                original_price = int(session.metadata.get('original_price'))
            except (ValueError, TypeError):
                # If conversion fails, get price from product
                original_price = get_product_price(product_id)
        else:
            # Get price from product
            original_price = get_product_price(product_id)
            
        if session.metadata.get('discount_amount'):
            try:
                discount_amount = int(session.metadata.get('discount_amount'))
            except (ValueError, TypeError):
                discount_amount = 0
        
        # Calculate unit price after discount
        unit_price = original_price - discount_amount
        if unit_price < 1:
            unit_price = 1  # Minimum price of 1 pence
            
        # Get the amount paid from Stripe
        total_amount_paid = 0
        if hasattr(session_details, 'amount_total'):
            total_amount_paid = session_details.amount_total  # This is in smallest currency unit (pence)
        
        # If amount_total is not available, calculate it
        if total_amount_paid == 0:
            total_amount_paid = unit_price * quantity
            
        # Process the payment
        products = load_products()
        if product_id and product_id in products:
            # Get codes for this product
            available_codes = get_product_codes(product_id)
            
            if len(available_codes) < quantity:
                quantity = len(available_codes)
                
            if available_codes:
                # Generate a unique order ID
                order_id = str(uuid.uuid4())
                
                # Get the codes for this order
                order_codes = available_codes[:quantity]
                
                # Format product name
                product_name = f"{products[product_id]['name']} (x{quantity})" if quantity > 1 else products[product_id]['name']
                
                # Send the email with the codes
                code_text = "\n".join(order_codes)
                
                try:
                    send_code_email(customer_email, product_name, code_text, order_id)
                except Exception as email_err:
                    print(f"Error sending email: {str(email_err)}")
                    # Log email errors
                    db.error_logs.insert_one({
                        "type": "email_error",
                        "timestamp": datetime.now(),
                        "order_id": order_id,
                        "email": customer_email,
                        "error": str(email_err)
                    })
                
                # Save the order with promo code and total price
                order_data = {
                    'order_id': order_id,
                    'product_id': product_id,
                    'product_name': product_name,
                    'email': customer_email,
                    'code': code_text,
                    'timestamp': datetime.now().isoformat(),
                    'payment_id': session.id,
                    'quantity': quantity,
                    'payment_method': 'stripe',
                    'price': unit_price,                  # Unit price after discount
                    'original_price': original_price,     # Original unit price
                    'discount_amount': discount_amount,   # Discount amount per unit
                    'total_price': total_amount_paid,     # Total price paid
                    'promo_code': promo_code              # Add promo code to order data
                }
                save_order(order_data)
                
                # Remove used codes
                for code in order_codes:
                    remove_used_code(product_id, code)
                    
                # Log successful order
                db.webhook_logs.insert_one({
                    "type": "stripe_success",
                    "timestamp": datetime.now(),
                    "order_id": order_id,
                    "session_id": session.id
                })

    return jsonify({"status": "success"})

@app.route('/success')
def success():
    session_id = request.args.get('session_id')
    order_id = request.args.get('order_id')
    customer_email = request.args.get('email')
    payment_method = request.args.get('payment_method')
    
    # Special case for NowPayments
    if payment_method == 'nowpayments':
        # Look for the order using the NowPayments order ID
        if order_id and order_id.startswith('np-'):
            # Get the temporary order data if it exists
            temp_order_data = get_temp_order(order_id)
            
            if temp_order_data:
                try:
                    # Show info about the pending crypto payment
                    return render_template('success.html',
                                          order_id=order_id,
                                          product_name="Your product",
                                          code="Your payment is processing. You will receive an email with your code when the payment is confirmed.",
                                          is_crypto=True,
                                          promo_info=get_promo_info(temp_order_data.get('promo_code', '')))
                except Exception as e:
                    print(f"Error reading temp order data: {str(e)}")
            
            # Look up the order in the completed orders
            order = db.orders.find_one({"payment_id": order_id})
            if order:
                return render_template('success.html',
                                    order_id=order.get('order_id'),
                                    product_name=order.get('product_name'),
                                    code=order.get('code'),
                                    promo_info=get_promo_info(order.get('promo_code', '')))
            
            # If we can't find the order, show a pending message
            return render_template('success.html',
                                order_id=order_id,
                                product_name="Your product",
                                code="Your payment is processing. You will receive an email with your code when the payment is confirmed.",
                                is_crypto=True)
            
    # Handle Stripe session_id
    if session_id:
        try:
            # Retrieve the session from Stripe
            session = stripe.checkout.Session.retrieve(session_id)
            product_id = session.metadata.get('product_id')
            
            # Look up the order in MongoDB
            order = db.orders.find_one({"payment_id": session_id})
            
            if order:
                print(f"Found order by session_id: {session_id}")
                print(f"Order product: {order.get('product_name')}")
                if order.get('code'):
                    print(f"Order code length: {len(order.get('code'))}")
                    newline_count = order.get('code').count('\n')
                    print(f"Newlines in code: {newline_count}")
                
                return render_template('success.html', 
                                     order_id=order.get('order_id'),
                                     product_name=order.get('product_name'),
                                     code=order.get('code'),
                                     promo_info=get_promo_info(order.get('promo_code', '')))
                                     
            # If no order found, try to get it from Stripe
            try:
                # Retrieve session from Stripe again with more details
                session_details = stripe.checkout.Session.retrieve(
                    session_id,
                    expand=['customer', 'line_items']
                )
                
                customer_email = session_details.customer_details.email
                
                # Get quantity
                quantity = 1
                if hasattr(session_details, 'line_items') and session_details.line_items.data:
                    quantity = session_details.line_items.data[0].quantity
                elif session.metadata.get('quantity'):
                    quantity = int(session.metadata.get('quantity', 1))
                
                print(f"Stripe quantity: {quantity}")
                
                # Get promo code from metadata
                promo_code = session.metadata.get('promo_code', '')
                
                # Get original price and discount amount from metadata
                original_price = 0
                discount_amount = 0
                
                if session.metadata.get('original_price'):
                    try:
                        original_price = int(session.metadata.get('original_price'))
                    except (ValueError, TypeError):
                        # If conversion fails, get price from product
                        original_price = get_product_price(product_id)
                else:
                    # Get price from product
                    original_price = get_product_price(product_id)
                    
                if session.metadata.get('discount_amount'):
                    try:
                        discount_amount = int(session.metadata.get('discount_amount'))
                    except (ValueError, TypeError):
                        discount_amount = 0
                
                # Calculate unit price after discount
                unit_price = original_price - discount_amount
                if unit_price < 1:
                    unit_price = 1  # Minimum price of 1 pence
                
                # Load products
                products = load_products()
                
                if product_id and product_id in products:
                    # Get available codes
                    available_codes = get_product_codes(product_id)
                    
                    if available_codes:
                        # Generate order ID
                        order_id = str(uuid.uuid4())
                        
                        if len(available_codes) < quantity:
                            quantity = len(available_codes)
                            
                        # Get codes for this order
                        order_codes = available_codes[:quantity]
                        code_text = "\n".join(order_codes)
                        
                        # Format product name
                        product_name = f"{products[product_id]['name']} (x{quantity})" if quantity > 1 else products[product_id]['name']
                        
                        # Get the amount paid from Stripe
                        total_amount_paid = 0
                        if hasattr(session_details, 'amount_total'):
                            total_amount_paid = session_details.amount_total
                        else:
                            # If not available, calculate based on unit price
                            total_amount_paid = unit_price * quantity
                        
                        # Save the order
                        order_data = {
                            'order_id': order_id,
                            'product_id': product_id,
                            'product_name': product_name,
                            'email': customer_email,
                            'code': code_text,
                            'timestamp': datetime.now().isoformat(),
                            'payment_id': session_id,
                            'quantity': quantity,
                            'payment_method': 'stripe',
                            'price': unit_price,                  # Unit price after discount
                            'original_price': original_price,     # Original unit price
                            'discount_amount': discount_amount,   # Discount amount per unit
                            'total_price': total_amount_paid,     # Total price paid
                            'promo_code': promo_code              # Add promo code to order data
                        }
                        save_order(order_data)
                        
                        # Send email
                        send_code_email(customer_email, product_name, code_text, order_id)
                        
                        # Remove used codes
                        for code in order_codes:
                            remove_used_code(product_id, code)
                        
                        # Display the success page with the code
                        return render_template('success.html', 
                                            order_id=order_id,
                                            product_name=product_name,
                                            code=code_text,
                                            promo_info=get_promo_info(promo_code))
            except Exception as e:
                print(f"Error retrieving Stripe session details: {str(e)}")
                traceback.print_exc()
                
        except Exception as e:
            print(f"Error retrieving session: {str(e)}")
            traceback.print_exc()
    
    # Handle direct order_id
    elif order_id:
        # Look up the order in MongoDB
        order = db.orders.find_one({"order_id": order_id})
        
        if order:
            print(f"Found order by order_id: {order_id}")
            print(f"Order product: {order.get('product_name')}")
            if order.get('code'):
                print(f"Order code length: {len(order.get('code'))}")
                newline_count = order.get('code').count('\n')
                print(f"Newlines in code: {newline_count}")
                print(f"Code snippet: {order.get('code')[:50]}...")
            
            # Make sure we correctly pass all order details
            return render_template('success.html', 
                                 order_id=order_id,
                                 product_name=order.get('product_name'),
                                 code=order.get('code'),
                                 promo_info=get_promo_info(order.get('promo_code', '')))
    
    # If we can't find the order or there was an error, log more details
    if session_id or order_id:
        # Log to MongoDB error collection instead of file
        db.error_logs.insert_one({
            "type": "success_page_error",
            "session_id": session_id,
            "order_id": order_id,
            "email": customer_email,
            "timestamp": datetime.now()
        })
    
    # If we can't find the order, show a generic success page
    return render_template('success.html', 
                         order_id=order_id or "Unknown",
                         product_name="Your product",
                         code="Check your email for the code")

# Helper function to format promo code info for display
def get_promo_info(promo_code):
    """Format promo code info for display in the success template"""
    if not promo_code:
        return ""
    
    return f"<p><strong>Promo Code:</strong> {promo_code}</p>"

@app.route('/get-code')
def get_code():
    """API endpoint to retrieve code information"""
    session_id = request.args.get('session_id')
    
    if not session_id:
        return jsonify({"error": "Missing session_id parameter"}), 400
    
    # Look up the order in MongoDB
    order = db.orders.find_one({"payment_id": session_id})
    
    if order:
        # Remove _id field to avoid serialization issues
        if '_id' in order:
            del order['_id']
            
        return jsonify({
            'code': order.get('code'),
            'product_name': order.get('product_name'),
            'email': order.get('email'),
            'order_id': order.get('order_id'),
            'promo_code': order.get('promo_code', ''),  # Include promo code in response
            'status': 'completed'
        })
    
    # If no order found, try to get it from Stripe
    try:
        # Retrieve session from Stripe
        session = stripe.checkout.Session.retrieve(
            session_id,
            expand=['customer', 'line_items']
        )
        
        customer_email = session.customer_details.email
        product_id = session.metadata.get('product_id')
        
        # Get quantity
        quantity = 1
        if hasattr(session, 'line_items') and session.line_items.data:
            quantity = session.line_items.data[0].quantity
        elif session.metadata.get('quantity'):
            quantity = int(session.metadata.get('quantity', 1))
        
        # Get promo code from metadata
        promo_code = session.metadata.get('promo_code', '')
        
        # Get original price and discount amount from metadata
        original_price = 0
        discount_amount = 0
        
        if session.metadata.get('original_price'):
            try:
                original_price = int(session.metadata.get('original_price'))
            except (ValueError, TypeError):
                # If conversion fails, get price from product
                original_price = get_product_price(product_id)
        else:
            # Get price from product
            original_price = get_product_price(product_id)
            
        if session.metadata.get('discount_amount'):
            try:
                discount_amount = int(session.metadata.get('discount_amount'))
            except (ValueError, TypeError):
                discount_amount = 0
                
        # Calculate unit price after discount
        unit_price = original_price - discount_amount
        if unit_price < 1:
            unit_price = 1  # Minimum price of 1 pence
        
        # Load products
        products = load_products()
        
        if product_id and product_id in products:
            # Get available codes
            available_codes = get_product_codes(product_id)
            
            if available_codes:
                # Generate order ID
                order_id = str(uuid.uuid4())
                
                if len(available_codes) < quantity:
                    quantity = len(available_codes)
                    
                # Get codes for this order
                order_codes = available_codes[:quantity]
                code_text = "\n".join(order_codes)
                
                # Format product name
                product_name = f"{products[product_id]['name']} (x{quantity})" if quantity > 1 else products[product_id]['name']
                
                # Get the amount paid from Stripe
                total_amount_paid = 0
                if hasattr(session, 'amount_total'):
                    total_amount_paid = session.amount_total
                else:
                    # If not available, calculate based on unit price
                    total_amount_paid = unit_price * quantity
                
                # Save the order with promo code
                order_data = {
                    'order_id': order_id,
                    'product_id': product_id,
                    'product_name': product_name,
                    'email': customer_email,
                    'code': code_text,
                    'timestamp': datetime.now().isoformat(),
                    'payment_id': session_id,
                    'quantity': quantity,
                    'payment_method': 'stripe',
                    'price': unit_price,                  # Unit price after discount
                    'original_price': original_price,     # Original unit price
                    'discount_amount': discount_amount,   # Discount amount per unit
                    'total_price': total_amount_paid,     # Total price paid
                    'promo_code': promo_code              # Add promo code to order data
                }
                save_order(order_data)
                
                # Remove used codes
                for code in order_codes:
                    remove_used_code(product_id, code)
                
                # Send email
                send_code_email(customer_email, product_name, code_text, order_id)
                
                return jsonify({
                    'code': code_text,
                    'product_name': product_name,
                    'email': customer_email,
                    'order_id': order_id,
                    'promo_code': promo_code,  # Include promo code in response
                    'status': 'completed'
                })
    except Exception as e:
        print(f"Error retrieving Stripe session: {str(e)}")
        traceback.print_exc()
    
    # Return a fallback response
    return jsonify({
        'code': f"Could not retrieve code. Please contact support with ID: {session_id}",
        'product_name': "Unknown Product",
        'email': "unknown@example.com",
        'order_id': "unknown",
        'promo_code': "",
        'status': 'error'
    }), 404


def send_code_email(recipient, product_name, code, order_id):
    """Send an email with the purchased code using Resend API"""
    try:
        
        db.logs.insert_one({
            "type": "email_env_check",
            "timestamp": datetime.now(),
            "resend_api_key_present": bool(resend_api_key),
            "recipient": recipient,
            "order_id": order_id
        })
        
        if not resend_api_key:
            print("RESEND_API_KEY environment variable is not set")
            
            db.unsent_codes.insert_one({
                "timestamp": datetime.now(),
                "order_id": order_id,
                "email": recipient,
                "code": code
            })
                
            return False
        
        # Check if we have multiple codes
        multiple_codes = '\n' in code
        code_list = code.strip().split('\n') if multiple_codes else [code]
        
        # Format codes HTML
        if multiple_codes:
            codes_html = ""
            for i, single_code in enumerate(code_list):
                codes_html += f'<div class="code">{single_code}</div>'
        else:
            codes_html = f'<div class="code">{code}</div>'
            
        # Create the email body
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #f8f9fa; padding: 10px; text-align: center; }}
                .content {{ padding: 20px; }}
                .code {{ background-color: #f0f0f0; padding: 10px; font-family: monospace; font-size: 18px; text-align: center; margin: 15px 0; }}
                .footer {{ text-align: center; font-size: 12px; color: #6c757d; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Thank you for your purchase!</h1>
                </div>
                <div class="content">
                    <p>Hello,</p>
                    <p>Thank you for purchasing <strong>{product_name}</strong>.</p>
                    <p>Here {'are your discount codes' if multiple_codes else 'is your discount code'}:</p>
                    {codes_html}
                    <p>Order ID: {order_id}</p>
                    <p>If you have any questions or need support, please contact our <a href="https://t.me/eats4u_bot">support bot</a>.</p>
                </div>
                <div class="footer">
                    <p>&copy; eats4u. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
            
        db.api_logs.insert_one({
            "type": "email_api_request",
            "timestamp": datetime.now(),
            "recipient": recipient,
            "order_id": order_id,
            "from_email": from_email,
            "multiple_codes": multiple_codes
        })
        
        # Prepare request data for the Resend API
        request_data = {
            "from": f"eats4u <{from_email}>",
            "to": recipient,
            "subject": f"Your {product_name} Code{'s' if multiple_codes else ''}",
            "html": html_content
        }
        
        # Send email using Resend API
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {resend_api_key}",
                "Content-Type": "application/json"
            },
            json=request_data
        )
        
        db.api_logs.insert_one({
            "type": "email_api_response",
            "timestamp": datetime.now(),
            "recipient": recipient,
            "status_code": response.status_code,
            "response_text": response.text
        })
        
        # Check response
        if response.status_code == 200:
            print(f"Email sent successfully to {recipient}")
            
            db.logs.insert_one({
                "type": "email_sent",
                "timestamp": datetime.now(),
                "recipient": recipient,
                "order_id": order_id
            })
                
            return True
        else:
            print(f"Failed to send email: {response.text}")
            
            db.error_logs.insert_one({
                "type": "email_api_error",
                "timestamp": datetime.now(),
                "order_id": order_id,
                "error": response.text
            })
                
            # Always save the code to backup log in case of failure
            try:
                # Create a log message with timestamp
                timestamp = datetime.now().isoformat()
                log_message = f"""
                --- EMAIL LOG [{timestamp}] ---
                To: {recipient}
                Subject: Your {product_name} Order
                
                Body:
                Thank you for purchasing {product_name}
                Your Code{'s' if multiple_codes else ''}: {code}
                Order ID: {order_id}
                
                Note: This is a backup log because email sending failed.
                --------------------------
                """
                
                # Print to console
                print(log_message)
                
                # Write to a log file
                db.email_backups.insert_one({
                    "timestamp": datetime.now(),
                    "recipient": recipient,
                    "subject": f"Your {product_name} Order",
                    "body": code,
                    "order_id": order_id,
                    "reason": "Email sending failed"
                })
            except Exception as log_err:
                print(f"Could not write to log file: {str(log_err)}")
                
            return False
            
    except Exception as e:
        print(f"Error sending email: {str(e)}")

        db.error_logs.insert_one({
            "type": "email_error",
            "timestamp": datetime.now(),
            "order_id": order_id,
            "email": recipient,
            "error": str(e)
        })
            
        db.logs.insert_one({
            "type": "email_fallback",
            "timestamp": datetime.now(),
            "order_id": order_id,
            "email": recipient,
            "code": code
        })
        
        return False

@app.errorhandler(404)
def page_not_found(e):
    """Custom 404 error handler"""
    return send_from_directory('.', '404.html'), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    setup_mongodb_indexes()
    app.run(host='0.0.0.0', port=port)