from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import logging
import os
import uuid
from decimal import Decimal
from dotenv import load_dotenv
from botocore.exceptions import ClientError

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'temporary_key_for_development')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Table Names
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'FurnishFusion_Users')
PRODUCTS_TABLE_NAME = os.environ.get('PRODUCTS_TABLE_NAME', 'FurnishFusion_Products')
ORDERS_TABLE_NAME = os.environ.get('ORDERS_TABLE_NAME', 'FurnishFusion_Orders')
CART_TABLE_NAME = os.environ.get('CART_TABLE_NAME', 'FurnishFusion_Cart')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'True').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
products_table = dynamodb.Table(PRODUCTS_TABLE_NAME)
orders_table = dynamodb.Table(ORDERS_TABLE_NAME)
cart_table = dynamodb.Table(CART_TABLE_NAME)

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("furnishfusion.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def send_sns_notification(message, subject="FurnishFusion Notification"):
    """Send SNS notification"""
    if not ENABLE_SNS or not SNS_TOPIC_ARN:
        logger.info(f"SNS disabled or no topic ARN. Message: {message}")
        return
    
    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS notification sent: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")

def require_login(f):
    """Decorator to require login"""
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def get_user_by_id(user_id):
    """Get user by ID from DynamoDB"""
    try:
        response = users_table.get_item(Key={'user_id': user_id})
        return response.get('Item')
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {str(e)}")
        return None

def get_user_by_email(email):
    """Get user by email from DynamoDB"""
    try:
        response = users_table.scan(
            FilterExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except Exception as e:
        logger.error(f"Error getting user by email {email}: {str(e)}")
        return None

# ---------------------------------------
# Routes - Authentication
# ---------------------------------------
@app.route('/')
def home():
    """Home page with featured products"""
    try:
        # Get featured products (limit to 6)
        response = products_table.scan(Limit=6)
        products = response.get('Items', [])
        
        return render_template('home.html', products=products)
    except Exception as e:
        logger.error(f"Error loading home page: {str(e)}")
        flash('Error loading products', 'error')
        return render_template('home.html', products=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        try:
            email = request.form['email'].lower().strip()
            password = request.form['password']
            name = request.form['name'].strip()
            phone = request.form.get('phone', '').strip()
            address = request.form.get('address', '').strip()
            
            # Validate input
            if not all([email, password, name]):
                flash('Email, password, and name are required', 'error')
                return render_template('register.html')
            
            # Check if user already exists
            existing_user = get_user_by_email(email)
            if existing_user:
                flash('Email already registered', 'error')
                return render_template('register.html')
            
            # Create new user
            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(password)
            
            user_data = {
                'user_id': user_id,
                'email': email,
                'password': hashed_password,
                'name': name,
                'phone': phone,
                'address': address,
                'created_at': datetime.now().isoformat(),
                'user_type': 'customer'
            }
            
            users_table.put_item(Item=user_data)
            
            # Send welcome notification
            send_sns_notification(
                f"New user registered: {name} ({email})",
                "New User Registration - FurnishFusion"
            )
            
            flash('Registration successful! Please log in.', 'success')
            logger.info(f"New user registered: {email}")
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        try:
            email = request.form['email'].lower().strip()
            password = request.form['password']
            
            user = get_user_by_email(email)
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['user_name'] = user['name']
                session['user_type'] = user.get('user_type', 'customer')
                
                flash(f'Welcome back, {user["name"]}!', 'success')
                logger.info(f"User logged in: {email}")
                
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('home'))

# ---------------------------------------
# Routes - Dashboard
# ---------------------------------------
@app.route('/dashboard')
@require_login
def dashboard():
    """User dashboard"""
    try:
        user = get_user_by_id(session['user_id'])
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('logout'))
        
        # Get recent orders
        response = orders_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']},
            Limit=5
        )
        recent_orders = response.get('Items', [])
        
        # Sort by created_at descending
        recent_orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template('dashboard.html', user=user, recent_orders=recent_orders)
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('home'))

# ---------------------------------------
# Routes - Products
# ---------------------------------------
@app.route('/products')
def products():
    """Display all products"""
    try:
        category = request.args.get('category', '')
        search = request.args.get('search', '')
        
        if category:
            response = products_table.scan(
                FilterExpression='category = :category',
                ExpressionAttributeValues={':category': category}
            )
        elif search:
            response = products_table.scan(
                FilterExpression='contains(#name, :search) OR contains(description, :search)',
                ExpressionAttributeNames={'#name': 'name'},
                ExpressionAttributeValues={':search': search}
            )
        else:
            response = products_table.scan()
        
        products_list = response.get('Items', [])
        
        # Convert Decimal types for each product
        for product in products_list:
            if 'price' in product:
                product['price'] = float(product['price'])
            if 'stock' in product:
                product['stock'] = int(product['stock'])
        
        # Get unique categories for filter
        categories_response = products_table.scan(
            ProjectionExpression='category'
        )
        categories = list(set([item.get('category', '') for item in categories_response.get('Items', []) if item.get('category')]))
        
        return render_template('products.html', products=products_list, categories=categories, 
                             current_category=category, search_term=search)
        
    except Exception as e:
        logger.error(f"Products error: {str(e)}")
        flash('Error loading products', 'error')
        return render_template('products.html', products=[], categories=[])

@app.route('/product/<product_id>')
def product_detail(product_id):
    """Product detail page"""
    try:
        response = products_table.get_item(Key={'product_id': product_id})
        product = response.get('Item')
        
        if not product:
            flash('Product not found', 'error')
            return redirect(url_for('products'))
        
        # Convert Decimal fields to appropriate types for template use
        if 'stock' in product:
            product['stock'] = int(product['stock'])
        if 'price' in product:
            product['price'] = float(product['price'])  # Keep as float for formatting
        
        return render_template('product_detail.html', product=product)
        
    except Exception as e:
        logger.error(f"Product detail error: {str(e)}")
        flash('Error loading product', 'error')
        return redirect(url_for('products'))

@app.route('/add_product', methods=['GET', 'POST'])
@require_login
def add_product():
    """Add new product (admin only)"""
    if session.get('user_type') != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            # Validate and convert input data
            name = request.form['name'].strip()
            description = request.form['description'].strip()
            price = request.form['price'].strip()
            category = request.form['category'].strip()
            stock = request.form['stock'].strip()
            
            if not all([name, description, price, category, stock]):
                flash('All fields are required', 'error')
                return render_template('add_product.html')
            
            # Convert and validate numeric fields
            try:
                price_decimal = Decimal(str(price))
                stock_int = int(stock)
                
                if price_decimal <= 0:
                    flash('Price must be greater than 0', 'error')
                    return render_template('add_product.html')
                
                if stock_int < 0:
                    flash('Stock cannot be negative', 'error')
                    return render_template('add_product.html')
                    
            except (ValueError, TypeError):
                flash('Invalid price or stock value', 'error')
                return render_template('add_product.html')
            
            product_data = {
                'product_id': str(uuid.uuid4()),
                'name': name,
                'description': description,
                'price': price_decimal,
                'category': category,
                'stock': stock_int,
                'created_at': datetime.now().isoformat(),
                'created_by': session['user_id']
            }
            
            products_table.put_item(Item=product_data)
            
            # Send notification
            send_sns_notification(
                f"New product added: {product_data['name']} - ${product_data['price']}",
                "New Product Added - FurnishFusion"
            )
            
            flash('Product added successfully!', 'success')
            logger.info(f"Product added: {product_data['name']}")
            return redirect(url_for('products'))
            
        except Exception as e:
            logger.error(f"Add product error: {str(e)}")
            flash('Error adding product', 'error')
    
    return render_template('add_product.html')

# ---------------------------------------
# Routes - Cart
# ---------------------------------------
@app.route('/add_to_cart', methods=['POST'])
@require_login
def add_to_cart():
    """Add item to cart"""
    try:
        product_id = request.form['product_id']
        quantity = int(request.form.get('quantity', 1))
        
        # Get product details
        product_response = products_table.get_item(Key={'product_id': product_id})
        product = product_response.get('Item')
        
        if not product:
            flash('Product not found', 'error')
            return redirect(url_for('products'))
        
        # Check stock
        if quantity > product.get('stock', 0):
            flash('Not enough stock available', 'error')
            return redirect(url_for('product_detail', product_id=product_id))
        
        # Check if item already in cart
        try:
            cart_response = cart_table.get_item(
                Key={'user_id': session['user_id'], 'product_id': product_id}
            )
            existing_item = cart_response.get('Item')
            
            if existing_item:
                # Update quantity
                new_quantity = existing_item['quantity'] + quantity
                if new_quantity > product.get('stock', 0):
                    flash('Not enough stock available', 'error')
                    return redirect(url_for('product_detail', product_id=product_id))
                
                cart_table.update_item(
                    Key={'user_id': session['user_id'], 'product_id': product_id},
                    UpdateExpression='SET quantity = :quantity, updated_at = :updated_at',
                    ExpressionAttributeValues={
                        ':quantity': new_quantity,
                        ':updated_at': datetime.now().isoformat()
                    }
                )
            else:
                # Add new item to cart
                cart_item = {
                    'user_id': session['user_id'],
                    'product_id': product_id,
                    'quantity': quantity,
                    'added_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                }
                cart_table.put_item(Item=cart_item)
            
            flash('Item added to cart!', 'success')
            
        except Exception as e:
            logger.error(f"Cart operation error: {str(e)}")
            flash('Error adding to cart', 'error')
        
        return redirect(url_for('product_detail', product_id=product_id))
        
    except Exception as e:
        logger.error(f"Add to cart error: {str(e)}")
        flash('Error adding to cart', 'error')
        return redirect(url_for('products'))

@app.route('/cart')
@require_login
def view_cart():
    """View cart"""
    try:
        # Get cart items
        response = cart_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        cart_items = response.get('Items', [])
        
        # Get product details for each cart item
        cart_with_products = []
        total_amount = Decimal('0')
        
        for item in cart_items:
            product_response = products_table.get_item(Key={'product_id': item['product_id']})
            product = product_response.get('Item')
            
            if product:
                item_total = Decimal(str(product['price'])) * item['quantity']
                cart_with_products.append({
                    'cart_item': item,
                    'product': product,
                    'item_total': item_total
                })
                total_amount += item_total
        
        return render_template('cart.html', cart_items=cart_with_products, total_amount=total_amount)
        
    except Exception as e:
        logger.error(f"View cart error: {str(e)}")
        flash('Error loading cart', 'error')
        return render_template('cart.html', cart_items=[], total_amount=0)

@app.route('/remove_from_cart', methods=['POST'])
@require_login
def remove_from_cart():
    """Remove item from cart"""
    try:
        product_id = request.form['product_id']
        
        cart_table.delete_item(
            Key={'user_id': session['user_id'], 'product_id': product_id}
        )
        
        flash('Item removed from cart', 'success')
        
    except Exception as e:
        logger.error(f"Remove from cart error: {str(e)}")
        flash('Error removing item from cart', 'error')
    
    return redirect(url_for('view_cart'))

# ---------------------------------------
# Routes - Orders
# ---------------------------------------
@app.route('/checkout')
@require_login
def checkout():
    """Checkout page"""
    try:
        # Get cart items
        response = cart_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        cart_items = response.get('Items', [])
        
        if not cart_items:
            flash('Your cart is empty', 'error')
            return redirect(url_for('view_cart'))
        
        # Get product details and calculate total
        cart_with_products = []
        total_amount = Decimal('0')
        
        for item in cart_items:
            product_response = products_table.get_item(Key={'product_id': item['product_id']})
            product = product_response.get('Item')
            
            if product:
                item_total = Decimal(str(product['price'])) * item['quantity']
                cart_with_products.append({
                    'cart_item': item,
                    'product': product,
                    'item_total': item_total
                })
                total_amount += item_total
        
        user = get_user_by_id(session['user_id'])
        
        return render_template('checkout.html', cart_items=cart_with_products, 
                             total_amount=total_amount, user=user)
        
    except Exception as e:
        logger.error(f"Checkout error: {str(e)}")
        flash('Error loading checkout', 'error')
        return redirect(url_for('view_cart'))
@app.route('/place_order', methods=['POST'])
@require_login
def place_order():
    """Place order"""
    try:
        # Get cart items
        response = cart_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        cart_items = response.get('Items', [])
        
        if not cart_items:
            flash('Your cart is empty', 'error')
            return redirect(url_for('view_cart'))
        
        # Calculate total and prepare order items
        order_items = []
        total_amount = Decimal('0')
        
        for item in cart_items:
            product_response = products_table.get_item(Key={'product_id': item['product_id']})
            product = product_response.get('Item')
            
            if product:
                # Check stock availability
                if item['quantity'] > product.get('stock', 0):
                    flash(f'Not enough stock for {product["name"]}', 'error')
                    return redirect(url_for('view_cart'))
                
                # Use Decimal for calculations
                product_price = Decimal(str(product['price']))
                item_quantity = int(item['quantity'])
                item_total = product_price * item_quantity
                
                order_items.append({
                    'product_id': item['product_id'],
                    'product_name': product['name'],
                    'price': product_price,  # Keep as Decimal for DynamoDB
                    'quantity': item_quantity,
                    'item_total': item_total  # Keep as Decimal for DynamoDB
                })
                total_amount += item_total
        
        # Create order
        order_id = str(uuid.uuid4())
        order_data = {
            'order_id': order_id,
            'user_id': session['user_id'],
            'items': order_items,  # Changed back to 'items' to match template
            'total_amount': total_amount,  # Keep as Decimal for DynamoDB
            'status': 'pending',
            'delivery_address': request.form.get('delivery_address', ''),
            'phone': request.form.get('phone', ''),
            'created_at': datetime.now().isoformat(),
            'estimated_delivery': (datetime.now() + timedelta(days=7)).isoformat()
        }
        
        orders_table.put_item(Item=order_data)
        
        # Update product stock and clear cart
        for item in cart_items:
            product_response = products_table.get_item(Key={'product_id': item['product_id']})
            product = product_response.get('Item')
            
            if product:
                new_stock = product.get('stock', 0) - item['quantity']
                products_table.update_item(
                    Key={'product_id': item['product_id']},
                    UpdateExpression='SET stock = :stock',
                    ExpressionAttributeValues={':stock': max(0, new_stock)}
                )
            
            # Remove from cart
            cart_table.delete_item(
                Key={'user_id': session['user_id'], 'product_id': item['product_id']}
            )
        
        # Send order confirmation notification
        try:
            user = get_user_by_id(session['user_id'])
            send_sns_notification(
                f"New order placed by {user['name']} - Order ID: {order_id} - Total: ${total_amount}",
                "New Order Placed - FurnishFusion"
            )
        except Exception as sns_error:
            logger.warning(f"SNS notification failed: {str(sns_error)}")
        
        flash('Order placed successfully!', 'success')
        logger.info(f"Order placed: {order_id} by user {session['user_id']}")
        return redirect(url_for('order_confirmation', order_id=order_id))
        
    except Exception as e:
        logger.error(f"Place order error: {str(e)}")
        flash('Error placing order', 'error')
        return redirect(url_for('checkout'))
@app.route('/order_confirmation/<order_id>')
@require_login
def order_confirmation(order_id):
    """Order confirmation page"""
    try:
        response = orders_table.get_item(Key={'order_id': order_id})
        order = response.get('Item')
        
        # Add debugging
        logger.info(f"Order response: {response}")
        logger.info(f"Order type: {type(order)}")
        logger.info(f"Order content: {order}")
        
        if not order or order.get('user_id') != session['user_id']:
            flash('Order not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Convert Decimal types for template rendering
        if 'total_amount' in order:
            order['total_amount'] = float(order['total_amount'])
        
        # Ensure items exists and is iterable
        items = order.get('items', [])
        if not isinstance(items, list):
            logger.error(f"Items is not a list: {type(items)} - {items}")
            items = []
        
        # Convert Decimal values in order items for template rendering
        for item in items:
            if isinstance(item, dict):  # Ensure item is a dictionary
                if 'price' in item:
                    item['price'] = float(item['price'])
                if 'item_total' in item:
                    item['item_total'] = float(item['item_total'])
                if 'quantity' in item:
                    item['quantity'] = int(item['quantity'])
            else:
                logger.error(f"Item is not a dict: {type(item)} - {item}")
        
        # Update the order with processed items
        order['items'] = items
        
        return render_template('order_confirmation.html', order=order)
        
    except Exception as e:
        logger.error(f"Order confirmation error: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        flash('Error loading order confirmation', 'error')
        return redirect(url_for('dashboard'))
        
@app.route('/orders')
@require_login
def orders():
    """View all user orders"""
    try:
        logger.info(f"Getting orders for user: {session['user_id']}")
        
        response = orders_table.scan(
            FilterExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        
        logger.info(f"DynamoDB response type: {type(response)}")
        logger.info(f"DynamoDB response keys: {list(response.keys()) if hasattr(response, 'keys') else 'No keys'}")
        
        user_orders = response.get('Items', [])
        logger.info(f"User orders type: {type(user_orders)}")
        logger.info(f"User orders length: {len(user_orders) if hasattr(user_orders, '__len__') else 'No len'}")
        
        # Convert Decimal types and sort by created_at descending
        for i, order in enumerate(user_orders):
            logger.info(f"Processing order {i}: type={type(order)}")
            
            if hasattr(order, 'get') and callable(order.get):
                if 'total_amount' in order:
                    order['total_amount'] = float(order['total_amount'])
                
                # Ensure items exists and convert Decimal types
                if 'items' not in order:
                    order['items'] = []
                
                items = order.get('items', [])
                logger.info(f"Order {i} items type: {type(items)}")
                
                if isinstance(items, list):
                    for j, item in enumerate(items):
                        logger.info(f"Order {i}, item {j} type: {type(item)}")
                        if isinstance(item, dict):
                            if 'price' in item:
                                item['price'] = float(item['price'])
                            if 'item_total' in item:
                                item['item_total'] = float(item['item_total'])
                            if 'quantity' in item:
                                item['quantity'] = int(item['quantity'])
                        else:
                            logger.error(f"Item {j} is not a dict: {type(item)}")
                else:
                    logger.error(f"Items is not a list: {type(items)}")
            else:
                logger.error(f"Order {i} is not a dict or doesn't have get method: {type(order)}")
        
        # Sort orders
        if isinstance(user_orders, list):
            user_orders.sort(key=lambda x: x.get('created_at', '') if hasattr(x, 'get') else '', reverse=True)
        
        logger.info(f"Returning {len(user_orders) if hasattr(user_orders, '__len__') else 'unknown count'} orders")
        return render_template('orders.html', orders=user_orders)
        
    except Exception as e:
        logger.error(f"Orders error: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        flash('Error loading orders', 'error')
        return render_template('orders.html', orders=[])
# ---------------------------------------
# API Routes
# ---------------------------------------
@app.route('/api/products')
def api_products():
    """API endpoint for products"""
    try:
        response = products_table.scan()
        products_list = response.get('Items', [])
        
        # Convert Decimal to float for JSON serialization
        for product in products_list:
            if 'price' in product:
                product['price'] = float(product['price'])
        
        return jsonify({
            'status': 'success',
            'products': products_list
        })
        
    except Exception as e:
        logger.error(f"API products error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Error fetching products'
        }), 500

@app.route('/api/product/<product_id>')
def api_product_detail(product_id):
    """API endpoint for single product"""
    try:
        response = products_table.get_item(Key={'product_id': product_id})
        product = response.get('Item')
        
        if not product:
            return jsonify({
                'status': 'error',
                'message': 'Product not found'
            }), 404
        
        # Convert Decimal to float for JSON serialization
        if 'price' in product:
            product['price'] = float(product['price'])
        
        return jsonify({
            'status': 'success',
            'product': product
        })
        
    except Exception as e:
        logger.error(f"API product detail error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Error fetching product'
        }), 500

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# ---------------------------------------
# Initialize Sample Data (for demo)
# ---------------------------------------
def initialize_sample_data():
    """Initialize sample products for demo"""
    try:
        # Check if products already exist
        response = products_table.scan(Limit=1)
        if response.get('Items'):
            return  # Products already exist
        
        sample_products = [
            {
                'product_id': str(uuid.uuid4()),
                'name': 'Modern Sofa Set',
                'description': 'Comfortable 3-seater sofa with premium fabric upholstery',
                'price': Decimal('899.99'),
                'category': 'Living Room',
                'stock': 10,
                'created_at': datetime.now().isoformat()
            },
            {
                'product_id': str(uuid.uuid4()),
                'name': 'Dining Table Set',
                'description': 'Elegant wooden dining table with 6 chairs',
                'price': Decimal('1299.99'),
                'category': 'Dining Room',
                'stock': 5,
                'created_at': datetime.now().isoformat()
            },
            {
                'product_id': str(uuid.uuid4()),
                'name': 'Queen Size Bed',
                'description': 'Luxury queen size bed with headboard',
                'price': Decimal('699.99'),
                'category': 'Bedroom',
                'stock': 8,
                'created_at': datetime.now().isoformat()
            },
            {
                'product_id': str(uuid.uuid4()),
                'name': 'Coffee Table',
                'description': 'Glass top coffee table with wooden legs',
                'price': Decimal('299.99'),
                'category': 'Living Room',
                'stock': 15,
                'created_at': datetime.now().isoformat()
            },
            {
                'product_id': str(uuid.uuid4()),
                'name': 'Office Chair',
                'description': 'Ergonomic office chair with lumbar support',
                'price': Decimal('199.99'),
                'category': 'Office',
                'stock': 20,
                'created_at': datetime.now().isoformat()
            }
        ]
        
        for product in sample_products:
            products_table.put_item(Item=product)
        
        logger.info("Sample products initialized")
        
    except Exception as e:
        logger.error(f"Error initializing sample data: {str(e)}")

# ---------------------------------------
# Application Entry Point
# ---------------------------------------
if __name__ == '__main__':
    # Initialize sample data
    initialize_sample_data()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
