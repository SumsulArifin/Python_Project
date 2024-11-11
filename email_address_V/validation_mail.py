import smtplib
import dns.resolver
import re
from email_validator import validate_email, EmailNotValidError
from concurrent.futures import ThreadPoolExecutor

# List of known disposable email domains (temporary email services)
TEMP_EMAIL_DOMAINS = [
    "tempmail.org",
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "temp-mail.org",
    "throwawaymail.com",
    "tempmail.com",
    "dispostable.com",
    "maildrop.cc",
    "trashmail.com",
    "getnada.com",
    "fakemailgenerator.com",
    "mailcatch.com",
    "mytemp.email",
    "anypng.com",
    "mailsac.com",
    "mailnesia.com",
    "yopmail.com",
    "tempmail.net",
    "mailinator.org",
]

# Regex pattern for detecting disposable email address services
TEMP_EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@(.*)$")


# 1. Syntax Validation using email-validator
def validate_email_syntax(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False


# 2. Check if the email is from a known temporary email provider
def is_temp_email(email):
    domain = email.split("@")[-1]

    # Check against known disposable email domains (including subdomains)
    if domain in TEMP_EMAIL_DOMAINS:
        return True

    # Check if the email domain has known temporary email patterns
    match = TEMP_EMAIL_PATTERN.match(email)
    if match:
        subdomain = match.group(1)
        # Check if subdomain matches known temporary email providers
        if any(temp in subdomain for temp in TEMP_EMAIL_DOMAINS):
            return True
    return False


# 3. Domain Validation using dnspython
def check_domain_exists(email):
    domain = email.split("@")[-1]
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False


# 4. SMTP Email Validation
def smtp_validate_email(email):
    domain = email.split("@")[1]

    try:
        # Look up the MX records for the domain
        mx_records = dns.resolver.resolve(domain, "MX")
        mx_record = str(mx_records[0].exchange)  # Get the primary mail server

        # Connect to the SMTP server
        server = smtplib.SMTP(mx_record, timeout=10)
        server.set_debuglevel(0)  # Disable debug output

        # Greet the server
        server.helo()

        # Send a 'MAIL FROM' command
        server.mail("s.arifinoriginal@gmail.com")  # This can be any valid email address
        code, message = server.rcpt(email)

        # If the server responds with 250, the email is valid
        if code == 250:
            server.quit()
            return True
        else:
            server.quit()
            return False
    except Exception as e:
        print(f"SMTP error for {email}: {e}")
        return False


# 5. Validate Bulk Emails
def validate_bulk_emails(email_list):
    valid_emails = []
    invalid_emails = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(validate_email_syntax, email): email for email in email_list
        }

        for future in futures:
            email = futures[future]
            try:
                # Check if the email is from a temporary provider
                if is_temp_email(email):
                    invalid_emails.append(email)
                # If it's not from a temporary email provider, validate email syntax and domain existence
                elif validate_email_syntax(email):
                    if check_domain_exists(email):
                        # Use SMTP verification for more reliable validation
                        if smtp_validate_email(email):
                            valid_emails.append(email)
                        else:
                            invalid_emails.append(email)
                    else:
                        invalid_emails.append(email)
                else:
                    invalid_emails.append(email)
            except Exception as e:
                invalid_emails.append(email)
                print(f"Error validating {email}: {str(e)}")

    return valid_emails, invalid_emails


# Function to run the script
def main():
    emails = [
        "user@example.com",  # Valid
        "invalid-email",  # Invalid
        "test@domain.com",  # Valid
        "hello@tempmail.org",  # Invalid (Temporary email)
        "temp@trashmail.com",  # Invalid (Temporary email)
        "user@mailinator.com",  # Invalid (Temporary email)
        "sabekig561@anypng.com",  # Invalid (Temp-Mail)
        "hevapi2099@anypng.com",  # Invalid (Temp-Mail)
        "imranarifin03@gmail.com",  # Valid
        "imranarifin033@gmail.com",  # Invalid (likely non-existent)
        "jotoxet772@gianes.com",
    ]

    valid, invalid = validate_bulk_emails(emails)

    print("Valid emails:", valid)
    print("Invalid emails:", invalid)


if __name__ == "__main__":
    main()
