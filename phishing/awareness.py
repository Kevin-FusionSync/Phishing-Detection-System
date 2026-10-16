ACTIONS = {
    "High": [
        "Do not click any links or open any attachments in this message.",
        "Do not reply or provide any personal, financial or login information.",
        "Report the message to your IT/security team or use your mail client's 'Report phishing' option.",
        "If you already clicked or entered details, change your password immediately and enable multi-factor authentication.",
        "Delete the message after reporting it.",
    ],
    "Medium": [
        "Treat this message with caution until you can confirm it is genuine.",
        "Verify the request by contacting the sender through a phone number or website you already trust.",
        "Hover over links to check the real destination before clicking.",
        "Do not download attachments you were not expecting.",
    ],
    "Low": [
        "No strong phishing signs were found, but stay alert.",
        "Still verify any unexpected requests for money, credentials or personal data.",
        "Keep your browser, email client and antivirus up to date.",
    ],
}

CATEGORY_TIPS = {
    "URL": "Check the domain carefully. Attackers register names like 'paypa1.com' or 'secure-paypal-login.xyz' that look close to the real thing.",
    "Language": "Pressure and urgency are classic manipulation tactics. Real organisations rarely threaten to close your account within hours.",
    "Sender": "The display name can say anything. Always look at the actual email address and the domain after the @ sign.",
    "Content": "Legitimate companies will not ask for passwords, PINs, card numbers or one-time codes by email.",
}

GENERAL_TIPS = [
    ("Inspect the sender", "Look at the full email address, not just the display name. Watch for misspelled company names and free email providers posing as businesses."),
    ("Hover before you click", "Hover over a link to see where it really goes. If the text and the destination differ, do not click."),
    ("Watch for urgency", "Messages that demand immediate action, threaten penalties or promise rewards are designed to make you act before you think."),
    ("Never share secrets by email", "Passwords, MFA codes, bank details and SSNs should never be requested or sent by email."),
    ("Be careful with attachments", "Unexpected .zip, .exe, .iso, .html or macro-enabled Office files are common malware carriers."),
    ("Verify independently", "If a message looks important, contact the organisation using a phone number or website you already know, not the one in the email."),
    ("Use multi-factor authentication", "MFA stops most account takeovers even if your password is stolen."),
    ("Report it", "Reporting phishing helps your security team block the campaign for everyone else."),
]

QUIZ = [
    {
        "question": "An email from 'PayPal Support <support@paypa1-secure.com>' asks you to confirm your account. What is the biggest red flag?",
        "options": ["The greeting", "The sender domain", "The email length", "It mentions PayPal"],
        "answer": "The sender domain",
        "explanation": "'paypa1-secure.com' replaces the letter l with the number 1 and is not an official PayPal domain.",
    },
    {
        "question": "A link shows 'https://www.mybank.com' but hovering reveals 'http://193.42.11.8/login'. What should you do?",
        "options": ["Click it, the text says mybank.com", "Do not click and report the email", "Reply asking if it is real", "Forward it to friends"],
        "answer": "Do not click and report the email",
        "explanation": "The visible text and the real destination differ, and the destination is a raw IP address.",
    },
    {
        "question": "Your 'IT department' emails from a Gmail address asking for your password to fix your mailbox. Is this normal?",
        "options": ["Yes, IT needs passwords", "No, IT never needs your password by email", "Only if it is urgent", "Only on weekdays"],
        "answer": "No, IT never needs your password by email",
        "explanation": "Legitimate IT staff never ask for your password, and they do not use free email services.",
    },
    {
        "question": "Which attachment is the most suspicious in an unexpected invoice email?",
        "options": ["invoice.pdf", "invoice.docm", "photo.jpg", "notes.txt"],
        "answer": "invoice.docm",
        "explanation": ".docm files can contain macros that run malicious code once 'Enable content' is clicked.",
    },
    {
        "question": "You entered your password on a page you now think was fake. What is the first thing to do?",
        "options": ["Wait and see", "Change your password and enable MFA", "Delete the email only", "Clear your browser history"],
        "answer": "Change your password and enable MFA",
        "explanation": "Changing the password quickly and turning on MFA limits what an attacker can do with stolen credentials.",
    },
]


def recommended_actions(level):
    return ACTIONS.get(level, ACTIONS["Low"])


def tips_for(findings):
    categories = []
    for f in findings:
        if f.category not in categories:
            categories.append(f.category)
    return [CATEGORY_TIPS[c] for c in categories if c in CATEGORY_TIPS]
