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

def recommended_actions(level):
    return ACTIONS.get(level, ACTIONS["Low"])


def tips_for(findings):
    categories = []
    for f in findings:
        if f.category not in categories:
            categories.append(f.category)
    return [CATEGORY_TIPS[c] for c in categories if c in CATEGORY_TIPS]
