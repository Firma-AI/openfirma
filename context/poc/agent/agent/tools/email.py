import os
from datetime import datetime, timezone

from agents import function_tool


@function_tool
def send_email(email_address: str, subject: str, body: str) -> str:
    """Send an email to the specified address."""
    try:
        os.makedirs("/data/emails", exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"/data/emails/{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(f"To: {email_address}\n")
            f.write(f"Subject: {subject}\n")
            f.write(f"Date: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"\n{body}\n")
        return f"Email sent to {email_address} (saved to {filename})"
    except Exception as e:
        return f"Error sending email: {e}"
