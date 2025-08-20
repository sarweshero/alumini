# backend/api/utils/email.py
from django.core.mail import EmailMessage, get_connection
from typing import List, Dict


def send_messages_batch(subject: str, body: str, from_email: str, recipient_list: List[str], attachments_meta: List[Dict] = None) -> int:
    """
    Build one EmailMessage per recipient, attach files from disk, and send them using a single SMTP connection.
    Returns number of messages successfully sent (as reported by backend).
    attachments_meta: list of {'path': '/tmp/...', 'name': 'file.png', 'content_type': 'image/png'}
    """
    messages = []
    attachments_meta = attachments_meta or []

    for recipient in recipient_list:
        msg = EmailMessage(subject=subject, body=body, from_email=from_email, to=[recipient])
        # Attach files from disk
        for a in attachments_meta:
            path = a.get("path")
            if path:
                try:
                    with open(path, "rb") as fh:
                        msg.attach(a.get("name") or path.split("/")[-1], fh.read(), a.get("content_type"))
                except Exception:
                    # If attachment cannot be read, skip it for this recipient
                    continue
        messages.append(msg)

    if not messages:
        return 0

    # Reuse a single SMTP connection for the whole batch
    connection = get_connection()
    try:
        connection.open()
        sent_count = connection.send_messages(messages)
    finally:
        try:
            connection.close()
        except Exception:
            pass

    return sent_count
