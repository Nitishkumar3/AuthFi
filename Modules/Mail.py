import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def SendMail(subject, body, to):
    email = "secureconnect@techmedok.com"
    password = "fajVY0vNBcQuUUG0T7NVyf4cxEahfmvsws6cZuqCh2UhbBv33wB6VWfvxgcrqa8P"
    message = MIMEMultipart()
    message["From"] = f"Secure Connect <{email}>"
    message["To"] = to
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))
    with smtplib.SMTP_SSL("smtp.yandex.com", 465) as server:
        server.login(email, password)
        server.sendmail(email, to, message.as_string())
    return True