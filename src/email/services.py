import smtplib
from email.mime.text import MIMEText
from fastapi import HTTPException
from pydantic import EmailStr

from src.settings import settings


class EmailServices:
    @staticmethod
    def send_code(
            to_email: EmailStr,
            code: str,
    ):
        msg = MIMEText(code)
        msg['Subject'] = "Ваш одноразовый пароль"
        msg['From'] = settings.email.from_address
        msg['To'] = to_email
        try:
            with smtplib.SMTP('smtp.yandex.ru', 587) as server:
                server.starttls()
                server.login(settings.email.from_address, settings.email.from_address_password)
                server.sendmail(settings.email.from_address, to_email, msg.as_string())
        except Exception as e:
            print("\nERROR\n", e)
            raise HTTPException(status_code=500, detail=f"Failed to send OTP {e}")


# if __name__ == "__main__":
#     EmailServices.send_code(
#         to_email="alekseevkirill30092004@mail.ru",
#         code="123123",
#     )
