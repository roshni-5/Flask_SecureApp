from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo
import bleach

# Sanitization filter to mitigate XSS (OWASP Injection Prevention)
def sanitize_html(text):
    if text:
        return bleach.clean(text)
    return text

class RegistrationForm(FlaskForm):
    # Length limits and stripping tags
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], filters=[sanitize_html])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], filters=[sanitize_html])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)], filters=[sanitize_html])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)], filters=[sanitize_html])
    phone = StringField('Phone', validators=[Length(max=20)], filters=[sanitize_html])
    message = TextAreaField('Message', filters=[sanitize_html])
    submit = SubmitField('Save Contact')
