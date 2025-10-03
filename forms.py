from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField, StringField, PasswordField,BooleanField
from wtforms.validators import DataRequired, Length,Email, EqualTo
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, email, id,username):
        self.email = email
        self.id = id  # Must be string for get_id()
        self.username = username  # Optional, for display purposes
        
    # UserMixin provides is_authenticated, etc.


class JournalEntryForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(message="Please enter a title for your journal entry."),
        Length(min=1, max=100, message="Title must be between 1 and 100 characters.")],
        render_kw={"placeholder": "Title"}
)
    content = TextAreaField('Journal Entry', validators=[
        DataRequired(message="Please enter your journal entry."),
        Length(min=1, max=5000, message="Entry must be between 1 and 5000 characters.")
    ],render_kw={"placeholder": "How are you feeling today? Write your thoughts here..."}
)
    tags = TextAreaField('Tags (optional)', validators=[
        Length(max=100, message="Tags must be under 100 characters.")
    ], render_kw={"placeholder": "Enter tags, separated by commas"})
    submit = SubmitField('Save Entry')

class RegisterForm(FlaskForm):
      username = StringField('Username', validators=[
          DataRequired(message="Please enter a username."),
          Length(min=3, max=25, message="Username must be between 3 and 25 characters.")
      ])
      email = StringField('Email', validators=[
          DataRequired(message="Please enter an email address."),
          Length(max=120, message="Email must be under 120 characters.")
      ])
      password = PasswordField('Password', validators=[
          DataRequired(message="Please enter a password."),
          Length(min=6, message="Password must be at least 6 characters long.")
      ])
      submit = SubmitField('Register')

class LoginForm(FlaskForm):
      username = StringField('Username', validators=[
          DataRequired(message="Please enter your username.")
      ])
      password = PasswordField('Password', validators=[
          DataRequired(message="Please enter your password.")
      ])
      remember = BooleanField('Remember Me')
      submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')