from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, HiddenField, \
    IntegerField, DecimalField, BooleanField
from wtforms.validators import Length, DataRequired, Regexp, NumberRange


class LoginForm(FlaskForm):
    wallet_name = StringField('Wallet Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class RequestWalletForm(FlaskForm):
    requested_wallet_name = StringField('Desired Wallet Name', validators=[
        DataRequired(),
        Regexp(r'^[a-zA-Z0-9_]{3,100}$', message="Wallet name must be 3-100 chars of letters, numbers, underscores")
    ])
    request_password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    request_reason = TextAreaField('Reason for Request', validators=[DataRequired(), Length(min=3, max=500)])
    submit = SubmitField('Request Wallet')


class FreezeForm(FlaskForm):
    wallet_name = HiddenField('Wallet Name', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[
        DataRequired(),
        Length(min=3, max=500)
    ])


class ResetForm(FlaskForm):
    wallet_name = HiddenField('Wallet Name', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[
        DataRequired(),
        Length(min=3, max=500)
    ])


class BurnForm(FlaskForm):
    wallet_name = HiddenField('Wallet Name', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[
        DataRequired(),
        Length(min=3, max=500)
    ])


class MintCurrencyForm(FlaskForm):
    mint_amount = IntegerField(
        'Amount to Mint',
        validators=[
            DataRequired(message="Mint amount is required."),
            NumberRange(min=1, message="Must mint at least 1 unit.")
        ]
    )
    submit = SubmitField('Mint Currency')


class BurnCurrencyForm(FlaskForm):
    burn_amount = IntegerField(
        'Amount to Burn',
        validators=[
            DataRequired(message="Burn amount is required."),
            NumberRange(min=1, message="Must burn at least 1 unit.")
            # max will be dynamically validated in route based on 'available' currency
        ]
    )
    submit = SubmitField('Burn Currency')


class CreateWalletForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=32, message="Username must be between 3 and 32 characters.")
        ]
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=6, message="Password must be at least 6 characters.")
        ]
    )

    initial_currency = DecimalField(
        'Initial Currency',
        places=2,
        rounding=None,
        validators=[
            NumberRange(min=0, message="Initial amount must be non-negative.")
        ],
        default=0
    )

    submit = SubmitField('Create Wallet')


class RulesForm(FlaskForm):
    allow_leaderboard = BooleanField('Allow Leaderboard')
    allow_public_logs = BooleanField('Allow Public Logs')
    allow_debts = BooleanField('Allow Debts')
    allow_self_review = BooleanField('Allow Self-Review')

    submit = SubmitField('Save Rules')


# Dynamic Generated Button Forms, all we need is the CSRF
class RequestForm(FlaskForm):
    pass


class AdminLogForm(FlaskForm):
    pass


class AdminRequestsForm(FlaskForm):
    pass
