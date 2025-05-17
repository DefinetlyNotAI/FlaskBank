from wtforms import Form, StringField, PasswordField, FloatField, validators, SelectField, TextAreaField


# Form Validation Classes
class SetupForm(Form):
    bank_name = StringField('Bank Name', [
        validators.Length(min=3, max=100, message="Bank name must be between 3 and 100 characters"),
        validators.DataRequired(message="Bank name is required")
    ])
    currency_name = StringField('Currency Name', [
        validators.Length(min=1, max=50, message="Currency name must be between 1 and 50 characters"),
        validators.DataRequired(message="Currency name is required")
    ])
    admin_password = PasswordField('Admin Password', [
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.DataRequired(message="Admin password is required")
    ])


class WalletForm(Form):
    username = StringField('Username', [
        validators.Length(min=3, max=100, message="Username must be between 3 and 100 characters"),
        validators.DataRequired(message="Username is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    password = PasswordField('Password', [
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.DataRequired(message="Password is required")
    ])
    initial_currency = FloatField('Initial Currency', [
        validators.NumberRange(min=0, message="Initial currency must be a non-negative number"),
        validators.Optional()
    ])

    def process(self, formdata=None, obj=None, data=None, **kwargs):
        if isinstance(data, dict) and 'initial_currency' in data:
            try:
                data['initial_currency'] = float(data['initial_currency'])
            except ValueError:
                data['initial_currency'] = None
        super().process(formdata, obj, data, **kwargs)


class TransferForm(Form):
    to_wallet = StringField('To Wallet', [
        validators.Length(min=3, max=100, message="Wallet name must be between 3 and 100 characters"),
        validators.DataRequired(message="Wallet name is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    amount = FloatField('Amount', [validators.DataRequired(message="Amount is required")])
    category = SelectField('Category', [validators.DataRequired(
        message="A category is required (Reward, Trade or Invoice, Penalty)")], choices=[
        ('Reward', 'Reward'),
        ('Trade', 'Trade'),
        ('Invoice', 'Invoice'),
        ('Penalty', 'Penalty')
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=2, max=500, message="Reason must be between 2 and 500 characters"),
        validators.DataRequired(message="Reason is required")
    ])


class ResetPasswordForm(Form):
    new_password = PasswordField('New Password', [
        validators.Length(min=8, message="Password must be at least 8 characters long"),
        validators.DataRequired(message="New password is required")
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class RefundForm(Form):
    transfer_ticket_uuid = StringField('Transfer Ticket UUID', [
        validators.Length(min=36, max=36, message="Invalid UUID length"),
        validators.DataRequired(message="UUID is required"),
        validators.Regexp(r'^[a-f0-9-]+$', message="Invalid UUID format")
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class AdminActionForm(Form):
    wallet_name = StringField('Wallet Name', [
        validators.Length(min=3, max=100, message="Wallet name must be between 3 and 100 characters"),
        validators.DataRequired(message="Wallet name is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class CurrencyForm(Form):
    amount = FloatField('Amount', [
        validators.NumberRange(min=0.01, message="Amount must be greater than 0"),
        validators.DataRequired(message="Amount is required")
    ])

    def process(self, formdata=None, obj=None, data=None, **kwargs):
        if isinstance(data, dict) and 'amount' in data:
            try:
                data['amount'] = float(data['amount'])
            except ValueError:
                data['amount'] = None
        super().process(formdata, obj, data, **kwargs)


class BankTransferForm(Form):
    wallet_name = StringField('Wallet Name', [
        validators.Length(min=3, max=100, message="Wallet name must be between 3 and 100 characters"),
        validators.DataRequired(message="Wallet name is required"),
        validators.Regexp(r'^[a-zA-Z0-9_]+$', message="Wallet name can only contain letters, numbers, and underscores")
    ])
    amount = FloatField('Amount', [
        validators.DataRequired(message="Amount is required")
    ])
    category = SelectField('Category', [validators.DataRequired(
        message="A category is required (Reward, Trade or Invoice, Penalty)")], choices=[
        ('Reward', 'Reward'),
        ('Trade', 'Trade'),
        ('Invoice', 'Invoice'),
        ('Penalty', 'Penalty')
    ])
    reason = TextAreaField('Reason', [
        validators.Length(min=3, max=500, message="Reason must be between 3 and 500 characters"),
        validators.DataRequired(message="Reason is required"),
    ])


class SqlQueryForm(Form):
    query = TextAreaField('SQL Query', [
        validators.DataRequired(message="Query is required")
    ])
