from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateTimeLocalField
from wtforms.validators import DataRequired, Length

class ScheduleForm(FlaskForm):
    title = StringField('Title', validators=[
        DataRequired(),
        Length(max=100)
    ])
    description = TextAreaField('Description', validators=[
        Length(max=500)
    ])
    scheduled_date = DateTimeLocalField('Schedule Date', 
                                      format='%Y-%m-%dT%H:%M',
                                      validators=[DataRequired()])