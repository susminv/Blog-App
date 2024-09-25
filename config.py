import urllib
class Config:
    SECRET_KEY = 'Some secret key'
    params = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=DESKTOP-QFHFBJH\\SQLEXPRESS;DATABASE=blogdb;Trusted_Connection=yes;'
    connection_string = urllib.parse.quote_plus(params)
    SQLALCHEMY_DATABASE_URI = "mssql+pyodbc:///?odbc_connect=%s" % connection_string
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_PERMANENT = False
    SESSION_COOKIE_NAME = 'your_session_name'
    SESSION_TYPE = 'filesystem'