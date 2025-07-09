from sqlalchemy.orm import DeclarativeBase

#TODO: find out why we need to separate sessions
class Base(DeclarativeBase):
    pass