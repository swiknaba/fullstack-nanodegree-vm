#!/usr/bin python
# -*- coding: utf-8 -*-

"""
########## creating a database with SQLAlchemy ##########
1) Configuration
    beginning of file: import moduls, create instances of declarative base
    end of file: create/connect the database and add tables and columns
2) Class
    representation of table as a python class
    extends the Base class
    nested inside will be table and mapper code
3) Table
    representation of our table inside the database
    syntax:
        __tablename__ = 'some_table'
4) Mapper
    maps python objects to columns in our database
    syntax:
        columnName = Column(attributes,...)
    example attribues:
        String(250)
        Integer
        elationship(Class)
        nullable = False
        primary_key = True
        ForeignKey('some_table.id')
"""

# Configuration - beginning of file
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    email = Column(String(80), nullable=False)
    picture = Column(String(160))


#class
class Restaurant(Base):
    # Table
    __tablename__ = 'restaurant'

    # Mapper
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'name': self.name,
            'id': self.id
        }


class MenuItem(Base):
    # Table
    __tablename__ = 'menu_item'

    # Mapper
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    course = Column(String(250))
    description = Column(String(250))
    price = Column(String(8))
    restaurant_id = Column(Integer, ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    # for the JSON API (GET Request)
    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
            'course': self.course
        }


# Configuration - end of file
engine = create_engine('sqlite:///restaurantmenuwithusers.db')

Base.metadata.create_all(engine)
