from .models import Contact
from datetime import datetime, timedelta
from sqlalchemy import extract
from . import models

from sqlalchemy.orm import Session
from .models import User
from . import schemas
from passlib.hash import bcrypt

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def hash_password(password: str):
    return bcrypt.hash(password)

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = hash_password(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.verify(plain_password, hashed_password)


def create_contact(db: Session, contact: schemas.ContactCreate):
    db_contact = Contact(**contact.model_dump())

    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(db: Session, skip: int = 0, limit: int = 10):
    return db.query(Contact).offset(skip).limit(limit).all()

def get_contact_by_id(db: Session, contact_id: int):
    return db.query(Contact).filter(Contact.id == contact_id).first()

def update_contact(db: Session, contact_id: int, contact_update: schemas.ContactUpdate):
    db_contact = db.query(Contact).filter(Contact.id == contact_id).first()
    for key, value in contact_update.model_dump().items():
        setattr(db_contact, key, value)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int):
    contact = db.query(models.Contact).filter(models.Contact.id == contact_id).first()
    if contact:
        db.delete(contact)
        db.commit()
        db.refresh(contact)
        return contact
    return None

def search_contacts(db: Session, query: str):
    return db.query(Contact).filter(
        (Contact.first_name.ilike(f"%{query}%")) |
        (Contact.last_name.ilike(f"%{query}%")) |
        (Contact.email.ilike(f"%{query}%"))
    ).all()

def get_upcoming_birthdays(db: Session, user_id: int):
    today = datetime.now().date()
    end_date = today + timedelta(days=7)
    return db.query(Contact).filter(
        extract('day', Contact.birthday) >= today.day,
        extract('month', Contact.birthday) == today.month,
        extract('day', Contact.birthday) <= end_date.day,
        extract('month', Contact.birthday) == end_date.month,
        Contact.owner == user_id  # Add this condition to filter by user ID
    ).all()
