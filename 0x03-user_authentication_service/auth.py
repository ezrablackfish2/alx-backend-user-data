#!/usr/bin/env python3
"""
Auth
"""
import bcrypt

from uuid import uuid4

from db import DB, User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """
    Encrypts a password.
    """
    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return hashed_password


def _generate_uuid() -> str:
    """
    Returns a string of uuid.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """
    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user.
        """
        try:
            if self._db.find_user_by(email=email):
                raise ValueError("User {} already exists.".format(email))

        except NoResultFound:
            hashed_pass = _hash_password(password)

            return self._db.add_user(email=email, hashed_password=hashed_pass)

    def valid_login(self, email: str, password: str) -> bool:
        """
        Login validation.
        """
        try:
            user = self._db.find_user_by(email=email)

            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password)

        except NoResultFound:
            return False

    def create_session(self, email):
        """
        Creates a session id for the user with the given email.
        """
        try:
            user = self._db.find_user_by(email=email)
            user.session_id = _generate_uuid()

            self._db.update_user(user.id, session_id=user.session_id)

            return user.session_id

        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Fetchs the user using session_id
        """

        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)

            return user

        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroys the session for the user.
        """
        try:
            self._db.update_user(user_id=user_id, session_id="")

        except NoResultFound:
            return None
