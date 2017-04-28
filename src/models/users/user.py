import uuid

from src.common.database import Database
from src.models.alerts.alert import Alert
import src.models.users.errors as UserErrors
import src.models.users.constants as UserConstants
from src.common.utils import Utils


class User(object):
    def __init__(self,email, password, _id=None):
        self.email = email
        self.password = password
        self._id = uuid.uuid4().hex if _id is None else _id

    def __repr__(self):
        return "<User {}>".format(self.email)

    @staticmethod
    def is_login_valid(email,password):
        """
        This method verifies that an e-mail/password combo (as sent by forms)
        is valid or not
        Checks that email exists and the password is correct
        :param email: string
        :param password: hashed password
        :return: True if valid, False, otherwise
        """
        user_data = Database.find_one(UserConstants.COLLECTION,{"email":email}) # password in sha512 --> pbkdf2_sha512
        if user_data is None:
            raise UserErrors.UserNotExistsError("Your user does not exist.")
        if not Utils.check_hashed_password(password,user_data['password']):
            # Tell the user that their password/email is wrong
            raise UserErrors.IncorrectPasswordError("Your password was wrong.")

        return True

    @staticmethod
    def register_user(email,password):
        """
        Registers a user using email/password.
        The password already comes hashed as sha_512
        :param email: user's email (might be invalid)
        :param password: sha512-hashed password
        :return: True if registered successfully, or False otherwise
        """
        user_data = Database.find_one("users",{"email":email})

        if user_data is not None:
            #Tell user they are already registered
            raise UserErrors.UserAlreadyRegisteredError("The email you used is already registered")
        if not Utils.email_is_valid(email):
            # Tell the user that their email is not constructed properly
            raise UserErrors.InvalidEmailError("Please input a correct email address!")
        User(email,Utils.hash_password(password)).save_to_db()

        return True

    def save_to_db(self):
        Database.insert(UserConstants.COLLECTION,self.json())

    def json(self):
        return {
            "_id":self._id,
            "email":self.email,
            "password":self.password #think we need to save hashed_password
        }

    @classmethod
    def find_by_email(cls,email):
        return cls(**Database.find_one(UserConstants.COLLECTION,
                                       {"email":email}))

    def get_alerts(self):
        return Alert.find_by_user_email(self.email)