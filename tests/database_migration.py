from modules.db.database import Database

_db = Database()
_db.clean()
_db.migrate()