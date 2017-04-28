from flask import Blueprint

item_blueprint = Blueprint('item',__name__)

@item_blueprint.route('/item/<string:name>')
def item_page(name):
    pass

