
import shelve
import json

from datetime import datetime

from adapters.lib.utils.mngFiles_ng import getfile_json2dict
from adapters.lib.utils.mngFiles_ng import chk_file
from adapters.lib.utils.mngFiles_ng import sndfile_dict2json

def main():

    # test write to db
    SOURCE_ID = "test"
    print db('local_file', 'test_collection', SOURCE_ID)

    guid = "018d89454aedd46ebd189568cb7f8311"
    db('local_file', 'test_collection', SOURCE_ID, {guid: {"date": "2016-06-30"}})

    guid = "b94ccd3ca856f22c38c5d40ac8cac0af"
    db('local_file', 'test_collection', SOURCE_ID, {guid: {"date": str(datetime.now())}})




def db(db, collection, key, value=None):
    """
    conndb_get_source - Gets source connection and remote data type
        from "database" | This function decouples the request from the database details
        | Presumably this will become a connection to a real database at some point

    :param collection: <string> name of colletion in database
    :param key: <string> key in openSourceList.json
    :param value: optional <anything> if a value is passed write to db
    :return: value
    """


    if db == 'local_file':
        db_name = '../../data/adapter/' + collection + '.json'
        chk_file(db_name, True, '{"' + key + '":{}}')

        data = getfile_json2dict(db_name)
        if value:
            if key not in data:
                data[key] = {}
            data[key].update(value)
            sndfile_dict2json(data, db_name, pretty=False)

        return data.get(key)


class DB(object):
    DEFAULT_PATH = '../../data/adapter/'
    DEFAULT_EXT = 'json'

    def __init__(self, type_='local_file', loc=None, name='local_db', key=None):
        self._type = type_
        self._loc = loc
        self._name = name
        self._ext = DB.DEFAULT_EXT
        self._path = None
        self.dict = {}
        self.setup(key)

    def wtf(self):  # write to file
        with open(self._path) as json_file:
            data = json.load(json_file)

        data = data.copy()
        data.update(self.dict)

        with open(self._path, 'w') as json_file:
            json.dump(data, json_file, indent=4)

        self.dict = data

    def setup(self, key):

        if '.' in self._name:
            self._ext = self._name.split('.')[-1]

        if key:
            data = '{"' + key + '":{}}'
        else:
            data = '{}'

        if self._loc:
            if self._loc[:1] is not '/':
                self._loc = '%s/' % self._loc

            path = '%s%s' % (self._loc, self._name)
        else:
            path = '%s%s' % (DB.DEFAULT_PATH, self._name)

        self._path = '%s.%s' % (path, self._ext)

        if not chk_file(self._path):
            chk_file(self._path, True, data)

        self.wtf()





def get_db(loc, name):

    if loc == 'local_file':
        name_ext = name.split('.')[-1]
        if name_ext == 'json':
            pass
        elif name_ext == 'shelve':
            return shelve.open(name, writeback=True)




if __name__ == "__main__":
    main()

#EOF
