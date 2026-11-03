# canon-v1 serialization; Python 3.10+, stdlib [a-Shell ok].
import json,hashlib
MAX_INT=2**53-1
class CanonError(ValueError):pass

def validate(value):
    if value is None or type(value) is bool:return
    if type(value) is int:
        if abs(value)>MAX_INT:raise CanonError('integer range')
    elif type(value) is str:
        try:value.encode('utf-8')
        except UnicodeError:raise CanonError('surrogate') from None
    elif type(value) is list:
        for item in value:validate(item)
    elif type(value) is dict:
        for key,item in value.items():
            if type(key) is not str:raise CanonError('object key')
            validate(key);validate(item)
    else:raise CanonError('unsupported value')

def dumps(value):
    validate(value)
    return json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':')).encode('utf-8')

def loads(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise CanonError('duplicate key')
            result[key]=value
        return result
    def integer(text):
        if text=='-0':raise CanonError('negative zero')
        value=int(text);validate(value);return value
    def forbidden(_):raise CanonError('number form')
    try:
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,parse_int=integer,parse_float=forbidden,parse_constant=forbidden)
        validate(value);return value
    except (UnicodeError,ValueError,RecursionError) as exc:raise CanonError(type(exc).__name__) from None

def digest(raw):return 'sha256:'+hashlib.sha256(raw).hexdigest()
def hash_value(value):return digest(dumps(value))
def hash_bytes(value):
    if type(value) is not str or len(value)!=71 or not value.startswith('sha256:') or any(c not in '0123456789abcdef' for c in value[7:]):raise ValueError('hash encoding')
    return bytes.fromhex(value[7:])
