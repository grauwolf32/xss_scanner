import re 
from functools import reduce

extractors = [
                     re.compile(r"([a-zA-Z_]\w*)\[([a-zA-Z_]\w*)*\w*\]"), # array regexp
                     re.compile(r"var\s+([a-zA-Z_]\w*)"),                 # var name regexp   
                     re.compile(r"([a-zA-Z_]\w*)\.([a-zA-Z_]\w*)\.*"),    # class hierarchy
                     re.compile(r"([a-zA-Z_]\w*)\s*=\s*\w"),              # name = value
                     re.compile(r"\w+\s*=\s*([a-zA-Z_]\w*)"),             # smth = name 
                     re.compile(r'''[\"\']([a-zA-Z_]\w*)[\"\']:[\"\']\w*[\"\']''') # "name":"value"
                    ]

js_keywords = set([
                        'abstract','arguments','boolean','break','byte',
                        'case','catch','char','class','const',
                        'continue','debugger','default','delete','do',
                        'double','else','enum*','eval','export',
                        'extends','false','final','finally','float',
                        'for','function','goto','if','implements',
                        'import','in','instanceof','int','interface',
                        'let','long','native','new','null',
                        'package','private','protected','public','return',
                        'short','static','super*','switch','synchronized',
                        'this','throw','throws','transient','true',
                        'try','typeof','var','void','volatile',
                        'while','with','yield'
                    ])

js_datatypes = set(["Array", "Date" ,"function",
                    "hasOwnProperty", "Infinity","isFinite", "isNaN",
                    "isPrototypeOf","Math","NaN",
                    "Number","Object","prototype"
                    "String","toString","undefined","valueOf"])

js_keywords.update(js_datatypes)

reserved_keywords = set(["alert", "all", "anchor", "anchors",
                         "area", "assign", "blur", "button",
                         "checkbox", "clearInterval", "clearTimeout", "clientInformation",
                         "close", "closed", "confirm","constructor",
                         "crypto", "decodeURI", "decodeURIComponent", "defaultStatus",
                         "document","element","elements", "embed",
                         "embeds","encodeURI","encodeURIComponent","escape",
                         "event","fileUpload","focus","form",
                         "forms","frame","innerHeight","innerWidth",
                         "layer","layers","link","location",
                         "mimeTypes","navigate","navigator","frames",
                         "frameRate","hidden", "history", "image",
                         "images","offscreenBuffering","open","opener",
                         "option","outerHeight","outerWidth","packages",
                         "pageXOffset","pageYOffset","parent","parseFloat",
                         "parseInt","password","pkcs11","plugin",
                         "prompt","propertyIsEnum", "radio","reset",
                         "screenX","screenY","scroll","secure",
                         "select","self","setInterval","setTimeout",
                         "status","submit","taint","text",
                         "textarea","top","unescape","untaint","window"])

reserved_small = set(["alert","innerHTML","self","setTimeout","window","clearTimeout"])
js_keywords.update(reserved_small)

def extractjs_fast(src):
    # Extract all variable names from script

    jsvars = reduce(lambda x, y: x + y, [re.findall(regexp, src) for regexp in extractors], [])
    jsvars = reduce(lambda x, y: x + tuple(y), jsvars, tuple())
    return set(jsvars)