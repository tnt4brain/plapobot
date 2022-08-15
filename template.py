import uuid

from jinja2 import Environment, FileSystemLoader, BaseLoader

import os
import yaml


def uniq_id():
    from secrets import choice
    from string import ascii_letters, digits
    alphabet = ascii_letters + digits
    result = ''.join(choice(alphabet) for _ in range(6))
    return result


class J2:
    # This converts this class to singleton
    # __instance = None
    # def __new__(cls, *args, **kwargs):
    #     if J2.__instance is None or kwargs.get('global', False) is False:
    #         J2.__instance = object.__new__(cls)
    #     return J2.__instance

    def __init__(self, add_ins: dict = None):
        template_dir = os.path.join(os.getcwd(), 'templates')
        self.env = Environment(loader=FileSystemLoader(template_dir, encoding="utf-8"))
        self.env.globals.update(add_ins if add_ins is not None else {})
        self.env.globals.update({'uniq_id': uniq_id})

    def load(self, filename: str, *args, **kwargs):
        return yaml.safe_load(self.render(filename, *args, **kwargs))

    def update_env(self, value):
        self.env.globals.update(value)

    def render(self, filename: str, *args, **kwargs):
        template = self.env.get_template(filename)
        # default_uuid = uuid.uuid4()
        default_uuid = uniq_id()
        res = template.render(*args, **{"default_uuid": default_uuid}, **kwargs)
        return res

    def render_msg(self, inp_template: str, msg_locals: dict, **kwargs):
        tmp_template = Environment(loader=BaseLoader()).from_string(inp_template, self.env.globals)
        tmp_dict = {}
        tmp_dict.update(msg_locals)
        tmp_dict.update(kwargs)
        res = tmp_template.render(tmp_dict)
        return res
