from argparse import ArgumentParser, Action, OPTIONAL, _copy, _ensure_value
import re

class _WildCardAction(Action):

    def __init__(self,
                 option_strings,
                 dest,
                 nargs=None,
                 const=None,
                 default=None,
                 type=None,
                 choices=None,
                 required=False,
                 help=None,
                 metavar=None):
        if len(option_strings) != 1:
            raise ValueError('The wild card action takes exactly one option string')
        if nargs == 0:
            raise ValueError('nargs for store actions must be > 0; if you '
                             'have nothing to store, actions such as store '
                             'true or store const may be more appropriate')
        if const is not None and nargs != OPTIONAL:
            raise ValueError('nargs must be %r to supply const' % OPTIONAL)
        super(_WildCardAction, self).__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=nargs,
            const=const,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        option_string_pat = self.option_strings[0]
        key = re.match(option_string_pat, option_string).groups()[0]
        items = _copy.copy(_ensure_value(namespace, self.dest, {}))
        items[key] = values
        setattr(namespace, self.dest, items)

    def match(self, option_string):
        option_string_pat = self.option_strings[0]
        if re.match(option_string_pat, option_string):
            return True

class WildCardArgumentParser(ArgumentParser):
    def __init__(self, *args, **kwargs):
        ArgumentParser.__init__(self, *args, **kwargs)
        self.register('action', 'wildcard', _WildCardAction)

    def _parse_optional(self, arg_string):
        result = ArgumentParser._parse_optional(self, arg_string)
        if result is None:
            return None
        action, option_string, explicit_arg = result

        if action is None:
            for wc in self._option_string_actions.values():
                if not isinstance(wc, _WildCardAction):
                    continue
                if wc.match(option_string):
                    action = wc

#             wildcards = [action for action in self._option_string_actions.values() if isinstance(action, _WildCardAction)]
#             print 'wildcards', wildcards

        return action, option_string, explicit_arg


