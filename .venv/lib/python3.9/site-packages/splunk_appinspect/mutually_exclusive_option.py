"""
A modifier to specify mutually-exclusive command line options.
Ref: https://gist.github.com/jacobtolar/fb80d5552a9a9dfc32b12a829fa21c0c
"""
from typing import Dict, List

from click import Context, Option, UsageError


class MutuallyExclusiveOption(Option):
    """Implementation of click.Option that allows to define
    other options as mutually exclusive with the current one.

    Attributes:
        mutually_exclusive: A list of strings indicating the mutually exclusive options.
            Each of the definitions has to be accessible through Option.opts.

    Typical usage example:

        @click.option(cls=MutuallyExclusiveOption)
    """

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = kwargs.pop("mutually_exclusive", [])
        help = kwargs.get("help", "")
        if self.mutually_exclusive:
            ex_str = ", ".join(self.mutually_exclusive)
            kwargs["help"] = help + f"\n\nNOTE: This option is mutually exclusive with {ex_str}."
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx: "Context", opts: Dict[str, List[str]], args: List[str]):
        conflicts = [
            ex
            for ex in self.mutually_exclusive
            if any(ex in param.opts for param in ctx.command.params if param.name in opts)
        ]
        if conflicts and self.name in opts:
            raise UsageError(f"Illegal usage: {self.opts[0]} is mutually exclusive with {', '.join(conflicts)}.")

        return super(MutuallyExclusiveOption, self).handle_parse_result(ctx, opts, args)
