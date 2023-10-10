import re
import sys

import utils
from generic_fn import GenericFn
from typed_generic_fn import TypedGenericFn

from typing import cast, Optional

import pprint


class Task:
    """
    Represents a task that needs to be resolved by inserting the concrete definition
    for the function in the Jasmin source code.

    Attributes:
        fn_name (str): The name of the function to be resolved in the Jasmin code.
        template_params (list[str]): A list of the value of the parameters to be used in the function.
        global_params (dict[str, int]): The dictionary of the global parameters
    """

    def __init__(
            self,
            fn_name: str,
            template_params: list[str | int],
            global_params: dict[str, int],
            # unless specified otherwise, a task is considered to be a simple
            # generic function (i.e. not typed)
            typed_fn_names: list[str] | None = None,
            # TODO: from typing import Optional
            typed_fn_types: list[str] | None = None,
    ):
        self.fn_name = fn_name
        self.template_params = template_params
        self.global_params = global_params

        if isinstance(typed_fn_names, str):
            self.typed_fn_names = utils.string_to_singleton_list(
                typed_fn_names)
        else:
            self.typed_fn_names = typed_fn_names

        if isinstance(typed_fn_types, str):
            self.typed_fn_types = utils.string_to_singleton_list(
                typed_fn_types)
        else:
            self.typed_fn_types = typed_fn_types

        self.is_typed_task = typed_fn_names and typed_fn_types

    def __eq__(self, other: object):
        if not isinstance(other, Task):
            return False

        template_params_int_self: list[int] = [
            int(val) for val in self.template_params]
        template_params_int_other: list[int] = [
            int(val) for val in other.template_params]

        if self.is_typed_task and other.is_typed_task:
            return (
                self.fn_name == other.fn_name
                and template_params_int_self == template_params_int_other
                and self.typed_fn_names == other.typed_fn_names
                and self.typed_fn_types == other.typed_fn_types
            )
        elif (not self.is_typed_task) and (not other.is_typed_task):
            return (
                self.fn_name == other.fn_name
                and template_params_int_self == template_params_int_other
            )
        else:
            return False

    def __hash__(self):
        # Convert the list to a tuple for hashing (TypeError: unhashable type:
        # 'list')
        return hash((self.fn_name, tuple(self.template_params)))

    def __repr__(self) -> str:
        params_str = ", ".join(str(param) for param in self.template_params)
        return f"Task(fn_name='{self.fn_name}', params=[{params_str}], typed_fn_names={self.typed_fn_names}, typed_fn_types={self.typed_fn_types})"

    def is_valid(self) -> bool:
        if self.is_typed_task:
            return self.fn_name != '' and self.template_params != [] and self.typed_fn_names != [] and list(
                self.typed_fn_types) != []  # TODO: FIXME: support tasks without typed_fn_name or without typed_fn_types
        else:
            return self.fn_name != '' and self.template_params != []

    def resolve(
            self,
            text: str,
            generic_fn_dict: dict[str, GenericFn],
            typed_generic_fn_dict: dict[str, TypedGenericFn],
    ) -> str:
        """
        Resolve the function and return the concrete definition
        """
        pattern = rf"// Place concrete instances of the {self.fn_name} function here"

        generic_fn: GenericFn | TypedGenericFn = None
        try:
            generic_fn = generic_fn_dict[self.fn_name]
        except KeyError:
            try:
                generic_fn = typed_generic_fn_dict[self.fn_name]
            except KeyError:
                sys.stderr.write(
                    f"Could not find {self.fn_name} in generic_fn_dict in Task.resolve [1]\n"
                )
                sys.exit(-1)

        replacement_dict: dict[str, int] = dict(
            zip(generic_fn.params, self.template_params)
        )

        if self.is_typed_task:
            # suppress pytype warning
            generic_fn = cast(TypedGenericFn, generic_fn)
            tmp = dict(zip(generic_fn.generic_fn_names, self.typed_fn_names))
            tm2 = dict(zip(generic_fn.generic_fn_types, self.typed_fn_types))
            replacement_dict = {**replacement_dict, **tmp, **tm2}

        # print(f"DEBUG: Printing replacement DICT of task {self.fn_name}")
        # pprint.pprint(replacement_dict)

        return re.sub(
            pattern,
            lambda match: match.group()
            + "\n"
            + utils.build_concrete_fn(generic_fn,
                                      replacement_dict, self.is_typed_task)
            + "\n",
            text,
        )

    # pytype: disable=name-error
    def get_sub_tasks(
            self,
            generic_fn_dict: dict[str, GenericFn],
            typed_generic_fn_dict: dict[str, TypedGenericFn],
            context_params: Optional[dict[str, int]] = None,
    ) -> list["Task"]:
        # pytype: enable=name-error
        """
        Get the sub-tasks for the current task by resolving nested generic function calls.
        """
        subtasks: list[Task] = []

        # print(f'\n\nDebug in Get Sub Task for task {self.fn_name}')
        # print("Context params at the beginning")
        # print(context_params)
        # print("Generic_Fn_Dict")
        # pprint.pprint(generic_fn_dict.keys())
        # print("Typed_Generic_Fn_Dict")
        # pprint.pprint(typed_generic_fn_dict.keys())

        generic_fn: GenericFn | TypedGenericFn = None

        function_name = self.fn_name
        if context_params is not None:
            try:
                function_name = eval(self.fn_name, {}, context_params)
                print(f"Name: {function_name}")
            except NameError:
                pass

        try:
            generic_fn = generic_fn_dict[function_name]
        except KeyError:
            try:
                generic_fn = typed_generic_fn_dict[function_name]
            except KeyError:
                sys.stderr.write(
                    f"Could not find {self.fn_name} in generic_fn_dict/typed_generic_fn_dict in Task.get_sub_tasks [2]\n"
                )
                sys.exit(-1)

        resolved_fn_body: str = self.resolve(
            generic_fn.fn_body, generic_fn_dict, typed_generic_fn_dict
        )

        # The 1st function call does not have
        if context_params is None:
            context_params = dict(zip(generic_fn.params, self.template_params))

            if self.is_typed_task:
                t = dict(zip(generic_fn.generic_fn_types, self.typed_fn_types))
                u = dict(zip(generic_fn.generic_fn_names, self.typed_fn_names))
                context_params.update(t)
                context_params.update(u)
        else:
            tmp = dict(zip(generic_fn.params, self.template_params))
            context_params.update(tmp)

        # 'Simple' generic fn
        generic_fn_call_pattern = r"(\w+)<([^>]+)>\(([^)]+)\);"
        for match in re.finditer(generic_fn_call_pattern, resolved_fn_body):
            fn_name, generic_params, _ = match.groups()

            if fn_name == self.fn_name:
                sys.stderr.write(
                    f"Recursive functions not supported: {self.fn_name}\n")
                sys.exit(-1)

            generic_params = [p.strip() for p in generic_params.split(",")]

            for param in generic_params:
                try:
                    # Context params may override global params
                    context_params[param] = int(context_params[param])
                except KeyError:
                    try:
                        context_params[param] = context_params.get(
                            param, self.global_params[param]
                        )
                    except KeyError:
                        template_params_int: list[int] = [
                            int(val) for val in self.template_params
                        ]
                        template_dict: dict[str, int] = dict(
                            zip(
                                generic_fn_dict[self.fn_name].params,
                                template_params_int,
                            )
                        )  # TODO: handle key error
                        context_params[param] = eval(
                            param.replace("/", "//"),
                            {},
                            {**self.global_params, **context_params, **template_dict},
                        )
                    except Exception:
                        sys.stderr.write(
                            "Could not evaluate parameter: {param}")

            concrete_args: list[int] = [
                int(context_params.get(p, p)) for p in generic_params]
            subtask = Task(fn_name, concrete_args, self.global_params)
            subtasks.append(subtask)

        # 'Typed' generic fn
        typed_generic_fn_call_pattern = r"(\w+)<([^>]+)>\s*\[([^\]]+)]\(([^)]+)\);"
        for match in re.finditer(
                typed_generic_fn_call_pattern, resolved_fn_body):
            fn_name, generic_params, type_info, _ = match.groups()
            fn_names = type_info.split(";")[0]
            if isinstance(fn_names, str):
                fn_names: list[str] = utils.string_to_singleton_list(fn_names)
            fn_names = [v.strip() for v in fn_names]

            fn_types = type_info.split(";")[-1]
            if isinstance(fn_types, str):
                fn_types: list[str] = utils.string_to_singleton_list(fn_types)
            fn_types = [v.strip() for v in fn_types]

            if fn_name == self.fn_name:
                sys.stderr.write(
                    f"Recursive functions not supported: {self.fn_name}\n")
                sys.exit(-1)

            generic_params: list[str] = [p.strip()
                                         for p in generic_params.split(",")]

            for param in generic_params:
                try:
                    # Context params may override global params
                    context_params[param] = int(context_params[param])
                except KeyError:
                    try:
                        context_params[param] = context_params.get(
                            param, self.global_params[param]
                        )
                    except KeyError:
                        template_params_int: list[int] = [
                            int(val) for val in self.template_params
                        ]
                        template_dict: dict[str, int] = dict(
                            zip(
                                generic_fn_dict[self.fn_name].params,
                                template_params_int,
                            )
                        )  # TODO: handle key error
                        context_params[param] = eval(
                            param.replace("/", "//"),
                            {},
                            {**self.global_params, **context_params, **template_dict},
                        )
                    except Exception:
                        sys.stderr.write(
                            "Could not evaluate parameter: {param}")

            concrete_args = [int(context_params.get(p, p))
                             for p in generic_params]

            fn_names: list[str] = utils.eval_list(fn_names, context_params)
            fn_types: list[str] = utils.eval_list(fn_types, context_params)

            subtask = Task(
                fn_name, concrete_args, self.global_params, fn_names, fn_types
            )
            subtasks.append(subtask)

        # Recursive step: Find and collect sub-tasks from the resolved function
        # body
        replacement_dict: dict[str, int] = dict(
            zip(generic_fn.params, self.template_params)
        )
        if self.is_typed_task:
            # suppress pytype warning
            generic_fn = cast(TypedGenericFn, generic_fn)
            tmp = dict(zip(generic_fn.generic_fn_names, self.typed_fn_names))
            tm2 = dict(zip(generic_fn.generic_fn_types, self.typed_fn_types))
            replacement_dict = {**replacement_dict, **tmp, **tm2}

        for subtask in subtasks:
            sub_subtasks = subtask.get_sub_tasks(
                generic_fn_dict,
                typed_generic_fn_dict,
                {
                    **self.global_params,
                    **context_params,
                    **replacement_dict,
                },  # Pass resolved_params_local in the recursion
            )
            subtasks.extend(sub_subtasks)

        return subtasks
