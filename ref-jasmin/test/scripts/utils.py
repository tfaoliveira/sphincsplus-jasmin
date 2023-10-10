import re
import sys

from generic_fn import GenericFn
from task import Task
from typed_generic_fn import TypedGenericFn

from typing import cast, Any


# TODO: FIX Any
def eval_list(input_list: list[Any], eval_dict: dict[str, int]):
    res = []
    for v in input_list:
        try:
            evaluated_value = eval(v, {}, eval_dict)
        except NameError:
            # If an exception is raised during evaluation, keep the original
            # value
            evaluated_value = v
        res.append(evaluated_value)
    return res


def string_to_singleton_list(input_string: str) -> list[str]:
    return [input_string]


def remove_duplicates(input_list: list[Any]) -> list[Any]:
    """
    Removes duplicates from a list and returns a new list with unique elements.

    Args:
        input_list (list[T]): The input list with potential duplicates.

    Returns:
        list[T]: A new list with duplicates removed.
    """
    if not hasattr(input_list[0].__class__, '__eq__'):
        raise TypeError(
            "Elements in the input list must implement the __eq__ method.")

    res = []

    for item in input_list:
        if item not in res:
            res.append(item)

    return res


def replace_eval_global_params(text: str, params: dict[str, int]) -> str:
    def eval_expression(match):
        name, expression = match.groups()
        try:
            value = eval(expression.replace("/", "//"), params)
            return f"param int {name} = {value};"
        except Exception as e:
            print(f"Error evaluating expression for {name}: {e}")
            return match.group(0)

    pattern = r"param\s+int\s+(\w+)\s*=\s*(.+);"
    updated_text = re.sub(pattern, eval_expression, text)
    return updated_text


def parse_tasks(text: list[str], global_params: dict[str, int]) -> list[Task]:
    if text is None:
        return []

    res: list[Task] = []
    for s in text:
        fields: list[str] = s.split()
        params: dict[str, int] = {}
        fn_name: str = fields[0].split(":")[-1]
        for field in fields:
            if field.startswith("p:"):
                # Split the field by ':'
                _, key, value = field.split(":")
                params[key] = int(value)

        task = Task(fn_name, list(params.values()), global_params)
        res.append(task)

    return res


def get_params(code: str) -> dict[str, int]:
    """
    Extracts and evaluates parameter declarations from Jasmin source code.
    The code assumes that all parameter declarations follow the format
    'param int <parameter_name> = <expression>;'
    """
    pattern = r"param\s+int\s+(\w+)\s*=\s*(.+);"
    matches = re.findall(pattern, code, re.MULTILINE)
    param_dict = dict(matches)
    res: dict[str, int] = {}
    visited: set[str] = set()

    def evaluate_expression(param_name: str):
        if param_name in visited:
            raise ValueError("Circular dependency.")

        visited.add(param_name)
        param_value = param_dict[param_name]
        res[param_name] = eval(param_value, None, res)
        visited.remove(param_name)

    for key in param_dict:
        evaluate_expression(key)

    return res


def get_generic_fn_dict(input_text: str) -> dict[str, GenericFn]:
    """
    Extracts generic function declarations from the input text and returns a dictionary
    containing information about each generic function.
    """
    res: dict[str, GenericFn] = {}

    pattern = r"([#\[\]\"=\w]+)?\s+?fn\s+(\w+)<([^>]+)>\s*\(([^\)]+)\)([\s\S]*?)}//<>"

    if matches := re.finditer(pattern, input_text, flags=re.MULTILINE):
        for match in matches:
            annotation, fn_name, params, args, fn_body = match.groups()

            # print(f"Annotation: {annotation}")
            # print(f"Fn name: {fn_name}")
            # print(f"Params: {params}")
            # print(f"Args: {args}")
            # print(f"Fn Body: {fn_body}")
            # print("---------------", end="\n\n")

            annotation = annotation.strip()
            if "#" in annotation:
                annotation += "\n"

            generic_fn = GenericFn(annotation, fn_name, params, args, fn_body)
            res[fn_name] = generic_fn

    return res


def get_typed_generic_fn_dict(input_text: str) -> dict[str, TypedGenericFn]:
    """
    Same as get_generic_fn_dict but for TypedGenericFn
    """
    res: dict[str, TypedGenericFn] = {}

    pattern = r"([#\[\]\"=\w]+)?\s+?fn\s+(\w+)<([^>]+)>\s*\[([^\]]+)]\s*\(([^\)]+)\)([\s\S]*?)}//<>"

    if matches := re.finditer(pattern, input_text, flags=re.MULTILINE):
        for match in matches:
            annotation, fn_name, params, typed_params, args, fn_body = match.groups()
            typed_fn_names: list[str] = typed_params.split(";")[0].split(",")
            typed_fn_type: list[str] = [
                t.strip() for t in typed_params.split(";")[-1].split(",")
            ]

            annotation = annotation.strip()
            if "#" in annotation:
                annotation += "\n"

            typed_generic_fn = TypedGenericFn(
                annotation,
                fn_name,
                params,
                args,
                fn_body,
                typed_fn_names,
                typed_fn_type,
            )
            res[fn_name] = typed_generic_fn

    return res


def remove_generic_fn_text(input_text: str) -> str:
    """
    Returns the updated input text with the generic function declarations removed
    """
    res: dict[str, GenericFn] = {}

    pattern = r"^([#\[\]\"=\w\s]*)\s+?fn\s+(\w+)<([^>]+)>\s*\(([^\)]+)\)([\s\S]*?)}//<>"

    matches = re.finditer(pattern, input_text, flags=re.MULTILINE)

    replacements = []

    for match in matches:
        _, fn_name, _, _, _ = match.groups()
        replacement_text = (
            f"\n\n// Place concrete instances of the {fn_name} function here"
        )
        replacements.append((match.start(), match.end(), replacement_text))

    # Sort the replacements in reverse order to ensure that replacing text
    # doesn't affect other replacements
    replacements.sort(reverse=True)

    for start, end, replacement_text in replacements:
        input_text = input_text[:start] + replacement_text + input_text[end:]

    return input_text


def remove_typed_generic_fn_text(input_text: str) -> str:
    """
    Returns the updated input text with the typed  generic function declarations removed
    """
    res: dict[str, GenericFn] = {}

    pattern = r"([#\[\]\"=\w]+)?\s+?fn\s+(\w+)<([^>]+)>\s*\[([^\]]+)]\s*\(([^\)]+)\)([\s\S]*?)}//<>"

    matches = re.finditer(pattern, input_text, flags=re.MULTILINE)

    replacements = []

    for match in matches:
        _, fn_name, _, _, _, _ = match.groups()
        replacement_text = (
            f"\n\n// Place concrete instances of the {fn_name} function here"
        )
        replacements.append((match.start(), match.end(), replacement_text))

    # Sort the replacements in reverse order to ensure that replacing text
    # doesn't affect other replacements
    replacements.sort(reverse=True)

    for start, end, replacement_text in replacements:
        input_text = input_text[:start] + replacement_text + input_text[end:]

    return input_text


def replace_generic_calls_with_concrete(
    text: str, global_params: dict[str, int]
) -> str:
    """
    Replaces generic function calls with concrete function calls based on the provided parameters.

    This function takes an input 'text' that may contain generic function calls with generic
    type parameters, e.g., 'my_function<T, U>(x, y)'. It also takes a dictionary 'global_params'
    containing concrete values for the generic type parameters. The function then replaces
    the calls to generic functions with the corresponding calls to concrete functions.
    """

    def replace_fn(match):
        fn_name, generic_params = match.groups()
        generic_params = [p.strip() for p in generic_params.split(",")]
        concrete_params: dict[str, int] = {}

        for param in generic_params:
            try:
                # Evaluate the expression using the global_params dict to get
                # the concrete value
                concrete_params[param] = eval(
                    param.replace("/", "//"), None, global_params
                )
            except (NameError, TypeError, ValueError, SyntaxError):
                # If evaluation fails, use the original param as a string
                concrete_params[param] = param

        concrete_args = [str(concrete_params.get(p, p))
                         for p in generic_params]
        concrete_call = f"{fn_name}_" + "_".join(concrete_args)

        return concrete_call

    pattern = r"(\w+)<(.+)>"
    return re.sub(pattern, replace_fn, text)


def replace_typed_generic_calls_with_concrete(
    text: str, global_params: dict[str, int]
) -> str:
    """
    Same as replace_generic_calls_with_concrete but for typed generic functions
    """

    def replace_fn(match):
        fn_name, generic_params, t = match.groups()
        generic_params = [p.strip() for p in generic_params.split(",")]
        concrete_params: dict[str, int] = {}

        for param in generic_params:
            try:
                # Evaluate the expression using the global_params dict to get
                # the concrete value
                concrete_params[param] = eval(
                    param.replace("/", "//"), None, global_params
                )
            except (NameError, TypeError, ValueError, SyntaxError):
                # If evaluation fails, use the original param as a string
                concrete_params[param] = param

        concrete_args = [str(concrete_params.get(p, p))
                         for p in generic_params]

        typed_fn_names = t.split(";")[0].strip()
        typed_fn_types = t.split(";")[-1].strip()

        if "," in typed_fn_types:
            typed_fn_types = [t.strip() for t in typed_fn_types.split(",")]

        if isinstance(typed_fn_names, str):
            typed_fn_names = string_to_singleton_list(typed_fn_names)
        if isinstance(typed_fn_types, str):
            typed_fn_types = string_to_singleton_list(typed_fn_types)

        typed_fn_types_str: str = "_".join(typed_fn_types)
        typed_fn_names_str: str = "_".join(typed_fn_names)
        concrete_call = (
            f"{fn_name}_{typed_fn_names_str}_{typed_fn_types_str}_"
            + "_".join(concrete_args)
        )

        return concrete_call

    pattern = r"(\w+)<([^>]+)>\[*\[([^\]]+)]"
    text = re.sub(pattern, replace_fn, text)

    return text


def get_tasks(text: str, global_params: dict[str, int]) -> list[Task]:
    """
    This function also replaces generic function calls with calls to the concrete functions
    """
    tasks = set()
    generic_fn_call_pattern = r"(\w+)<([^>]+)>\(([^)]+)\);"

    def replace_fn(match) -> str:
        fn_name, generic_params, generic_args = match.groups()
        generic_params: list[str] = [p.strip()
                                     for p in generic_params.split(",")]
        concrete_params = {}

        for param in generic_params:
            try:
                # Evaluate the expression using the param_dict to get the
                # concrete value
                concrete_params[param] = eval(
                    param.replace("/", "//"), None, global_params
                )
            except (NameError, TypeError, ValueError, SyntaxError):
                # If evaluation fails, use the original param as a string
                concrete_params[param] = param

        concrete_args = [str(concrete_params.get(p, p))
                         for p in generic_params]
        # Store the task with all parameters
        tasks.add((fn_name, tuple(concrete_args)))
        return f"{fn_name}_" + "_".join(concrete_args) + f"({generic_args})"

    text = re.sub(generic_fn_call_pattern, replace_fn, text)
    return [  # We only return the tasks that can be solved right away. We look for subtasks later
        Task(fn_name, list(params), global_params)
        for fn_name, params in tasks
        if all(param.isdigit() for param in params)
    ]


def replace_parameters_in_string(
        text: str, replacement_dict: dict[str, int]) -> str:
    """_
    Auxiliary function to replace the parameters with their value
    """
    for key, value in replacement_dict.items():
        text = text.replace(f"{key}", str(value))
    return text


def build_concrete_fn(
    generic_fn: GenericFn | TypedGenericFn,
    replacement_dict: dict[str, int],
    is_typed_task: bool,
) -> str:
    """
    Build the concrete function from the generic one.

    Args:
        generic_fn (GenericFn | TypedGenericFn): Information about the generic function.
        replacement_dict (dict[str, int]): Map containing the value of each parameter to replace in the function.
        is_typed_task (bool): Boolean flag indicating whether the task is typed.

    Returns:
        str: The concrete function as a string.
    """
    tmp = ""
    if not is_typed_task:  # Simple generic function
        generic_fn = cast(GenericFn, generic_fn)  # suppress pytype warning
        tmp = replace_parameters_in_string(
            "_".join(generic_fn.params), replacement_dict
        )
    else:  # Typed Generic function
        # suppress pytype warning
        generic_fn = cast(TypedGenericFn, generic_fn)
        tmp = replace_parameters_in_string(
            "_".join(generic_fn.generic_fn_names)
            + "_"
            + "_".join(generic_fn.generic_fn_types)
            + "_"
            + "_".join(generic_fn.params),
            replacement_dict,
        )

    if generic_fn.annotation == "":
        res = f"fn {generic_fn.fn_name}_{tmp}({replace_parameters_in_string(generic_fn.args, replacement_dict)})"
    elif "#" in generic_fn.annotation:  # #[returnaddress="stack"] annotation
        res = f"{generic_fn.annotation}fn {generic_fn.fn_name}_{tmp}({replace_parameters_in_string(generic_fn.args, replacement_dict)})"
    else:
        res = f"{generic_fn.annotation} fn {generic_fn.fn_name}_{tmp}({replace_parameters_in_string(generic_fn.args, replacement_dict)})"
    res += replace_parameters_in_string(generic_fn.fn_body, replacement_dict)
    res += "}"

    return res


def get_typed_fn_tasks(text: str, global_params: dict[str, int]) -> list[Task]:
    """
    Same as get_tasks but for typed generic functions
    """
    tasks = set()
    generic_fn_call_pattern = r"(\w+)<([^>]+)>\[*\[([^\]]+)]\(([^)]+)\);"

    def replace_fn(match) -> str:
        fn_name, generic_params, typed_fn_info, generic_args = match.groups()
        generic_params = [p.strip() for p in generic_params.split(",")]
        typed_fn_names = tuple(
            [name.strip() for name in typed_fn_info.split(";")[0].split(",")]
        )
        typed_fn_types = tuple(
            [t.strip() for t in typed_fn_info.split(";")[-1].split(",")]
        )  # because a list is not hashable

        concrete_params = {}

        # print('Debug in get tasks')
        # print(typed_fn_names)
        # print(typed_fn_types)

        for param in generic_params:
            try:
                # Evaluate the expression using the param_dict to get the
                # concrete value
                concrete_params[param] = eval(
                    param.replace("/", "//"), None, global_params
                )
            except (NameError, TypeError, ValueError, SyntaxError):
                # If evaluation fails, use the original param as a string
                concrete_params[param] = param

        concrete_args = [str(concrete_params.get(p, p))
                         for p in generic_params]
        tasks.add(
            (fn_name, tuple(concrete_args), typed_fn_names, typed_fn_types)
        )  # Store the task with all parameters

        # TODO: FIXME: Update to handle multiple typed fn names
        typed_fn_names_str: str = "_".join(typed_fn_names)
        typed_fn_types_str: str = "_".join(typed_fn_types)
        return (
            f"{fn_name}_{typed_fn_names_str}_{typed_fn_types_str}"
            + "_".join(concrete_args)
            + f"({generic_args})"
        )

    text = re.sub(generic_fn_call_pattern, replace_fn, text)

    return [  # We only return the tasks that can be solved right away. We look for subtasks later
        Task(
            fn_name,
            list(params),
            global_params,
            typed_fn_names,
            typed_fn_types)
        for fn_name, params, typed_fn_names, typed_fn_types in tasks
        if all(param.isdigit() for param in params)
    ]


def resolve_generic_fn_calls(text: str, global_params: dict[str, int]) -> str:
    if text is None:
        return

    # Typed first
    typed_generic_fn_call_pattern = r"(\w+)<([^>]+)>\s*\[([^\]]+)]\(([^)]+)\);"
    for match in re.finditer(typed_generic_fn_call_pattern, text):
        fn_name, generic_params, type_info, args = match.groups()
        fn_names = [type_info.split(";")[0].strip()]
        fn_types = [type_info.split(";")[-1].strip()]
        names_types = list(zip(fn_names, fn_types))
        replacement = (
            fn_name
            + "_"
            + "_".join([x + "_" + y for x,
                        y in names_types] + [generic_params])
            + "("
            + ", ".join(args)
            + ");"
        )
        text = re.sub(re.escape(match.group(0)), replacement, text)

    # Regular generic fn
    text = re.sub(
        r"(\w+)<(.+)>",
        lambda match: f"{match.group(1)}_{'_'.join(str(global_params.get(p.strip(), eval(p.strip().replace('/', '//'), {}, global_params))) for p in match.group(2).split(','))}",
        text,
    )

    return text


def replace_expand_macros(text: str) -> str:
    """
    Only performs find-replace
    """

    pattern = r"#expand\s+(\S+)\s+([^\/\/\n]+)"
    matches = dict(re.findall(pattern, text, re.MULTILINE))

    # Remove #expand from the jasmin source code
    text = re.sub(pattern, "", text)

    for key, value in matches.items():
        text = text.replace(f"{key}", str(value))

    return text


def validate_tasks(tasks: list[Task]):
    for task in tasks:
        if not task.is_valid():
            sys.stderr.write(f'Invalid task: {task}\n')
            sys.exit(1)


def find_subtasks(
    task: Task,
    generic_fn_dict: dict[str, GenericFn],
    typed_generic_fn_dict: dict[str, TypedGenericFn],
):
    return task.get_sub_tasks(generic_fn_dict, typed_generic_fn_dict)
